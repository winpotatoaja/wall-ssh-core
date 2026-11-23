#!/usr/bin/env python3
"""Apply the r44 bulk AES-GCM decrypt experiment to patched libssh2 1.11.0."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"{path.name}: {label}: expected one exact source anchor, found {count}"
        )
    path.write_text(source.replace(old, new, 1))


def patch(root: Path) -> None:
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.0"' not in version:
        raise RuntimeError("The r44 bulk decrypt patch is pinned to libssh2 1.11.0")

    if not (root / ".passwall-r43-diag-patched").is_file():
        raise RuntimeError("Apply the r43 diagnostic patch before the r44 optimization")
    marker = root / ".passwall-r44-bulk-aesgcm-patched"
    if marker.exists():
        raise RuntimeError("The r44 bulk AES-GCM patch is already applied")

    priv = root / "src/libssh2_priv.h"
    replace_once(
        priv,
        "        unsigned long long decrypt_path_bytes;\n",
        "        unsigned long long decrypt_path_bytes;\n"
        "        unsigned long long decrypt_cipher_calls;\n"
        "        unsigned long long decrypt_cipher_bytes;\n",
        "session cipher callback counters",
    )
    replace_once(
        priv,
        """/* Public snapshot layout shared with the app's libssh2_diag.h. */
typedef struct {
    unsigned long long decrypt_path_ns;
    unsigned long long decrypt_path_calls;
    unsigned long long decrypt_path_bytes;
""",
        """/* Public snapshot layout shared with the app's libssh2_diag.h. */
typedef struct {
    unsigned long long decrypt_path_ns;
    unsigned long long decrypt_path_calls;
    unsigned long long decrypt_path_bytes;
    unsigned long long decrypt_cipher_calls;
    unsigned long long decrypt_cipher_bytes;
""",
        "diagnostic snapshot cipher callback counters",
    )

    transport = root / "src/transport.c"
    replace_once(
        transport,
        """    if(!CRYPT_FLAG_L(session, PKTLEN_AAD))
        assert((len % blocksize) == 0);

    while(len > 0) {""",
        """    if(!CRYPT_FLAG_L(session, PKTLEN_AAD))
        assert((len % blocksize) == 0);

    /*
     * For OpenSSH AES-GCM, the initial block is needed to learn packet length
     * and must stay on the existing FIRST_BLOCK path. Once that length is
     * known, process each available ciphertext fragment in one cipher
     * callback instead of iterating over 16-byte AES blocks.
     */
    if(len > blocksize && !IS_FIRST(firstlast) &&
       CRYPT_FLAG_R(session, PKTLEN_AAD) &&
       session->remote.crypt->name &&
       (!strcmp(session->remote.crypt->name, "aes128-gcm@openssh.com") ||
        !strcmp(session->remote.crypt->name, "aes256-gcm@openssh.com"))) {
        if(session->passwall_diag.enabled) {
            session->passwall_diag.decrypt_cipher_calls++;
            session->passwall_diag.decrypt_cipher_bytes +=
                (unsigned long long)len;
        }
        if(session->remote.crypt->crypt(session, source, (size_t)len,
                                        &session->remote.crypt_abstract,
                                        firstlast)) {
            LIBSSH2_FREE(session, p->payload);
            return LIBSSH2_ERROR_DECRYPT;
        }
        memcpy(dest, source, (size_t)len);
        return LIBSSH2_ERROR_NONE;
    }

    while(len > 0) {""",
        "bulk AES-GCM fragment path",
    )
    replace_once(
        transport,
        """        if(session->remote.crypt->crypt(session, source, decryptlen,
                                        &session->remote.crypt_abstract,
                                        lowerfirstlast)) {""",
        """        if(session->passwall_diag.enabled) {
            session->passwall_diag.decrypt_cipher_calls++;
            session->passwall_diag.decrypt_cipher_bytes +=
                (unsigned long long)decryptlen;
        }
        if(session->remote.crypt->crypt(session, source, decryptlen,
                                        &session->remote.crypt_abstract,
                                        lowerfirstlast)) {""",
        "count fallback cipher callbacks",
    )

    openssl = root / "src/openssl.c"
    replace_once(
        openssl,
        "    const int cryptlen = (unsigned int)blocksize - aadlen - authenticationtag;\n",
        "    const int cryptlen = (unsigned int)blocksize - aadlen - authenticationtag;\n"
        "    const int inplace_gcm_decrypt = is_aesgcm && !encrypt;\n",
        "identify in-place AES-GCM decrypt",
    )
    replace_once(
        openssl,
        "    assert(blocksize <= sizeof(buf));\n",
        "    assert(inplace_gcm_decrypt || blocksize <= sizeof(buf));\n",
        "allow large in-place GCM decrypt fragments",
    )
    replace_once(
        openssl,
        "        ret = EVP_Cipher(*ctx, buf + aadlen, block + aadlen, cryptlen);\n",
        "        ret = EVP_Cipher(*ctx,\n"
        "                         inplace_gcm_decrypt ? block + aadlen : buf + aadlen,\n"
        "                         block + aadlen, cryptlen);\n",
        "opaque OpenSSL in-place decrypt",
    )
    replace_once(
        openssl,
        "        ret = EVP_Cipher(ctx, buf + aadlen, block + aadlen, cryptlen);\n",
        "        ret = EVP_Cipher(ctx,\n"
        "                         inplace_gcm_decrypt ? block + aadlen : buf + aadlen,\n"
        "                         block + aadlen, cryptlen);\n",
        "legacy OpenSSL in-place decrypt",
    )
    replace_once(
        openssl,
        "        memcpy(block + aadlen, buf + aadlen, cryptlen);\n",
        "        if(!inplace_gcm_decrypt)\n"
        "            memcpy(block + aadlen, buf + aadlen, cryptlen);\n",
        "skip redundant GCM decrypt copy",
    )

    session = root / "src/session.c"
    replace_once(
        session,
        """    timing->decrypt_path_bytes =
        session->passwall_diag.decrypt_path_bytes;""",
        """    timing->decrypt_path_bytes =
        session->passwall_diag.decrypt_path_bytes;
    timing->decrypt_cipher_calls =
        session->passwall_diag.decrypt_cipher_calls;
    timing->decrypt_cipher_bytes =
        session->passwall_diag.decrypt_cipher_bytes;""",
        "snapshot cipher callback counters",
    )
    replace_once(
        session,
        "        session->passwall_diag.decrypt_path_bytes = 0;\n",
        "        session->passwall_diag.decrypt_path_bytes = 0;\n"
        "        session->passwall_diag.decrypt_cipher_calls = 0;\n"
        "        session->passwall_diag.decrypt_cipher_bytes = 0;\n",
        "reset cipher callback counters",
    )

    marker.write_text(
        "libssh2 1.11.0 Passwall r44 bulk AES-GCM fragment decrypt\n"
    )
    print(
        "PASS: r44 bulk AES-GCM fragment decrypt and in-place OpenSSL path "
        "patched into libssh2 1.11.0"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError(
            "usage: apply_libssh2_r44_bulk_aesgcm.py <libssh2-1.11.0-source-dir>"
        )
    patch(Path(sys.argv[1]).resolve())
