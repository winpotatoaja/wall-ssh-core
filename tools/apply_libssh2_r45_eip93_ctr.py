#!/usr/bin/env python3
"""Apply the r45 MT7621 EIP93 AES-128-CTR backend to patched libssh2 1.11.0."""
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


def replace_range(path: Path, start: str, end: str, new: str, label: str) -> None:
    source = path.read_text()
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError(f"{path.name}: {label}: source range is not unique")
    begin = source.index(start)
    finish = source.index(end, begin + len(start))
    if finish <= begin:
        raise RuntimeError(f"{path.name}: {label}: invalid source range")
    path.write_text(source[:begin] + new + source[finish:])


def patch(root: Path) -> None:
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.0"' not in version:
        raise RuntimeError("The r45 EIP93 patch is pinned to libssh2 1.11.0")
    if not (root / ".passwall-r43-diag-patched").is_file():
        raise RuntimeError("Apply r43 diagnostics before r45")
    if not (root / ".passwall-r44-bulk-aesgcm-patched").is_file():
        raise RuntimeError("Apply the r44 bulk AES-GCM patch before r45")
    marker = root / ".passwall-r45-eip93-ctr-patched"
    if marker.exists():
        raise RuntimeError("The r45 EIP93 patch is already applied")

    openssl_h = root / "src/openssl.h"
    replace_once(
        openssl_h,
        """#define _libssh2_cipher_type(name) const EVP_CIPHER *(*name)(void)
#ifdef HAVE_OPAQUE_STRUCTS
#define _libssh2_cipher_ctx EVP_CIPHER_CTX *
#else
#define _libssh2_cipher_ctx EVP_CIPHER_CTX
#endif""",
        """#define _libssh2_cipher_type(name) const EVP_CIPHER *(*name)(void)

/*
 * Keep the normal OpenSSL context and the optional EIP93 AF_ALG operation
 * state together. The AF_ALG driver is requested by its exact driver name;
 * generic ctr(aes) is never used for the hardware path.
 */
typedef struct {
    EVP_CIPHER_CTX *evp;
    int eip93_fd;
    int eip93_enabled;
    int eip93_last_hw;
    int encrypt;
    unsigned char eip93_key[16];
    unsigned char eip93_iv[16];
} libssh2_openssl_cipher_ctx;

#define _libssh2_cipher_ctx libssh2_openssl_cipher_ctx
void _libssh2_cipher_ctx_dtor(_libssh2_cipher_ctx *ctx);""",
        "replace OpenSSL cipher context with backend wrapper",
    )
    replace_once(
        openssl_h,
        """#ifdef HAVE_OPAQUE_STRUCTS
#define _libssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_free(*(ctx))
#else
#define _libssh2_cipher_dtor(ctx) EVP_CIPHER_CTX_cleanup(ctx)
#endif""",
        """#define _libssh2_cipher_dtor(ctx) _libssh2_cipher_ctx_dtor(ctx)""",
        "route cipher destructor through backend wrapper",
    )

    openssl = root / "src/openssl.c"
    replace_once(
        openssl,
        "#include <assert.h>\n",
        "#include <assert.h>\n"
        "#include <errno.h>\n"
        "#include <limits.h>\n"
        "#include <stdint.h>\n"
        "#include <string.h>\n"
        "#include <sys/socket.h>\n"
        "#include <sys/types.h>\n"
        "#include <unistd.h>\n"
        "#include <linux/if_alg.h>\n",
        "include AF_ALG socket definitions",
    )

    cipher_backend = r'''
static int
_libssh2_eip93_afalg_open(_libssh2_cipher_ctx *ctx,
                          const unsigned char *secret,
                          const unsigned char *iv)
{
    struct sockaddr_alg sa;
    int tfm_fd = -1;
    int op_fd = -1;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "skcipher", sizeof("skcipher"));
    memcpy(sa.salg_name, "ctr(aes-eip93)", sizeof("ctr(aes-eip93)"));

    tfm_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if(tfm_fd < 0)
        return -1;

    if(bind(tfm_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;

    if(setsockopt(tfm_fd, SOL_ALG, ALG_SET_KEY, secret, 16) < 0)
        goto fail;

    op_fd = accept(tfm_fd, NULL, 0);
    if(op_fd < 0)
        goto fail;

    close(tfm_fd);
    ctx->eip93_fd = op_fd;
    ctx->eip93_enabled = 1;
    memcpy(ctx->eip93_key, secret, sizeof(ctx->eip93_key));
    memcpy(ctx->eip93_iv, iv, sizeof(ctx->eip93_iv));
    return 0;

fail:
    if(op_fd >= 0)
        close(op_fd);
    if(tfm_fd >= 0)
        close(tfm_fd);
    return -1;
}

static int
_libssh2_eip93_ctr_advance(unsigned char iv[16], size_t length)
{
    size_t blocks;
    size_t n;

    if(length == 0 || (length & 15U) != 0)
        return -1;

    blocks = length / 16U;
    for(n = 0; n < blocks; n++) {
        int i;
        for(i = 15; i >= 0; i--) {
            iv[i]++;
            if(iv[i] != 0)
                break;
        }
    }
    return 0;
}

static int
_libssh2_eip93_ctr_afalg(_libssh2_cipher_ctx *ctx,
                         unsigned char *block, size_t length)
{
    union {
        struct cmsghdr align;
        unsigned char bytes[
            CMSG_SPACE(sizeof(uint32_t)) +
            CMSG_SPACE(sizeof(struct af_alg_iv) + 16)
        ];
    } control;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    uint32_t operation = ctx->encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    ssize_t sent;
    size_t received = 0;

    if(ctx->eip93_fd < 0 || length < 1024U ||
       length > (size_t)INT_MAX || (length & 15U) != 0)
        return -1;

    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    iov.iov_base = block;
    iov.iov_len = length;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);

    cmsg = CMSG_FIRSTHDR(&msg);
    if(!cmsg)
        return -1;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(operation));
    memcpy(CMSG_DATA(cmsg), &operation, sizeof(operation));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if(!cmsg)
        return -1;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = 16;
    memcpy(alg_iv->iv, ctx->eip93_iv, 16);

    do {
        sent = sendmsg(ctx->eip93_fd, &msg, 0);
    } while(sent < 0 && errno == EINTR);
    if(sent != (ssize_t)length)
        return -1;

    while(received < length) {
        ssize_t got = recv(ctx->eip93_fd, block + received,
                           length - received, 0);
        if(got < 0 && errno == EINTR)
            continue;
        if(got <= 0)
            return -1;
        received += (size_t)got;
    }

    if(_libssh2_eip93_ctr_advance(ctx->eip93_iv, length))
        return -1;

    ctx->eip93_last_hw = 1;
    return 0;
}

static int
_libssh2_eip93_ctr_software(_libssh2_cipher_ctx *ctx,
                            unsigned char *block, size_t length)
{
    if(!ctx->evp || length > (size_t)INT_MAX ||
       (length & 15U) != 0)
        return -1;

    if(EVP_CIPHER_CTX_reset(ctx->evp) != 1)
        return -1;
    if(EVP_CipherInit(ctx->evp, EVP_aes_128_ctr(),
                      ctx->eip93_key, ctx->eip93_iv,
                      ctx->encrypt) != 1)
        return -1;
    if(EVP_Cipher(ctx->evp, block, block, (unsigned int)length) != 1)
        return -1;
    if(_libssh2_eip93_ctr_advance(ctx->eip93_iv, length))
        return -1;

    ctx->eip93_last_hw = 0;
    return 0;
}

void
_libssh2_cipher_ctx_dtor(_libssh2_cipher_ctx *ctx)
{
    if(!ctx)
        return;
    if(ctx->eip93_fd >= 0)
        close(ctx->eip93_fd);
    if(ctx->evp)
        EVP_CIPHER_CTX_free(ctx->evp);
    OPENSSL_cleanse(ctx->eip93_key, sizeof(ctx->eip93_key));
    OPENSSL_cleanse(ctx->eip93_iv, sizeof(ctx->eip93_iv));
    memset(ctx, 0, sizeof(*ctx));
    ctx->eip93_fd = -1;
}

int
_libssh2_cipher_init(_libssh2_cipher_ctx *h,
                     _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    int rc;

    memset(h, 0, sizeof(*h));
    h->eip93_fd = -1;
    h->encrypt = encrypt;
    h->evp = EVP_CIPHER_CTX_new();
    if(!h->evp)
        return 1;

    /*
     * Only bind the exact EIP93 driver. This avoids CryptoAPI selecting a
     * generic software ctr(aes) implementation for what should be offload.
     * The relay batches packet fragments above the driver's 512-byte
     * AES-128 software-fallback threshold before invoking this context.
     */
    if(algo == EVP_aes_128_ctr && secret && iv &&
       _libssh2_eip93_afalg_open(h, secret, iv) == 0)
        return 0;

    rc = !EVP_CipherInit(h->evp, algo(), secret, iv, encrypt);
#if LIBSSH2_AES_GCM
    if(algo == EVP_aes_128_gcm || algo == EVP_aes_256_gcm) {
        /* Sets both fixed and invocation_counter parts of IV. */
        rc |= !EVP_CIPHER_CTX_ctrl(h->evp, EVP_CTRL_AEAD_SET_IV_FIXED,
                                   -1, iv);
    }
#endif
    if(rc) {
        _libssh2_cipher_ctx_dtor(h);
        return 1;
    }
    return 0;
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blocksize,
                      int firstlast)
{
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    int ret = 1;
    int rc = 1;

    if(ctx->eip93_enabled) {
        ctx->eip93_last_hw = 0;
        /*
         * The OpenWrt 24.10 MT7621 driver sets AES-128 software fallback
         * through 512 bytes. Use EVP for small chunks; use AF_ALG with the
         * driver-specific name for larger, block-aligned packet fragments.
         */
        if(blocksize >= 1024U)
            return _libssh2_eip93_ctr_afalg(ctx, block, blocksize);
        return _libssh2_eip93_ctr_software(ctx, block, blocksize);
    }

#if LIBSSH2_AES_GCM
    const int is_aesgcm = (algo == EVP_aes_128_gcm) ||
                          (algo == EVP_aes_256_gcm);
#else
    const int is_aesgcm = 0;
#endif
    const int authlen = is_aesgcm ? 16 : 0;
    const int aadlen = (is_aesgcm && IS_FIRST(firstlast)) ? 4 : 0;
    const int authenticationtag = IS_LAST(firstlast) ? authlen : 0;
    const int cryptlen = (unsigned int)blocksize - aadlen - authenticationtag;
    const int inplace_gcm_decrypt = is_aesgcm && !encrypt;

    (void)algo;
    assert(inplace_gcm_decrypt || blocksize <= sizeof(buf));
    assert(cryptlen >= 0);

#if LIBSSH2_AES_GCM
    if(IS_FIRST(firstlast)) {
        char lastiv[1];
        if(is_aesgcm)
            ret = EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_IV_GEN,
                                      1, lastiv);
        if(aadlen)
            ret = EVP_Cipher(ctx->evp, NULL, block, aadlen);
    }
    if(IS_LAST(firstlast) && is_aesgcm && !encrypt)
        ret = EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_SET_TAG,
                                  authlen, block + blocksize - authlen);
#else
    (void)encrypt;
    (void)firstlast;
#endif

    if(cryptlen > 0) {
        ret = EVP_Cipher(ctx->evp,
                         inplace_gcm_decrypt ? block + aadlen : buf + aadlen,
                         block + aadlen, cryptlen);
    }

#if (defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3) || \
     defined(LIBSSH2_WOLFSSL)
    if(ret != -1)
#else
    if(ret >= 1)
#endif
    {
        rc = 0;
        if(IS_LAST(firstlast)) {
            ret = EVP_Cipher(ctx->evp, NULL, NULL, 0);
            if(ret < 0)
                ret = 0;
            else {
                ret = 1;
#if LIBSSH2_AES_GCM
                if(is_aesgcm && encrypt) {
                    assert(authenticationtag == authlen);
                    ret = EVP_CIPHER_CTX_ctrl(ctx->evp, EVP_CTRL_GCM_GET_TAG,
                                              authlen,
                                              block + blocksize -
                                              authenticationtag);
                }
#endif
            }
        }
        if(!inplace_gcm_decrypt)
            memcpy(block + aadlen, buf + aadlen, cryptlen);
        rc = !ret;
    }

    return rc;
}
'''
    replace_range(
        openssl,
        "int\n_libssh2_cipher_init",
        "\nvoid _libssh2_openssl_crypto_init",
        cipher_backend + "\n",
        "replace OpenSSL cipher init/crypt backend",
    )

    transport = root / "src/transport.c"
    replace_once(
        transport,
        """    if(!CRYPT_FLAG_L(session, PKTLEN_AAD))
        assert((len % blocksize) == 0);

    while(len > 0) {""",
        """    /*
     * CTR has no per-block framing requirement after the SSH packet's first
     * length block. Batch large aligned fragments so the EIP93 driver's
     * AES-128 software-fallback threshold is exceeded.
     */
    if(len >= 1024 && !IS_FIRST(firstlast) &&
       !CRYPT_FLAG_R(session, PKTLEN_AAD) &&
       session->remote.crypt->name &&
       !strcmp(session->remote.crypt->name, "aes128-ctr") &&
       (len % blocksize) == 0) {
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
        "bulk AES-128-CTR receive fragment path",
    )

    replace_range(
        transport,
        "        for(i = etm_crypt_offset; i < packet_length;",
        "        /* Call crypt() one last time so it can be filled in with the MAC */",
        r'''        if(session->local.crypt->name &&
           !strcmp(session->local.crypt->name, "aes128-ctr") &&
           packet_length - etm_crypt_offset >= 1024 &&
           ((packet_length - etm_crypt_offset) %
            session->local.crypt->blocksize) == 0) {
            if(session->local.crypt->crypt(
                   session, &p->outbuf[etm_crypt_offset],
                   packet_length - etm_crypt_offset,
                   &session->local.crypt_abstract, MIDDLE_BLOCK))
                return LIBSSH2_ERROR_ENCRYPT;
        }
        else {
            for(i = etm_crypt_offset; i < packet_length;
                i += session->local.crypt->blocksize) {
                unsigned char *ptr = &p->outbuf[i];
                size_t bsize = LIBSSH2_MIN(session->local.crypt->blocksize,
                                           (int)(packet_length-i));
                int firstlast = i == 0 ? FIRST_BLOCK :
                    (!CRYPT_FLAG_L(session, INTEGRATED_MAC)
                     && (i == packet_length - session->local.crypt->blocksize)
                       ? LAST_BLOCK: MIDDLE_BLOCK);
                if(!CRYPT_FLAG_L(session, INTEGRATED_MAC))
                    if(i > packet_length - 2*bsize) {
                        bsize = packet_length - i;
                        i += bsize - session->local.crypt->blocksize;
                    }
                _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                               "crypting bytes %d-%d", i,
                               i + session->local.crypt->blocksize - 1));
                if(session->local.crypt->crypt(session, ptr, bsize,
                                               &session->local.crypt_abstract,
                                               firstlast))
                    return LIBSSH2_ERROR_ENCRYPT;
            }
        }
''',
        "bulk AES-128-CTR transmit fragment path",
    )

    crypt = root / "src/crypt.c"
    replace_once(
        crypt,
        """    (void) session;
    return _libssh2_cipher_crypt(&cctx->h, cctx->algo, cctx->encrypt, block,
                                 blocksize, firstlast);""",
        """    int rc = _libssh2_cipher_crypt(&cctx->h, cctx->algo, cctx->encrypt,
                                   block, blocksize, firstlast);

    if(!rc && session->passwall_diag.enabled &&
       cctx->algo == _libssh2_cipher_aes128ctr) {
        if(cctx->h.eip93_last_hw) {
            session->passwall_diag.eip93_ctr_hw_calls++;
            session->passwall_diag.eip93_ctr_hw_bytes +=
                (unsigned long long)blocksize;
        }
        else {
            session->passwall_diag.eip93_ctr_sw_calls++;
            session->passwall_diag.eip93_ctr_sw_bytes +=
                (unsigned long long)blocksize;
        }
    }
    return rc;""",
        "record actual EIP93 and software AES-CTR work",
    )

    priv = root / "src/libssh2_priv.h"
    replace_once(
        priv,
        "        unsigned long long decrypt_cipher_bytes;\n",
        "        unsigned long long decrypt_cipher_bytes;\n"
        "        unsigned long long eip93_ctr_hw_calls;\n"
        "        unsigned long long eip93_ctr_hw_bytes;\n"
        "        unsigned long long eip93_ctr_sw_calls;\n"
        "        unsigned long long eip93_ctr_sw_bytes;\n",
        "session EIP93/software CTR counters",
    )
    replace_once(
        priv,
        """/* Public snapshot layout shared with the app's libssh2_diag.h. */
typedef struct {
    unsigned long long decrypt_path_ns;
    unsigned long long decrypt_path_calls;
    unsigned long long decrypt_path_bytes;
    unsigned long long decrypt_cipher_calls;
    unsigned long long decrypt_cipher_bytes;
""",
        """/* Public snapshot layout shared with the app's libssh2_diag.h. */
typedef struct {
    unsigned long long decrypt_path_ns;
    unsigned long long decrypt_path_calls;
    unsigned long long decrypt_path_bytes;
    unsigned long long decrypt_cipher_calls;
    unsigned long long decrypt_cipher_bytes;
    unsigned long long eip93_ctr_hw_calls;
    unsigned long long eip93_ctr_hw_bytes;
    unsigned long long eip93_ctr_sw_calls;
    unsigned long long eip93_ctr_sw_bytes;
""",
        "public snapshot EIP93/software CTR counters",
    )

    session = root / "src/session.c"
    replace_once(
        session,
        """    timing->decrypt_cipher_bytes =
        session->passwall_diag.decrypt_cipher_bytes;""",
        """    timing->decrypt_cipher_bytes =
        session->passwall_diag.decrypt_cipher_bytes;
    timing->eip93_ctr_hw_calls =
        session->passwall_diag.eip93_ctr_hw_calls;
    timing->eip93_ctr_hw_bytes =
        session->passwall_diag.eip93_ctr_hw_bytes;
    timing->eip93_ctr_sw_calls =
        session->passwall_diag.eip93_ctr_sw_calls;
    timing->eip93_ctr_sw_bytes =
        session->passwall_diag.eip93_ctr_sw_bytes;""",
        "snapshot EIP93/software CTR counters",
    )
    replace_once(
        session,
        "        session->passwall_diag.decrypt_cipher_bytes = 0;\n",
        "        session->passwall_diag.decrypt_cipher_bytes = 0;\n"
        "        session->passwall_diag.eip93_ctr_hw_calls = 0;\n"
        "        session->passwall_diag.eip93_ctr_hw_bytes = 0;\n"
        "        session->passwall_diag.eip93_ctr_sw_calls = 0;\n"
        "        session->passwall_diag.eip93_ctr_sw_bytes = 0;\n",
        "reset EIP93/software CTR counters",
    )

    marker.write_text(
        "libssh2 1.11.0 Passwall r45 MT7621 EIP93 AES-128-CTR AF_ALG backend\n"
    )
    print(
        "PASS: r45 exact-driver EIP93 CTR backend, packet batching, "
        "and hardware/software counters patched into libssh2 1.11.0"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError(
            "usage: apply_libssh2_r45_eip93_ctr.py <libssh2-1.11.0-source-dir>"
        )
    patch(Path(sys.argv[1]).resolve())
