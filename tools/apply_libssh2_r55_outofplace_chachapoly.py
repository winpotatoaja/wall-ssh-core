#!/usr/bin/env python3
"""Passwall r55: authenticate then decrypt ChaCha20 payload out-of-place."""
from pathlib import Path
import re
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


def patch(root: Path) -> None:
    required = (
        ".passwall-r51-auth-before-decrypt-patched",
        ".passwall-r52-worker-lifecycle-patched",
        ".passwall-r53-mips32r2-chacha-asm-patched",
        ".passwall-r54-mips32r2-poly1305-asm-patched",
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise RuntimeError("r55 requires prior patches: " + ", ".join(missing))

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r55 patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r55-out-of-place-chachapoly-patched"
    if marker.exists():
        raise RuntimeError("r55 out-of-place ChaCha20-Poly1305 patch is already present")

    # The r51 MAC phase still reads the original packet. Only the post-tag
    # ChaCha destination offset changes: AAD is authenticated but not emitted.
    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        "                                u_int bytes, u_int aadlen,\n"
        "                                const u_char poly_key[POLY1305_KEYLEN],",
        "                                u_int bytes, u_int aadlen,\n"
        "                                u_int dest_aadlen,\n"
        "                                const u_char poly_key[POLY1305_KEYLEN],",
        "extend worker decrypt with an independent destination AAD offset",
    )
    replace_once(
        chacha_c,
        "    if(!pool || !base_state || !source || !destination || !poly_key ||\n"
        "       !wire_tag || bytes < 4096U)\n"
        "        return 0;\n",
        "    if(!pool || !base_state || !source || !destination || !poly_key ||\n"
        "       !wire_tag || bytes < 4096U)\n"
        "        return 0;\n"
        "    if(dest_aadlen != 0U && dest_aadlen != aadlen)\n"
        "        return 0;\n",
        "validate body-only or full-AAD output layout",
    )
    replace_once(
        chacha_c,
        "    pool->destination = destination + aadlen;\n",
        "    pool->destination = destination + dest_aadlen;\n",
        "write worker plaintext directly at the requested output offset",
    )

    chacha_h = root / "src/chacha.h"
    replace_once(
        chacha_h,
        "                                    u_int bytes, u_int aadlen,\n"
        "                                    const u_char poly_key[32],",
        "                                    u_int bytes, u_int aadlen,\n"
        "                                    u_int dest_aadlen,\n"
        "                                    const u_char poly_key[32],",
        "update worker-only decrypt declaration",
    )

    cipher_h = root / "src/cipher-chachapoly.h"
    replace_once(
        cipher_h,
        "                     u_char *dest, const u_char *src, u_int len, u_int aadlen,\n"
        "                     int do_encrypt);",
        "                     u_char *dest, const u_char *src, u_int len,\n"
        "                     u_int aadlen, u_int dest_aadlen, int do_encrypt);",
        "expose independent ChaCha20-Poly1305 destination offset",
    )

    cipher_c = root / "src/cipher-chachapoly.c"
    replace_once(
        cipher_c,
        "                 const u_char *src, u_int len, u_int aadlen, int do_encrypt)",
        "                 const u_char *src, u_int len, u_int aadlen,\n"
        "                 u_int dest_aadlen, int do_encrypt)",
        "update ChaCha20-Poly1305 implementation signature",
    )
    replace_once(
        cipher_c,
        "    unsigned long long poly_worker_ns = 0ULL;\n\n"
        "    memset(poly_key, 0, sizeof(poly_key));",
        "    unsigned long long poly_worker_ns = 0ULL;\n\n"
        "    if(dest_aadlen != 0U && dest_aadlen != aadlen)\n"
        "        return LIBSSH2_ERROR_INVAL;\n"
        "    if(do_encrypt && dest_aadlen != aadlen)\n"
        "        return LIBSSH2_ERROR_INVAL;\n\n"
        "    memset(poly_key, 0, sizeof(poly_key));",
        "validate output framing before crypto work",
    )
    replace_once(
        cipher_c,
        "            ctx->parallel_pool, &ctx->main_ctx, src, dest, len, aadlen,\n"
        "            poly_key, wire_tag, &poly_worker_ns, diag_enabled);",
        "            ctx->parallel_pool, &ctx->main_ctx, src, dest, len, aadlen,\n"
        "            dest_aadlen, poly_key, wire_tag, &poly_worker_ns, diag_enabled);",
        "pass independent destination AAD offset to authenticated workers",
    )
    replace_once(
        cipher_c,
        "    if(aadlen) {\n"
        "        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;\n"
        "        chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);",
        "    if(dest_aadlen) {\n"
        "        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;\n"
        "        chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);",
        "skip AAD output for body-only decrypt",
    )
    replace_once(
        cipher_c,
        "                ctx->parallel_pool, &ctx->main_ctx, src + aadlen,\n"
        "                dest + aadlen, len);",
        "                ctx->parallel_pool, &ctx->main_ctx, src + aadlen,\n"
        "                dest + dest_aadlen, len);",
        "write serial-fallback parallel decrypt into body-only output",
    )
    replace_once(
        cipher_c,
        "            chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,\n"
        "                                 dest + aadlen, len);",
        "            chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,\n"
        "                                 dest + dest_aadlen, len);",
        "write serial decrypt into body-only output",
    )
    replace_once(
        cipher_c,
        "        poly1305_auth(dest + aadlen + len, dest, aadlen + len, poly_key);",
        "        poly1305_auth(dest + dest_aadlen + len, dest,\n"
        "                      dest_aadlen + len, poly_key);",
        "preserve normal encryption tag placement",
    )

    # Existing generic API calls keep the legacy four-byte AAD layout.
    crypt_c = root / "src/crypt.c"
    replace_once(
        crypt_c,
        "                                   ((u_int)buf_len) - 4, 4, ctx->encrypt);",
        "                                   ((u_int)buf_len) - 4, 4, 4,\n"
        "                                   ctx->encrypt);",
        "preserve existing encryption framing",
    )
    crypt_source = crypt_c.read_text()
    decrypt_call = re.compile(
        r"(?m)^(?P<indent>[ \t]*)ret = chachapoly_crypt\(\s*session,\s*"
        r"&ctx->chachapoly_ctx,\s*seqno,\s*buf,\s*buf,\s*"
        r"\(\(u_int\)buf_len\),\s*4,\s*ctx->encrypt\s*\);"
    )
    matches = list(decrypt_call.finditer(crypt_source))
    if len(matches) != 1:
        raise RuntimeError(
            "crypt.c: preserve existing in-place decrypt framing: "
            f"expected one session-aware call, found {len(matches)}"
        )
    replacement = (
        r"\g<indent>ret = chachapoly_crypt(session, &ctx->chachapoly_ctx,\n"
        r"\g<indent>                       seqno, buf, buf, ((u_int)buf_len),\n"
        r"\g<indent>                       4, 4, ctx->encrypt);"
    )
    crypt_c.write_text(decrypt_call.sub(replacement, crypt_source, count=1))

    helper = r'''
/*
 * r55: authenticate the full wire packet, then decrypt only the SSH packet
 * body directly into the transport payload allocation. The four-byte
 * encrypted packet-length AAD remains in the read-only source buffer.
 */
int
_libssh2_chachapoly_decrypt_body(LIBSSH2_SESSION *session,
                                 unsigned int seqno,
                                 const unsigned char *source,
                                 unsigned char *destination,
                                 unsigned int payload_len,
                                 unsigned int tag_len,
                                 void **abstract)
{
    struct crypt_ctx *ctx;
    int rc;

    if(!session || !abstract || !*abstract || !source || !destination ||
       source == destination || tag_len != 16U)
        return LIBSSH2_ERROR_INVAL;

    ctx = *(struct crypt_ctx **)abstract;
    if(ctx->encrypt)
        return LIBSSH2_ERROR_INVAL;

    rc = chachapoly_crypt(session, &ctx->chachapoly_ctx, seqno,
                          destination, source, payload_len, 4U, 0U, 0);
    if(rc == 0)
        memset(destination + payload_len, 0, tag_len);
    return rc;
}

'''
    replace_once(
        crypt_c,
        "static int\ncrypt_get_length_chacha20_poly(LIBSSH2_SESSION * session, unsigned int seqno,",
        helper + "static int\ncrypt_get_length_chacha20_poly(LIBSSH2_SESSION * session, unsigned int seqno,",
        "add authenticated body-only decrypt entry point",
    )

    priv_h = root / "src/libssh2_priv.h"
    replace_once(
        priv_h,
        "typedef struct _LIBSSH2_CRYPT_METHOD LIBSSH2_CRYPT_METHOD;\n",
        "typedef struct _LIBSSH2_CRYPT_METHOD LIBSSH2_CRYPT_METHOD;\n"
        "int _libssh2_chachapoly_decrypt_body(LIBSSH2_SESSION *session,\n"
        "                                     unsigned int seqno,\n"
        "                                     const unsigned char *source,\n"
        "                                     unsigned char *destination,\n"
        "                                     unsigned int payload_len,\n"
        "                                     unsigned int tag_len,\n"
        "                                     void **abstract);\n",
        "declare internal transport-to-crypto body decrypt helper",
    )

    transport_c = root / "src/transport.c"
    old_transport = (
        "            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {\n"
        "                rc = session->remote.crypt->crypt(session,\n"
        "                                               session->remote.seqno,\n"
        "                                               &p->buf[p->readidx],\n"
        "                                               numdecrypt,\n"
        "                                               &session->remote.crypt_abstract,\n"
        "                                               0);\n\n"
        "                if(rc != LIBSSH2_ERROR_NONE) {\n"
        "                    p->total_num = 0;   /* no packet buffer available */\n"
        "                    return rc;\n"
        "                }\n\n"
        "                memcpy(p->wptr, &p->buf[p->readidx], numbytes);\n"
    )
    new_transport = (
        "            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {\n"
        "                int out_of_place_chachapoly =\n"
        "                    strcmp(session->remote.crypt->name,\n"
        "                           \"chacha20-poly1305@openssh.com\") == 0;\n\n"
        "                if(out_of_place_chachapoly) {\n"
        "                    rc = _libssh2_chachapoly_decrypt_body(\n"
        "                        session, session->remote.seqno,\n"
        "                        &p->buf[p->readidx], p->wptr,\n"
        "                        (unsigned int)numdecrypt, auth_len,\n"
        "                        &session->remote.crypt_abstract);\n"
        "                }\n"
        "                else {\n"
        "                    rc = session->remote.crypt->crypt(session,\n"
        "                                                   session->remote.seqno,\n"
        "                                                   &p->buf[p->readidx],\n"
        "                                                   numdecrypt,\n"
        "                                                   &session->remote.crypt_abstract,\n"
        "                                                   0);\n"
        "                }\n\n"
        "                if(rc != LIBSSH2_ERROR_NONE) {\n"
        "                    p->total_num = 0;   /* no packet buffer available */\n"
        "                    return rc;\n"
        "                }\n\n"
        "                if(!out_of_place_chachapoly)\n"
        "                    memcpy(p->wptr, &p->buf[p->readidx], numbytes);\n"
    )
    replace_once(
        transport_c, old_transport, new_transport,
        "decrypt OpenSSH ChaCha body out-of-place after tag authentication",
    )

    marker.write_text(
        ".passwall-r55-out-of-place-chachapoly-patched\n"
        "libssh2 1.11.1 Passwall r55 authenticated out-of-place ChaCha20-Poly1305 body decrypt\n"
    )
    print(
        "PASS: r55 authenticates ciphertext before writing plaintext directly "
        "to the transport payload; non-ChaCha ciphers retain the original path"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r55_outofplace_chachapoly.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
