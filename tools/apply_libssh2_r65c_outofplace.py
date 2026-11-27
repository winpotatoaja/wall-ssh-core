#!/usr/bin/env python3
"""R65-C: remove the extra RX AES-128-CTR copy with checked out-of-place EVP."""
from pathlib import Path
import sys

MARKER = ".passwall-r65c-rx-outofplace-patched"


def once(src: str, old: str, new: str, label: str) -> str:
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return src.replace(old, new, 1)


def function_bounds(src: str, signature: str):
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one function {signature!r}")
    brace = src.find("{", start)
    if brace < 0:
        raise RuntimeError(f"missing function body for {signature!r}")
    end = matching_brace(src, brace)
    return start, end + 1


def matching_brace(src: str, brace: int) -> int:
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n":
                line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "/" and n == "/":
            line_comment = True
            i += 2
            continue
        elif c == "/" and n == "*":
            block_comment = True
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise RuntimeError("unterminated C block")


def replace_function(src: str, signature: str, transform, label: str) -> str:
    start, end = function_bounds(src, signature)
    original = src[start:end]
    updated = transform(original)
    if updated == original:
        raise RuntimeError(f"{label}: function was not changed")
    return src[:start] + updated + src[end:]


def replace_ctr_bulk_block(fn: str) -> str:
    marker = "    if(CRYPT_FLAG_R(session, CTR_BULK) && !IS_FIRST(firstlast)) {"
    if fn.count(marker) != 1:
        raise RuntimeError(
            "R65-C: expected exactly one R64/R65-A CTR_BULK receive block"
        )
    start = fn.index(marker)
    brace = fn.index("{", start)
    end = matching_brace(fn, brace) + 1
    replacement = r'''    if(CRYPT_FLAG_R(session, CTR_BULK) && !IS_FIRST(firstlast)) {
        unsigned long long ctr_rx_start_ns = 0;
        unsigned long long ctr_rx_evp_end_ns = 0;

        if(((size_t)len % (size_t)blocksize) != 0U) {
            if(p->payload) {
                LIBSSH2_FREE(session, p->payload);
                p->payload = NULL;
            }
            return LIBSSH2_ERROR_DECRYPT;
        }

        if(session->passwall_diag.enabled)
            ctr_rx_start_ns = _libssh2_diag_now_ns();

        if(_libssh2_ctr_bulk_crypt_outofplace(
               session, &session->remote.crypt_abstract,
               dest, source, (size_t)len)) {
            if(p->payload) {
                LIBSSH2_FREE(session, p->payload);
                p->payload = NULL;
            }
            return LIBSSH2_ERROR_DECRYPT;
        }

        if(session->passwall_diag.enabled) {
            ctr_rx_evp_end_ns = _libssh2_diag_now_ns();
            session->passwall_diag.ctr_rx_bulk_calls++;
            session->passwall_diag.ctr_rx_bulk_bytes +=
                (unsigned long long)len;
            if(ctr_rx_start_ns && ctr_rx_evp_end_ns >= ctr_rx_start_ns)
                session->passwall_diag.ctr_rx_evp_ns +=
                    ctr_rx_evp_end_ns - ctr_rx_start_ns;
        }
        return LIBSSH2_ERROR_NONE;
    }'''
    return fn[:start] + replacement + fn[end:]


def patch_private_header(root: Path) -> None:
    p = root / "src/libssh2_priv.h"
    s = p.read_text()
    s = once(
        s,
        "const LIBSSH2_CRYPT_METHOD **libssh2_crypt_methods(void);\n"
        "const LIBSSH2_HOSTKEY_METHOD **libssh2_hostkey_methods(void);\n",
        "const LIBSSH2_CRYPT_METHOD **libssh2_crypt_methods(void);\n"
        "const LIBSSH2_HOSTKEY_METHOD **libssh2_hostkey_methods(void);\n"
        "/* Internal RX-only OpenSSL 3 AES-128-CTR out-of-place fast path. */\n"
        "int _libssh2_ctr_bulk_crypt_outofplace(\n"
        "    LIBSSH2_SESSION *session, void **abstract, unsigned char *dest,\n"
        "    const unsigned char *source, size_t len);\n",
        "declare the internal CTR RX bridge"
    )
    p.write_text(s)


def patch_openssl_header(root: Path) -> None:
    p = root / "src/openssl.h"
    s = p.read_text()
    s = once(
        s,
        "#define _libssh2_cipher_chacha20 NULL\n",
        "#define _libssh2_cipher_chacha20 NULL\n\n"
        "#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)\n"
        "int _libssh2_openssl_ctr_bulk_crypt(_libssh2_cipher_ctx *ctx,\n"
        "                                    unsigned char *dest,\n"
        "                                    const unsigned char *source,\n"
        "                                    size_t len);\n"
        "#endif\n",
        "declare the OpenSSL backend helper"
    )
    p.write_text(s)


def patch_openssl_backend(root: Path) -> None:
    p = root / "src/openssl.c"
    s = p.read_text()
    s = once(
        s,
        "#include <stdlib.h>\n#include <assert.h>\n#include <limits.h>\n",
        "#include <stdlib.h>\n#include <assert.h>\n#include <limits.h>\n"
        "#include <stdint.h>\n#include <openssl/obj_mac.h>\n",
        "include uintptr_t definitions"
    )
    helper = r'''#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)
/*
 * R65-C: write AES-128-CTR plaintext directly to the packet payload.
 * Partial overlap is rejected; exact in-place operation remains valid.
 */
int
_libssh2_openssl_ctr_bulk_crypt(_libssh2_cipher_ctx *ctx,
                                unsigned char *dest,
                                const unsigned char *source, size_t len)
{
    EVP_CIPHER_CTX *evp_ctx;
    uintptr_t d;
    uintptr_t s;
    int outl = 0;
    int ret;

    if(len == 0U)
        return 0;

#ifdef HAVE_OPAQUE_STRUCTS
    if(!ctx || !*ctx)
        return 1;
    evp_ctx = *ctx;
#else
    if(!ctx)
        return 1;
    evp_ctx = ctx;
#endif

    if(!dest || !source || len > (size_t)INT_MAX || (len % 16U) != 0U)
        return 1;

    if(EVP_CIPHER_CTX_mode(evp_ctx) != EVP_CIPH_CTR_MODE ||
       EVP_CIPHER_CTX_nid(evp_ctx) != NID_aes_128_ctr)
        return 1;

    d = (uintptr_t)dest;
    s = (uintptr_t)source;
    if(dest != source) {
        /* Check before adding len so uintptr_t range arithmetic cannot wrap. */
        if(len > (size_t)(UINTPTR_MAX - d) ||
           len > (size_t)(UINTPTR_MAX - s))
            return 1;
        if(d < s + (uintptr_t)len && s < d + (uintptr_t)len)
            return 1;
    }

    ret = EVP_CipherUpdate(evp_ctx, dest, &outl, source, (int)len);
    return (ret == 1 && outl == (int)len) ? 0 : 1;
}
#endif /* LIBSSH2_CRYPT_HAS_CTR_BULK */

'''
    s = once(
        s,
        "int\n_libssh2_cipher_init(_libssh2_cipher_ctx * h,\n",
        helper + "int\n_libssh2_cipher_init(_libssh2_cipher_ctx * h,\n",
        "insert checked out-of-place EVP helper"
    )
    p.write_text(s)


def patch_crypt_bridge(root: Path) -> None:
    p = root / "src/crypt.c"
    s = p.read_text()
    bridge = r'''int
_libssh2_ctr_bulk_crypt_outofplace(LIBSSH2_SESSION *session, void **abstract,
                                   unsigned char *dest,
                                   const unsigned char *source, size_t len)
{
#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)
    struct crypt_ctx *cctx;

    if(!session || abstract != &session->remote.crypt_abstract ||
       !CRYPT_FLAG_R(session, CTR_BULK) || !abstract || !*abstract ||
       !dest || !source)
        return 1;

    cctx = *(struct crypt_ctx **)abstract;
    if(!cctx || cctx->encrypt ||
       cctx->algo != _libssh2_cipher_aes128ctr)
        return 1;
#ifdef HAVE_OPAQUE_STRUCTS
    if(!cctx->h)
        return 1;
#endif
    return _libssh2_openssl_ctr_bulk_crypt(&cctx->h, dest, source, len);
#else
    (void)session;
    (void)abstract;
    (void)dest;
    (void)source;
    (void)len;
    return 1;
#endif
}

'''
    s = once(
        s,
        "static int\ncrypt_dtor(LIBSSH2_SESSION * session, void **abstract)\n",
        bridge + "static int\ncrypt_dtor(LIBSSH2_SESSION * session, void **abstract)\n",
        "insert the RX-only crypt context bridge"
    )
    p.write_text(s)


def patch_transport(root: Path) -> None:
    p = root / "src/transport.c"
    s = p.read_text()
    s = replace_function(
        s,
        "static int\ndecrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,",
        lambda fn: replace_ctr_bulk_block(fn),
        "replace only the CTR bulk receive path"
    )
    p.write_text(s)


def patch(root: Path) -> None:
    if not (root / ".passwall-r64-portable-aes-ctr-patched").is_file():
        raise RuntimeError("R65-C requires the R64 AES-CTR bulk foundation")
    if not (root / ".passwall-r65a-crypto-diagnostics-patched").is_file():
        raise RuntimeError("R65-C requires R65-A CTR diagnostics")
    if not (root / ".passwall-r65b-hmac-context-reuse-patched").is_file():
        raise RuntimeError("R65-C requires the R65-B HMAC context reuse patch")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (
        root / "include/libssh2.h"
    ).read_text():
        raise RuntimeError("R65-C is pinned to libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R65-C marker already exists")

    patch_private_header(root)
    patch_openssl_header(root)
    patch_openssl_backend(root)
    patch_crypt_bridge(root)
    patch_transport(root)

    (root / MARKER).write_text(
        "R65-C: RX AES-128-CTR out-of-place EVP update; no destination memcpy\n"
    )
    print(
        "PASS: R65-C checked OpenSSL 3 RX AES-128-CTR out-of-place path; "
        "HMAC/TX/ChaCha/AES-GCM/default cipher unchanged"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r65c_outofplace.py LIBSSH2_SOURCE_DIR")
    try:
        patch(Path(sys.argv[1]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
