#!/usr/bin/env python3
"""R65-C source regression for the checked RX AES-128-CTR out-of-place path."""
from pathlib import Path
import sys


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return bool(ok)


def matching_brace(src, brace):
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


def extract_function(src, signature):
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = src.find("{", start)
    return src[start:matching_brace(src, brace) + 1]


def extract_block(src, marker):
    if src.count(marker) != 1:
        raise RuntimeError("expected exactly one block marker: " + marker)
    start = src.index(marker)
    brace = src.index("{", start)
    return src[start:matching_brace(src, brace) + 1]


def main():
    if len(sys.argv) != 3:
        print("usage: r65c_aes_ctr_outofplace_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
              file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    project = Path(sys.argv[2])
    transport = (root / "src/transport.c").read_text()
    crypt = (root / "src/crypt.c").read_text()
    openssl = (root / "src/openssl.c").read_text()
    openssl_h = (root / "src/openssl.h").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    mac = (root / "src/mac.c").read_text()
    core = (project / "ssh-core.c").read_text()
    diag = (project / "libssh2_diag.h").read_text()

    decrypt = extract_function(
        transport,
        "static int\ndecrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,",
    )
    bulk = extract_block(
        decrypt,
        "    if(CRYPT_FLAG_R(session, CTR_BULK) && !IS_FIRST(firstlast)) {",
    )
    bridge = extract_function(
        crypt,
        "int\n_libssh2_ctr_bulk_crypt_outofplace(LIBSSH2_SESSION *session,",
    )
    backend = extract_function(
        openssl,
        "int\n_libssh2_openssl_ctr_bulk_crypt(_libssh2_cipher_ctx *ctx,",
    )

    checks = [
        check((root / ".passwall-r64-portable-aes-ctr-patched").is_file() and
              (root / ".passwall-r65a-crypto-diagnostics-patched").is_file() and
              (root / ".passwall-r65b-hmac-context-reuse-patched").is_file() and
              (root / ".passwall-r65c-rx-outofplace-patched").is_file(),
              "R64, R65-A, R65-B and R65-C prerequisites/markers are present"),
        check("_libssh2_ctr_bulk_crypt_outofplace" in priv and
              "LIBSSH2_CRYPT_HAS_CTR_BULK" in openssl_h and
              "_libssh2_openssl_ctr_bulk_crypt" in openssl_h,
              "helper interfaces remain private to libssh2/OpenSSL backend headers"),
        check("abstract != &session->remote.crypt_abstract" in bridge and
              "!CRYPT_FLAG_R(session, CTR_BULK)" in bridge and
              "!cctx->encrypt" in bridge and
              "cctx->algo != _libssh2_cipher_aes128ctr" in bridge,
              "bridge is restricted to the live remote RX AES-128-CTR context"),
        check("!ctx || !*ctx" in backend and
              "len > (size_t)INT_MAX" in backend and
              "(len % 16U) != 0U" in backend and
              "EVP_CIPHER_CTX_mode(evp_ctx) != EVP_CIPH_CTR_MODE" in backend and
              "EVP_CIPHER_CTX_nid(evp_ctx) != NID_aes_128_ctr" in backend,
              "backend validates context, cipher, integer range and 16-byte framing"),
        check("UINTPTR_MAX - d" in backend and "UINTPTR_MAX - s" in backend and
              "d < s + (uintptr_t)len" in backend and
              "s < d + (uintptr_t)len" in backend and
              "if(dest != source)" in backend,
              "backend rejects partial overlap and address-range overflow but permits in-place"),
        check("EVP_CipherUpdate(evp_ctx, dest, &outl, source, (int)len)" in backend and
              "outl == (int)len" in backend,
              "EVP writes directly from ciphertext source into separate plaintext destination"),
        check("_libssh2_ctr_bulk_crypt_outofplace(" in bulk and
              "&session->remote.crypt_abstract" in bulk and
              "dest, source, (size_t)len" in bulk and
              "memcpy(" not in bulk and
              "session->remote.crypt->crypt(" not in bulk,
              "CTR_BULK RX no longer performs in-place decrypt followed by memcpy"),
        check("ctr_rx_evp_ns +=" in bulk and
              "ctr_rx_bulk_calls++" in bulk and
              "ctr_rx_bulk_bytes +=" in bulk and
              "ctr_rx_copy_calls++" not in bulk and
              "ctr_rx_copy_bytes +=" not in bulk and
              "ctr_rx_copy_ns +=" not in bulk,
              "R65-A EVP/bulk telemetry remains while bulk copy telemetry stays zero"),
        check("!IS_FIRST(firstlast)" in decrypt and
              "memcpy(dest, source, decryptlen)" in decrypt,
              "FIRST_BLOCK and the non-bulk fallback retain their original transport path"),
        check("EVP_MAC_init(ctx, NULL, 0, NULL)" in mac and
              "mac_method_hmac_sha2_256_hash" in mac and
              'log_raw("[PERF-MAC]' in core and
              "ctr_rx_copy_calls" in diag,
              "R65-B HMAC reuse and existing diagnostic ABI remain intact"),
    ]

    if not all(checks):
        return 1
    print("PASS: R65-C source-level transport/backend/diagnostic regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
