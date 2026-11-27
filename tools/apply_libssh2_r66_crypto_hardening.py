#!/usr/bin/env python3
"""R66: transport and HMAC hardening fixes on top of R64/R65-B."""
from pathlib import Path
import sys

MARKER = ".passwall-r66-crypto-hardening-patched"


def once(src: str, old: str, new: str, label: str) -> str:
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return src.replace(old, new, 1)


def bounds(src: str, signature: str):
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = src.find("{", start)
    depth = 0
    quote_char = None
    line_comment = block_comment = False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n": line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote_char:
            if c == "\\": i += 2; continue
            if c == quote_char: quote_char = None
        elif c == "/" and n == "/":
            line_comment = True; i += 2; continue
        elif c == "/" and n == "*":
            block_comment = True; i += 2; continue
        elif c in ("'", '"'):
            quote_char = c
        elif c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return start, i + 1
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def patch_fullpacket(root: Path) -> None:
    path = root / "src/transport.c"
    src = path.read_text()
    sig = "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted"
    start, end = bounds(src, sig)
    fn = src[start:end]

    old_mac_error = (
        "                if(mac_rc)\n"
        "                    return LIBSSH2_ERROR_MAC_FAILURE;\n"
    )
    cleanup_mac_error = (
        "                if(mac_rc) {\n"
        "                    if(p->payload) {\n"
        "                        LIBSSH2_FREE(session, p->payload);\n"
        "                        p->payload = NULL;\n"
        "                    }\n"
        "                    return LIBSSH2_ERROR_MAC_FAILURE;\n"
        "                }\n"
    )
    if fn.count(old_mac_error) != 2:
        raise RuntimeError(
            "fullpacket MAC cleanup: expected 2 mac_rc error blocks, found "
            + str(fn.count(old_mac_error))
        )
    fn = fn.replace(old_mac_error, cleanup_mac_error)

    # R64 already has an ETM upper-bound check after successful MAC verification
    # and decryption. Keep it; add the minimum check for both modes below.
    etm_upper_bound = "                if(p->padding_length > p->packet_length - 1U) {\n"
    if fn.count(etm_upper_bound) != 1:
        raise RuntimeError("R64 ETM padding upper-bound check not found exactly once")

    # Do not inspect the minimum padding value before authentication. A bad MAC
    # must remain a MAC failure regardless of the unauthenticated padding byte.
    padding_anchor = "        session->remote.seqno++;\n"
    padding_replacement = (
        "        if(session->fullpacket_macstate == LIBSSH2_MAC_CONFIRMED &&\n"
        "           (p->padding_length < 4U ||\n"
        "            p->padding_length > p->packet_length - 1U)) {\n"
        "            if(p->payload) {\n"
        "                LIBSSH2_FREE(session, p->payload);\n"
        "                p->payload = NULL;\n"
        "            }\n"
        "            return LIBSSH2_ERROR_PROTO;\n"
        "        }\n\n"
        "        session->remote.seqno++;\n"
    )
    fn = once(fn, padding_anchor, padding_replacement,
              "add authenticated minimum/maximum SSH padding validation")
    path.write_text(src[:start] + fn + src[end:])


def validate_transport_read(root: Path) -> None:
    """Keep only the existing pre-MAC upper-bound sanity check."""
    path = root / "src/transport.c"
    src = path.read_text()
    sig = "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)"
    start, end = bounds(src, sig)
    fn = src[start:end]
    old_upper = (
        "                    if(p->padding_length > p->packet_length - 1) {\n"
        "                        return LIBSSH2_ERROR_DECRYPT;\n"
        "                    }\n"
    )
    if fn.count(old_upper) != 1:
        raise RuntimeError("legacy pre-MAC padding upper-bound check missing or duplicated")
    if "p->padding_length < 4U" in fn:
        raise RuntimeError("minimum padding must not be checked before MAC verification")


def patch_hmac_init_validation(root: Path) -> None:
    path = root / "src/mac.c"
    src = path.read_text()
    sig = "static int\nmac_method_hmac_sha2_256_init("
    start, end = bounds(src, sig)
    fn = src[start:end]
    old = (
        "    *abstract = NULL;\n"
        "    *free_key = 0;\n"
    )
    new = (
        "    if(!abstract || !free_key)\n"
        "        return 1;\n"
        "    *abstract = NULL;\n"
        "    *free_key = 0;\n"
        "    if(!session || !key)\n"
        "        return 1;\n"
    )
    fn = once(fn, old, new, "validate HMAC init callback arguments")
    path.write_text(src[:start] + fn + src[end:])


def patch_force_dup_test_path(root: Path) -> None:
    path = root / "src/mac.c"
    src = path.read_text()
    old = "#if OPENSSL_VERSION_NUMBER >= 0x30000030L\n"
    new = (
        "#if OPENSSL_VERSION_NUMBER >= 0x30000030L && \\\n"
        "    !defined(LIBSSH2_TEST_FORCE_EVP_MAC_CTX_DUP)\n"
    )
    src = once(src, old, new,
               "add test-only switch for the EVP_MAC_CTX_dup compatibility path")
    path.write_text(src)


def patch_mac_test_accessors(root: Path) -> None:
    path = root / "src/mac.c"
    src = path.read_text()
    anchor = "#endif /* OpenSSL 3 HMAC-SHA256 context reuse */\n"
    test_api = r'''#if defined(LIBSSH2_TEST_HMAC_CALLBACKS)
/* The hash callback is defined immediately below these test-only accessors. */
static int mac_method_hmac_sha2_256_hash(LIBSSH2_SESSION *session,
                                         unsigned char *out, uint32_t seqno,
                                         const unsigned char *packet,
                                         size_t packet_len,
                                         const unsigned char *addtl,
                                         size_t addtl_len, void **abstract);

/* Test-build-only access to the actual static R65-B callbacks. No failure
 * injection or test hook is present in production builds. */
int libssh2_test_hmac256_init(LIBSSH2_SESSION *session, unsigned char *key,
                              int *free_key, void **abstract)
{
    return mac_method_hmac_sha2_256_init(session, key, free_key, abstract);
}

int libssh2_test_hmac256_hash(LIBSSH2_SESSION *session, unsigned char *out,
                              uint32_t seqno, const unsigned char *packet,
                              size_t packet_len, const unsigned char *addtl,
                              size_t addtl_len, void **abstract)
{
    return mac_method_hmac_sha2_256_hash(session, out, seqno, packet,
                                         packet_len, addtl, addtl_len, abstract);
}

int libssh2_test_hmac256_dtor(LIBSSH2_SESSION *session, void **abstract)
{
    return mac_method_hmac_sha2_256_dtor(session, abstract);
}

int libssh2_test_hmac256_invalidate(void **abstract)
{
    LIBSSH2_HMAC_SHA256_STATE *state;
    if(!abstract || !*abstract)
        return 1;
    state = (LIBSSH2_HMAC_SHA256_STATE *)*abstract;
    EVP_MAC_CTX_free(state->ctx);
    state->ctx = NULL;
    return 0;
}
#endif
'''
    if src.count(anchor) != 1:
        raise RuntimeError("R65-B HMAC insertion point not unique")
    src = src.replace(anchor, test_api + anchor, 1)
    path.write_text(src)


def patch(root: Path) -> None:
    if not (root / ".passwall-r64-portable-aes-ctr-patched").is_file():
        raise RuntimeError("R66 hardening requires R64")
    if not (root / ".passwall-r65b-hmac-context-reuse-patched").is_file():
        raise RuntimeError("R66 hardening requires R65-B")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("R66 hardening is pinned to libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R66 crypto hardening patch marker already exists")
    patch_fullpacket(root)
    validate_transport_read(root)
    patch_hmac_init_validation(root)
    patch_force_dup_test_path(root)
    patch_mac_test_accessors(root)
    (root / MARKER).write_text(
        "R66 crypto hardening: MAC RX cleanup and post-auth minimum SSH padding validation\n"
    )
    print("PASS: R66 MAC cleanup, authenticated padding validation, HMAC init guards and test-only accessors applied")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r66_crypto_hardening.py LIBSSH2_SOURCE_DIR")
    try:
        patch(Path(sys.argv[1]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
