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

    old_etm_padding = "                if(p->padding_length > p->packet_length - 1U) {\n"
    new_etm_padding = (
        "                if(p->padding_length < 4U ||\n"
        "                   p->padding_length > p->packet_length - 1U) {\n"
    )
    if fn.count(old_etm_padding) != 1:
        raise RuntimeError("ETM padding upper-bound check not found exactly once")
    fn = fn.replace(old_etm_padding, new_etm_padding, 1)

    # Non-ETM padding is authenticated by the MAC before this check. Reject it
    # before fullpacket_payload_len is reduced by the padding length below.
    payload_anchor = "        session->fullpacket_payload_len = p->packet_length - 1;\n\n"
    payload_replacement = (
        "        session->fullpacket_payload_len = p->packet_length - 1;\n\n"
        "        if(encrypted && remote_mac && !remote_mac->etm &&\n"
        "           (p->padding_length < 4U ||\n"
        "            p->padding_length > p->packet_length - 1U)) {\n"
        "            if(p->payload) {\n"
        "                LIBSSH2_FREE(session, p->payload);\n"
        "                p->payload = NULL;\n"
        "            }\n"
        "            return LIBSSH2_ERROR_PROTO;\n"
        "        }\n"
    )
    fn = once(fn, payload_anchor, payload_replacement,
              "add non-ETM minimum/maximum padding validation")
    path.write_text(src[:start] + fn + src[end:])


def patch_transport_read(root: Path) -> None:
    path = root / "src/transport.c"
    src = path.read_text()
    sig = "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)"
    start, end = bounds(src, sig)
    fn = src[start:end]
    old = (
        "                    if(p->padding_length > p->packet_length - 1) {\n"
        "                        return LIBSSH2_ERROR_DECRYPT;\n"
        "                    }\n"
    )
    new = (
        "                    if(p->padding_length < 4U ||\n"
        "                       p->padding_length > p->packet_length - 1U) {\n"
        "                        if(p->payload) {\n"
        "                            LIBSSH2_FREE(session, p->payload);\n"
        "                            p->payload = NULL;\n"
        "                        }\n"
        "                        return LIBSSH2_ERROR_PROTO;\n"
        "                    }\n"
    )
    if fn.count(old) != 1:
        raise RuntimeError("transport read non-ETM padding check not found exactly once")
    fn = fn.replace(old, new, 1)
    path.write_text(src[:start] + fn + src[end:])


def patch_mac_test_accessors(root: Path) -> None:
    path = root / "src/mac.c"
    src = path.read_text()
    anchor = "#endif /* OpenSSL 3 HMAC-SHA256 context reuse */\n"
    test_api = r'''#if defined(LIBSSH2_TEST_HMAC_CALLBACKS)
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
    patch_transport_read(root)
    patch_mac_test_accessors(root)
    (root / MARKER).write_text(
        "R66 crypto hardening: MAC RX cleanup and minimum SSH padding validation\n"
    )
    print("PASS: R66 transport/padding hardening and test-only HMAC callback accessors applied")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r66_crypto_hardening.py LIBSSH2_SOURCE_DIR")
    try:
        patch(Path(sys.argv[1]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
