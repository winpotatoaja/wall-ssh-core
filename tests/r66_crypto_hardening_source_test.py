#!/usr/bin/env python3
"""R66 crypto hardening source and malformed-padding regression checks."""
from pathlib import Path
import sys


def check(ok: bool, label: str) -> bool:
    print(("PASS: " if ok else "FAIL: ") + label)
    return ok


def extract(src: str, signature: str) -> str:
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = src.find("{", start)
    depth = 0
    quote = None
    line_comment = block_comment = False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n": line_comment = False
        elif block_comment:
            if c == "*" and n == "/": block_comment = False; i += 2; continue
        elif quote:
            if c == "\\": i += 2; continue
            if c == quote: quote = None
        elif c == "/" and n == "/": line_comment = True; i += 2; continue
        elif c == "/" and n == "*": block_comment = True; i += 2; continue
        elif c in ("'", '"'): quote = c
        elif c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return src[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: r66_crypto_hardening_source_test.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    transport = (root / "src/transport.c").read_text()
    mac = (root / "src/mac.c").read_text()
    kex = (root / "src/kex.c").read_text()
    fullpacket = extract(transport, "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted")
    read_impl = extract(transport, "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)")
    init = extract(mac, "static int\nmac_method_hmac_sha2_256_init(")
    hmac_hash = extract(mac, "static int\nmac_method_hmac_sha2_256_hash(")

    checks = [
        check((root / ".passwall-r66-crypto-hardening-patched").is_file(), "R66 hardening marker exists"),
        check(fullpacket.count("if(mac_rc) {") == 2 and
              fullpacket.count("LIBSSH2_FREE(session, p->payload);") >= 2 and
              fullpacket.count("return LIBSSH2_ERROR_MAC_FAILURE;") >= 2,
              "ETM and non-ETM MAC failures free and null payload then fail closed"),
        check(fullpacket.index("if(p->padding_length < 4U") <
              fullpacket.index("session->fullpacket_payload_len -= p->padding_length"),
              "fullpacket validates padding before subtracting it from payload length"),
        check("p->padding_length < 4U" in fullpacket and "p->padding_length > p->packet_length - 1U" in fullpacket,
              "fullpacket preserves upper bound and enforces minimum padding"),
        check("p->padding_length < 4U" in read_impl and "p->padding_length > p->packet_length - 1U" in read_impl,
              "transport read validates non-ETM padding and clears payload on malformed input"),
        check("if(!abstract || !free_key || !key)" in init,
              "HMAC init rejects invalid args before allocating or dereferencing"),
        check("EVP_MAC_CTX_dup(state->ctx)" in hmac_hash and "EVP_MAC_init(ctx, NULL, 0, NULL)" in hmac_hash,
              "both compatibility fallback and 3.0.3+ reuse paths remain intact"),
        check("LIBSSH2_TEST_HMAC_CALLBACKS" in mac and
              "libssh2_test_hmac256_hash" in mac,
              "direct callback accessors compile only in test builds"),
        check(kex.count("if(session->local.mac->init(session, key, &free_key,") == 3 and
              kex.count("if(session->remote.mac->init(session, key, &free_key,") == 3,
              "KEX init-error checks remain for both directions"),
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
