#!/usr/bin/env python3
"""R66 crypto hardening source and malformed-padding regression checks."""
from pathlib import Path
import re
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

    mac_error_blocks = re.findall(r"if\(mac_rc\)\s*\{(.*?)\n\s*\}", fullpacket, re.S)
    padding_guard = "if(session->fullpacket_macstate == LIBSSH2_MAC_CONFIRMED &&"
    mac_compare = fullpacket.find("if(memcmp(macbuf")
    guard_at = fullpacket.find(padding_guard)
    seq_at = fullpacket.find("session->remote.seqno++")
    subtract_at = fullpacket.find("session->fullpacket_payload_len -= p->padding_length")

    checks = [
        check((root / ".passwall-r66-crypto-hardening-patched").is_file(),
              "R66 hardening marker exists"),
        check(len(mac_error_blocks) == 2 and all(
            "LIBSSH2_FREE(session, p->payload);" in block and
            "p->payload = NULL;" in block and
            "return LIBSSH2_ERROR_MAC_FAILURE;" in block
            for block in mac_error_blocks),
            "both ETM and non-ETM MAC callback errors free and null payload before failing closed"),
        check(mac_compare >= 0 and guard_at > mac_compare and
              guard_at < seq_at < subtract_at,
              "padding validation runs after MAC comparison and before sequence/payload updates"),
        check("p->padding_length < 4U" in fullpacket and
              "p->padding_length > p->packet_length - 1U" in fullpacket,
              "authenticated fullpacket path enforces minimum and maximum padding"),
        check("p->padding_length > p->packet_length - 1" in read_impl and
              "p->padding_length < 4U" not in read_impl,
              "pre-MAC transport path retains only the legacy upper-bound sanity check"),
        check(init.find("if(!abstract || !free_key)") >= 0 and
              init.find("if(!abstract || !free_key)") < init.find("*abstract = NULL;") <
              init.find("if(!session || !key)") < init.find("LIBSSH2_ALLOC(session"),
              "HMAC init validates output pointers and session/key before allocation"),
        check("EVP_MAC_CTX_dup(state->ctx)" in hmac_hash and
              "EVP_MAC_init(ctx, NULL, 0, NULL)" in hmac_hash and
              "!defined(LIBSSH2_TEST_FORCE_EVP_MAC_CTX_DUP)" in hmac_hash,
              "normal context reuse and test-forced compatibility fallback paths remain available"),
        check("LIBSSH2_TEST_HMAC_CALLBACKS" in mac and
              "libssh2_test_hmac256_hash" in mac,
              "direct callback accessors compile only in dedicated test builds"),
        check(kex.count("if(session->local.mac->init(session, key, &free_key,") == 3 and
              kex.count("if(session->remote.mac->init(session, key, &free_key,") == 3,
              "KEX init-error cleanup remains present for both directions"),
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
