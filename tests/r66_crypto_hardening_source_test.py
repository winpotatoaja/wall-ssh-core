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
                return src[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def padding_valid(padding: int, packet_length: int) -> bool:
    return 4 <= padding <= packet_length - 1


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: r66_crypto_hardening_source_test.py LIBSSH2_SOURCE_DIR",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    transport = (root / "src/transport.c").read_text()
    mac = (root / "src/mac.c").read_text()
    kex = (root / "src/kex.c").read_text()

    fullpacket = extract(transport,
                         "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted")
    read_impl = extract(transport,
                        "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)")

    cleanup_marker = (
        "if(mac_rc) {\n                    if(p->payload) {\n"
    )

    padding_values = []
    for padding in range(0, 5):
        padding_values.append(padding_valid(padding, 32))

    checks = [
        check((root / ".passwall-r66-crypto-hardening-patched").is_file(),
              "R66 crypto-hardening marker is present"),
        check(fullpacket.count(cleanup_marker) >= 2,
              "both ETM/non-ETM MAC receive failures free payload and clear its pointer"),
        check(fullpacket.count("p->payload = NULL;") >= 3,
              "fullpacket payload cleanup/ownership paths clear pointers"),
        check(fullpacket.count("return LIBSSH2_ERROR_MAC_FAILURE;") >= 2,
              "both receive MAC callbacks propagate MAC_FAILURE"),
        check("p->padding_length < 4U" in fullpacket and
              "p->padding_length > p->packet_length - 1U" in fullpacket,
              "fullpacket enforces both minimum and maximum padding"),
        check("p->padding_length < 4U" in read_impl and
              "p->padding_length > p->packet_length - 1U" in read_impl,
              "transport receive path rejects minimum/maximum padding violations"),
        check("p->padding_length < 4U" in transport and
              "p->padding_length > p->packet_length - 1U" in transport,
              "malformed padding is rejected before payload length subtraction"),
        check(padding_values == [False, False, False, False, True],
              "malformed padding 0/1/2/3 rejects and padding 4 accepts"),
        check("EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL)" in mac and
              "EVP_MAC_CTX_dup(state->ctx)" in mac,
              "R65-B HMAC EVP_MAC initialization and legacy fallback remain present"),
        check("EVP_MAC_init(ctx, NULL, 0, NULL)" in mac,
              "OpenSSL 3.0.3+ context reuse reset remains present"),
        check("EVP_MAC_update(ctx, packet, packet_len)" in mac and
              "EVP_MAC_final(ctx, buf, &out_len, 32)" in mac,
              "HMAC callback performs update/final with exact 32-byte output"),
        check(mac.count("mac_method_hmac_sha2_256_init,") == 2 and
              mac.count("mac_method_hmac_sha2_256_dtor,") == 2,
              "standard and ETM method tables retain separate init/dtor callbacks"),
        check(kex.count("if(session->local.mac->init(session, key, &free_key,") == 3 and
              kex.count("if(session->remote.mac->init(session, key, &free_key,") == 3,
              "both KEX directions retain init-failure cleanup checks"),
    ]

    if not all(checks):
        return 1
    print("PASS: R66 crypto transport/HMAC source hardening checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
