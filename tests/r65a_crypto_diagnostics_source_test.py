#!/usr/bin/env python3
"""R65-A source regression for diagnostic-only crypto instrumentation."""
from pathlib import Path
import sys


def check(ok: bool, label: str) -> bool:
    print(("PASS: " if ok else "FAIL: ") + label)
    return ok


def extract(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = source.find("{", start)
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
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
                return source[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r65a_crypto_diagnostics_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    project = Path(sys.argv[2])
    transport = (root / "src/transport.c").read_text()
    mac = (root / "src/mac.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()
    diag = (project / "libssh2_diag.h").read_text()
    core = (project / "ssh-core.c").read_text()

    decrypt = extract(
        transport,
        "static int\ndecrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,",
    )
    fullpacket = extract(
        transport,
        "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted",
    )
    send = extract(
        transport,
        "int _libssh2_transport_send(LIBSSH2_SESSION *session,",
    )
    hmac_start = mac.find("mac_method_hmac_sha2_256_hash(")
    hmac_end = mac.find("\n}\n", hmac_start)
    hmac_sha256 = mac[hmac_start:hmac_end + 3] if hmac_start >= 0 and hmac_end > hmac_start else ""

    fields = (
        "ctr_rx_evp_ns", "ctr_rx_copy_calls", "ctr_rx_copy_bytes",
        "ctr_rx_copy_ns", "mac_rx_calls", "mac_rx_bytes", "mac_rx_ns",
        "mac_tx_calls", "mac_tx_bytes", "mac_tx_ns",
        "mac_sha256_setup_calls",
    )
    checks = [
        check((root / ".passwall-r64-portable-aes-ctr-patched").is_file() and
              (root / ".passwall-r65a-crypto-diagnostics-patched").is_file(),
              "R64 prerequisite and R65-A marker are present"),
        check(all(name in priv and name in diag for name in fields),
              "private and public diagnostic layouts include all R65-A fields"),
        check(all(f"timing->{name}" in session for name in fields) and
              all(f"session->passwall_diag.{name} = 0" in session for name in fields),
              "snapshot API copies and resets all R65-A counters"),
        check("ctr_rx_start_ns = _libssh2_diag_now_ns()" in decrypt and
              "ctr_rx_evp_end_ns = _libssh2_diag_now_ns()" in decrypt and
              "ctr_rx_copy_end_ns = _libssh2_diag_now_ns()" in decrypt and
              decrypt.index("ctr_rx_evp_ns +=") < decrypt.index("memcpy(dest, source") <
              decrypt.index("ctr_rx_copy_ns +="),
              "AES-CTR RX EVP and memcpy are timed as separate regions"),
        check(decrypt.count("_libssh2_diag_now_ns()") >= 3 and
              "if(session->passwall_diag.enabled)" in decrypt,
              "CTR timing clock reads are conditional on diagnostics"),
        check(fullpacket.count("remote_mac->hash(session, macbuf") == 2 and
              fullpacket.count("mac_rx_calls++") == 2 and
              "mac_rx_bytes +=" in fullpacket and "mac_rx_ns +=" in fullpacket,
              "RX MAC timing covers ETM and non-ETM packet layouts"),
        check(send.count("local_mac->hash(session, p->outbuf + packet_length") == 2 and
              send.count("mac_tx_calls++") == 2 and
              "mac_tx_bytes +=" in send and "mac_tx_ns +=" in send,
              "TX MAC timing covers ETM and non-ETM packet layouts"),
        check("mac_sha256_setup_calls++" in hmac_sha256 and
              "_libssh2_hmac_sha256_init(&ctx, *abstract, 32)" in hmac_sha256,
              "per-packet HMAC-SHA256 setup entry count is recorded"),
        check('log_raw("[PERF-CTR] span_ms=%lld "' in core and
              "ctr_rx_evp_us=%llu" in core and "ctr_rx_copy_us=%llu" in core,
              "CTR EVP and copy metrics are emitted in a separate PERF record"),
        check('log_raw("[PERF-MAC] span_ms=%lld "' in core and
              "mac_rx_us=%llu" in core and "mac_tx_us=%llu" in core and
              "mac_sha256_setup_calls=%llu" in core,
              "MAC timing/bytes/setup count use a separate PERF record"),
        check("remote_mac->hash(session, macbuf" in fullpacket and
              "if(remote_mac->hash" not in fullpacket and
              "if(mac_rc)" in send,
              "R65-A does not alter current RX/TX MAC failure handling"),
    ]
    if not all(checks):
        return 1
    print("PASS: R65-A source-level diagnostics regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
