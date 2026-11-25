#!/usr/bin/env python3
"""Source invariants for R62 runtime ChaCha worker and threshold controls."""
from pathlib import Path
import sys

def check(value: bool, label: str) -> bool:
    print(("PASS: " if value else "FAIL: ") + label)
    return value

def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r62_chacha_config_source_test.py LIBSSH2_SOURCE_DIR SSH_CORE_C", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    core = Path(sys.argv[2]).read_text()
    chacha = (root / "src/chacha.c").read_text()
    cipher = (root / "src/cipher-chachapoly.c").read_text()
    cipher_h = (root / "src/cipher-chachapoly.h").read_text()
    crypt = (root / "src/crypt.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()
    checks = [
        check((root / ".passwall-r61-window-backpressure-patched").is_file() and
              (root / ".passwall-r62-runtime-ab-controls-patched").is_file(),
              "R61 prerequisite and R62 patch markers are present"),
        check("unsigned int min_parallel_bytes;" in chacha and
              "bytes < pool->min_parallel_bytes" in chacha,
              "per-pool threshold controls authenticated parallel dispatch"),
        check("if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS)" in chacha,
              "one-worker offload accepted and zero-worker path remains serial"),
        check(all(x in cipher for x in (
              "min_parallel_bytes != 4096U", "min_parallel_bytes != 8192U",
              "min_parallel_bytes != 16384U", "min_parallel_bytes != 24576U",
              "min_parallel_bytes != 32768U")),
              "libssh2 validates all five supported thresholds"),
        check("unsigned int min_parallel_bytes);" in cipher_h and
              "session->passwall_diag.chacha_threshold_bytes" in crypt,
              "session threshold reaches each inbound ChaCha context"),
        check(priv.count("unsigned int chacha_threshold_bytes;") == 2 and
              "libssh2_session_set_chacha_threshold" in session,
              "internal session state, public snapshot and setter include threshold"),
        check("threshold_bytes = session->passwall_diag.chacha_threshold_bytes;" in session and
              "session->passwall_diag.chacha_threshold_bytes = threshold_bytes;" in session,
              "diagnostic reset preserves runtime config"),
        check("passwall_chacha_parse_workers" in core and
              "passwall_chacha_parse_threshold_kib" in core and
              "CHACHA_WORKERS" in core and "CHACHA_THRESHOLD_KIB" in core,
              "environment and command line accept only supported settings"),
        check('"[CHACHA-CONFIG] mode=%s requested_workers=%u threshold_kib=%u threshold_bytes=%u detected_cores=%ld"' in core and
              '"[CHACHA-CONFIG-ACTIVE] requested_workers=%u active_workers=%u threshold_bytes=%u"' in core,
              "requested and post-key-exchange active settings are logged"),
        check("libssh2_chacha_threshold_bytes=%u" in core,
              "PERF-CHACHA records the selected threshold"),
    ]
    if not all(checks):
        return 1
    print("PASS: R62 runtime crypto configuration source invariants")
    return 0

if __name__ == "__main__":
    sys.exit(main())
