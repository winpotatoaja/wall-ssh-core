#!/usr/bin/env python3
"""Source checks for compact, complete r58 ChaCha PERF output."""
from pathlib import Path
import re
import sys


def check(condition: bool, label: str) -> bool:
    print(("PASS: " if condition else "FAIL: ") + label)
    return condition


def extract_log_call(source: str, marker: str) -> str:
    needle = 'log_raw("' + marker
    start = source.find(needle)
    if start < 0 or source.find(needle, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one log_raw call for {marker}")
    end = source.find(");", start)
    if end < 0:
        raise RuntimeError(f"unterminated log_raw call for {marker}")
    return source[start:end + 2]


def format_text(call: str) -> str:
    return "".join(re.findall(r'"((?:\\.|[^"\\])*)"', call))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: r58_chacha_perf_log_test.py ssh-core.c", file=sys.stderr)
        return 2

    source = Path(sys.argv[1]).read_text()
    main_log = extract_log_call(source, "[PERF] span_ms=")
    chacha_log = extract_log_call(source, "[PERF-CHACHA] span_ms=")
    chacha_format = format_text(chacha_log)
    main_format = format_text(main_log)

    required = (
        "libssh2_chacha_workers_requested",
        "libssh2_chacha_workers_active",
        "libssh2_chacha_poly1305_us",
        "libssh2_chacha_poly1305_offloaded_packets",
        "libssh2_chacha20_key_us",
        "libssh2_chacha20_header_us",
        "libssh2_chacha20_payload_us",
        "libssh2_chacha20_serial_us",
        "libssh2_chacha20_serial_bytes",
        "libssh2_chacha20_serial_packets",
        "libssh2_chacha20_parallel_us",
        "libssh2_chacha20_parallel_bytes",
        "libssh2_chacha20_parallel_packets",
        "libssh2_chacha_poly1305_wall_us",
        "libssh2_chacha20_decrypt_wall_us",
        "libssh2_chacha20_worker_cpu_us",
        "libssh2_chacha20_worker_critical_us",
        "libssh2_chacha20_parallel_other_us",
        "libssh2_chacha20_profile_packets",
    )

    checks = [
        check("libssh2_chacha_" not in main_format and
              "libssh2_chacha20_" not in main_format,
              "main PERF record no longer contains the extended ChaCha fields"),
        check(all(field + "=" in chacha_format for field in required),
              "PERF-CHACHA record retains every r57 metric key"),
        check("libssh2_diag.chacha_poly1305_wall_ns" in chacha_log and
              "libssh2_diag.chacha20_decrypt_wall_ns" in chacha_log and
              "libssh2_diag.chacha20_worker_cpu_ns" in chacha_log and
              "libssh2_diag.chacha20_worker_critical_ns" in chacha_log and
              "libssh2_diag.chacha20_parallel_other_ns" in chacha_log and
              "libssh2_diag.chacha20_profile_packets" in chacha_log,
              "all new r57 phase counters are emitted from the diagnostic snapshot"),
        check(len(main_format) < 1800 and len(chacha_format) < 1024,
              "both PERF records remain below conservative log-line limits"),
        check("libssh2_packet_queue_enqueued_bytes" in main_format,
              "main PERF record retains the transport and packet-queue metrics"),
    ]

    if not all(checks):
        return 1
    print("PASS: r58 split PERF output preserves all ChaCha profile fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
