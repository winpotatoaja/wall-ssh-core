#!/usr/bin/env python3
"""Validate r59 ChaCha PERF records with both ChaCha field-name prefixes."""
from pathlib import Path
import re
import sys

FIELD_RE = re.compile(r"(libssh2_chacha(?:20)?_[a-z0-9_]+)=(\d+)")
REQUIRED_POSITIVE = (
    "libssh2_chacha_poly1305_wall_us",
    "libssh2_chacha20_decrypt_wall_us",
    "libssh2_chacha20_worker_cpu_us",
    "libssh2_chacha20_worker_critical_us",
    "libssh2_chacha20_profile_packets",
    "libssh2_chacha_poly1305_offloaded_packets",
)


def parse_perf_chacha(line: str):
    if "[PERF-CHACHA]" not in line:
        return None
    return {key: int(value) for key, value in FIELD_RE.findall(line)}


def valid_record(fields) -> bool:
    if not fields:
        return False
    poly_total = fields.get("libssh2_chacha_poly1305_us", 0)
    poly_wall = fields.get("libssh2_chacha_poly1305_wall_us", 0)
    profile_packets = fields.get("libssh2_chacha20_profile_packets", 0)
    offloaded_packets = fields.get("libssh2_chacha_poly1305_offloaded_packets", 0)
    # poly1305_us includes serial fallback MAC work; poly1305_wall_us
    # measures only the authenticated parallel path.
    if poly_wall <= 0 or poly_total < poly_wall:
        return False
    if profile_packets <= 0 or profile_packets != offloaded_packets:
        return False
    return all(fields.get(key, 0) > 0 for key in REQUIRED_POSITIVE)


def self_test() -> bool:
    valid = (
        "[PERF-CHACHA] span_ms=1106 "
        "libssh2_chacha_poly1305_us=33791 "
        "libssh2_chacha_poly1305_offloaded_packets=378 "
        "libssh2_chacha_poly1305_wall_us=33552 "
        "libssh2_chacha20_decrypt_wall_us=538867 "
        "libssh2_chacha20_worker_cpu_us=487251 "
        "libssh2_chacha20_worker_critical_us=199688 "
        "libssh2_chacha20_profile_packets=378"
    )
    invalid_missing = (
        "[PERF-CHACHA] span_ms=1106 "
        "libssh2_chacha_poly1305_us=33791 "
        "libssh2_chacha_poly1305_offloaded_packets=378 "
        "libssh2_chacha_poly1305_wall_us=33552"
    )
    invalid_mismatch = valid.replace(
        "libssh2_chacha20_profile_packets=378",
        "libssh2_chacha20_profile_packets=377",
    )
    checks = (
        ("parser reads both libssh2_chacha_ and libssh2_chacha20_ fields",
         valid_record(parse_perf_chacha(valid))),
        ("missing ChaCha20 phase fields are rejected",
         not valid_record(parse_perf_chacha(invalid_missing))),
        ("profile/offload packet-count mismatch is rejected",
         not valid_record(parse_perf_chacha(invalid_mismatch))),
    )
    ok = True
    for label, passed in checks:
        print(("PASS: " if passed else "FAIL: ") + label)
        ok = ok and passed
    return ok


def check_log(path: Path) -> bool:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"FAIL: cannot read PERF log {path}: {exc}", file=sys.stderr)
        return False
    seen = 0
    for line in lines:
        fields = parse_perf_chacha(line)
        if fields is None:
            continue
        seen += 1
        if valid_record(fields):
            print(
                "PASS: r59 PERF record validated "
                f"(offloaded_packets={fields['libssh2_chacha_poly1305_offloaded_packets']}, "
                f"profile_packets={fields['libssh2_chacha20_profile_packets']}, "
                f"poly_total_us={fields['libssh2_chacha_poly1305_us']}, "
                f"poly_parallel_wall_us={fields['libssh2_chacha_poly1305_wall_us']})"
            )
            return True
    print(
        f"FAIL: no valid r59 PERF-CHACHA record found in {path} "
        f"(records_seen={seen})",
        file=sys.stderr,
    )
    return False


def main() -> int:
    if len(sys.argv) == 1:
        return 0 if self_test() else 1
    if len(sys.argv) == 2:
        return 0 if check_log(Path(sys.argv[1])) else 1
    print("usage: r59_perf_log_parser_test.py [PERF_LOG]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
