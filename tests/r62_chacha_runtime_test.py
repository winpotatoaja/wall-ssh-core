#!/usr/bin/env python3
"""Verify selected and active R62 ChaCha config in TCP and TLS QEMU logs."""
from pathlib import Path
import re
import sys

CONFIG = re.compile(
    r"\[CHACHA-CONFIG\] mode=(auto|manual) requested_workers=(\d) "
    r"threshold_kib=(4|8|16|24|32) threshold_bytes=(4096|8192|16384|24576|32768) "
    r"detected_cores=(\d+)"
)
ACTIVE = re.compile(
    r"\[CHACHA-CONFIG-ACTIVE\] requested_workers=(\d) active_workers=(\d) "
    r"threshold_bytes=(4096|8192|16384|24576|32768)"
)
PERF = re.compile(
    r"\[PERF-CHACHA\].*?libssh2_chacha_workers_requested=(\d+) "
    r"libssh2_chacha_workers_active=(\d+) "
    r"libssh2_chacha_threshold_bytes=(4096|8192|16384|24576|32768)"
)

def verify(path: Path, require_perf: bool) -> bool:
    if not path.is_file():
        print(f"FAIL: missing runtime log: {path}")
        return False
    data = path.read_text(errors="replace")
    config = CONFIG.search(data)
    active = ACTIVE.search(data)
    if not config or not active:
        print(f"FAIL: missing R62 config record in {path}")
        return False
    mode, requested, kib, threshold_bytes, cores = config.groups()
    active_requested, active_count, active_threshold = active.groups()
    if (mode, requested, kib, threshold_bytes) != ("auto", "3", "4", "4096"):
        print(f"FAIL: unexpected default config in {path}: {config.group(0)}")
        return False
    if int(cores) < 2:
        print(f"FAIL: expected at least two detected physical cores in {path}")
        return False
    if (active_requested, active_count, active_threshold) != ("3", "3", "4096"):
        print(f"FAIL: active worker values mismatch in {path}: {active.group(0)}")
        return False
    if require_perf:
        perf = PERF.search(data)
        if not perf or perf.groups() != ("3", "3", "4096"):
            print(f"FAIL: PERF-CHACHA threshold/worker telemetry mismatch in {path}")
            return False
    print(f"PASS: {path.name}: auto workers=3 active=3 threshold=4 KiB cores={cores}")
    return True

def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r62_chacha_runtime_test.py TCP_LOG TLS_LOG", file=sys.stderr)
        return 2
    if not verify(Path(sys.argv[1]), True):
        return 1
    if not verify(Path(sys.argv[2]), False):
        return 1
    print("PASS: R62 TCP/TLS runtime configuration and PERF-CHACHA verification")
    return 0

if __name__ == "__main__":
    sys.exit(main())
