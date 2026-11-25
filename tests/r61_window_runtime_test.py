#!/usr/bin/env python3
"""Verify the initial SSH S2C receive window observed by TCP and TLS relays."""
from pathlib import Path
import re
import sys

EXPECTED_WINDOW = 512 * 1024
EXPECTED_RING = 256 * 1024
WINDOW_RE = re.compile(r"\[S2C WINDOW\].*?initial=(\d+).*?ring=(\d+)")

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: r61_window_runtime_test.py SSH_CORE_LOG [SSH_CORE_LOG ...]",
              file=sys.stderr)
        return 2
    total = 0
    for name in sys.argv[1:]:
        path = Path(name)
        if not path.is_file():
            print(f"FAIL: runtime log missing: {path}")
            return 1
        matches = WINDOW_RE.findall(path.read_text(errors="replace"))
        if not matches:
            print(f"FAIL: no [S2C WINDOW] runtime records in {path}")
            return 1
        for initial_text, ring_text in matches:
            initial = int(initial_text)
            ring = int(ring_text)
            if initial != EXPECTED_WINDOW or ring != EXPECTED_RING:
                print(f"FAIL: {path}: initial={initial} ring={ring}; "
                      f"expected initial={EXPECTED_WINDOW} ring={EXPECTED_RING}")
                return 1
        total += len(matches)
        print(f"PASS: {path.name}: {len(matches)} direct-tcpip channel(s) "
              "advertised a 512 KiB receive window for the 256 KiB S2C ring")
    print(f"PASS: R61 TCP/TLS runtime receive-window validation; channels={total}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
