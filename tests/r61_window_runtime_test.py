#!/usr/bin/env python3
"""Verify runtime logs do not emit the removed per-client S2C window diagnostic."""
from pathlib import Path
import sys

FORBIDDEN = (
    "[S2C WINDOW]",
    "unexpected initial receive window",
)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: r61_window_runtime_test.py SSH_CORE_LOG [SSH_CORE_LOG ...]",
              file=sys.stderr)
        return 2

    for name in sys.argv[1:]:
        path = Path(name)
        if not path.is_file():
            print(f"FAIL: runtime log missing: {path}")
            return 1
        content = path.read_text(errors="replace")
        for marker in FORBIDDEN:
            if marker in content:
                print(f"FAIL: forbidden S2C window diagnostic found in {path}: {marker}")
                return 1
        print(f"PASS: {path.name}: no S2C WINDOW diagnostic records")

    print("PASS: R61 runtime logs remain free of per-client S2C window messages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
