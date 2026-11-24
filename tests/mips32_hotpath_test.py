#!/usr/bin/env python3
"""Verify r51's native-MIPS32 hotpath annotation was applied to both APIs."""
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mips32_hotpath_test.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    header = root / "src/libssh2_mips32_hot.h"
    chacha = root / "src/chacha.h"
    poly = root / "src/poly1305.h"
    marker = root / ".passwall-r51-mips32-hotpath-patched"

    checks = {
        "r51 MIPS32 patch marker exists": marker.is_file(),
        "MIPS hotpath macro uses nomips16": header.is_file()
            and "__attribute__((nomips16))" in header.read_text(),
        "non-MIPS builds retain default function mode": header.is_file()
            and "#else\n# define LIBSSH2_MIPS32_HOT\n#endif" in header.read_text(),
        "ChaCha payload routine is annotated": chacha.is_file()
            and "void LIBSSH2_MIPS32_HOT chacha_encrypt_bytes(" in chacha.read_text(),
        "Poly1305 authenticator is annotated": poly.is_file()
            and "void LIBSSH2_MIPS32_HOT poly1305_auth(" in poly.read_text(),
    }

    failed = []
    for name, passed in checks.items():
        print(("PASS: " if passed else "FAIL: ") + name)
        if not passed:
            failed.append(name)
    if failed:
        return 1
    print("PASS: r51 native-MIPS32 hotpath annotation invariant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
