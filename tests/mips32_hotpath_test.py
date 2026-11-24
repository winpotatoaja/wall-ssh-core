#!/usr/bin/env python3
"""Verify source-level and built-code native MIPS32 hotpath selection."""
from pathlib import Path
import re
import sys


def verify_source(root: Path) -> int:
    cmake = root / "src/CMakeLists.txt"
    chacha = root / "src/chacha.h"
    poly = root / "src/poly1305.h"
    marker = root / ".passwall-r51-mips32-hotpath-patched"

    cmake_text = cmake.read_text() if cmake.is_file() else ""
    chacha_text = chacha.read_text() if chacha.is_file() else ""
    poly_text = poly.read_text() if poly.is_file() else ""

    checks = {
        "r51 native-MIPS32 patch marker exists": marker.is_file(),
        "CMake limits the override to MIPS targets": 'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")' in cmake_text,
        "ChaCha and Poly1305 receive source-specific -mno-mips16": (
            "set_source_files_properties(" in cmake_text
            and "chacha.c" in cmake_text
            and "poly1305.c" in cmake_text
            and 'PROPERTIES COMPILE_OPTIONS "-mno-mips16"' in cmake_text
        ),
        "no conflicting nomips16 declaration remains in chacha.h": "LIBSSH2_MIPS32_HOT" not in chacha_text,
        "no conflicting nomips16 declaration remains in poly1305.h": "LIBSSH2_MIPS32_HOT" not in poly_text,
        "obsolete attribute header is absent": not (root / "src/libssh2_mips32_hot.h").exists(),
    }

    failed = []
    for name, passed in checks.items():
        print(("PASS: " if passed else "FAIL: ") + name)
        if not passed:
            failed.append(name)
    if failed:
        return 1
    print("PASS: r51 native-MIPS32 source configuration invariant")
    return 0


def verify_disassembly(path: Path) -> int:
    text = path.read_text(errors="replace")
    failed = []

    for symbol in ("chacha_encrypt_bytes", "poly1305_auth"):
        marker = f"===== DISASSEMBLE {symbol} ====="
        start = text.find(marker)
        if start < 0:
            failed.append(f"{symbol}: disassembly section missing")
            print(f"FAIL: {symbol} disassembly section exists")
            continue

        end = text.find("===== DISASSEMBLE ", start + len(marker))
        section = text[start + len(marker): end if end >= 0 else len(text)]
        label = re.search(rf"<{re.escape(symbol)}>:", section)
        if not label:
            failed.append(f"{symbol}: symbol label missing")
            print(f"FAIL: {symbol} symbol label exists in objdump output")
            continue

        body = section[label.end():]
        instructions = []
        for line in body.splitlines():
            match = re.match(
                r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4,8})\s+([A-Za-z][A-Za-z0-9_.]*)",
                line,
            )
            if match:
                instructions.append((int(match.group(1), 16), match.group(2), match.group(3)))

        native32 = (
            len(instructions) >= 8
            and all(len(word) == 8 and address % 4 == 0
                    for address, word, _mnemonic in instructions)
        )
        if native32:
            print(f"PASS: {symbol} disassembles as aligned 32-bit instructions ({len(instructions)} instructions)")
        else:
            failed.append(f"{symbol}: instruction encoding is not consistently native 32-bit")
            widths = sorted({len(word) for _address, word, _mnemonic in instructions})
            print(f"FAIL: {symbol} native 32-bit encoding; parsed={len(instructions)}, opcode_widths={widths}")

    if failed:
        print("FAIL: built MIPS32 hotpath disassembly verification")
        return 1
    print("PASS: both crypto hotpaths are native 32-bit mode in the built MIPS ELF")
    return 0


def main() -> int:
    if len(sys.argv) == 2:
        return verify_source(Path(sys.argv[1]))
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-disasm":
        return verify_disassembly(Path(sys.argv[2]))
    print(
        "usage: mips32_hotpath_test.py LIBSSH2_SOURCE_DIR | "
        "--verify-disasm LIBSSH2_MIPS_DISASSEMBLY",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
