#!/usr/bin/env python3
"""Verify r54 Poly1305 assembly source selection and MIPS32r2 disassembly."""
from pathlib import Path
import re
import sys


def verify_source(root: Path) -> int:
    cmake = root / "src/CMakeLists.txt"
    poly = root / "src/poly1305.c"
    asm = root / "src/poly1305-core.S"
    marker = root / ".passwall-r54-mips32r2-poly1305-asm-patched"
    cmake_text = cmake.read_text() if cmake.is_file() else ""
    poly_text = poly.read_text() if poly.is_file() else ""
    asm_text = asm.read_text() if asm.is_file() else ""

    checks = {
        "r54 Poly1305 assembly patch marker exists": marker.is_file(),
        "portable C implementation remains available as test oracle": (
            "poly1305_auth_portable(" in poly_text
        ),
        "MIPS32 ISA guard excludes MIPS64 and MIPS16": (
            "defined(__mips__) && !defined(__mips64)" in poly_text
            and "(__mips_isa_rev >= 2)" in poly_text
            and "(__mips_isa_rev < 6)" in poly_text
            and "!defined(__mips16)" in poly_text
        ),
        "MIPS wrapper uses init, complete-block and emit assembly primitives": (
            "poly1305_init_mips(&state, key)" in poly_text
            and "poly1305_blocks_mips(&state, m, (unsigned int)full_len, 1U)" in poly_text
            and "poly1305_emit_mips(&state, out, pad)" in poly_text
        ),
        "partial block uses explicit 1-byte padding and zero hibit": (
            "final_block[tail_len] = 1U" in poly_text
            and "poly1305_blocks_mips(&state, final_block, 16U, 0U)" in poly_text
        ),
        "assembly symbols are renamed to private MIPS entry points": (
            "#define poly1305_init poly1305_init_mips" in asm_text
            and "#define poly1305_blocks poly1305_blocks_mips" in asm_text
            and "#define poly1305_emit poly1305_emit_mips" in asm_text
            and ".hidden poly1305_init_mips" in asm_text
            and ".hidden poly1305_blocks_mips" in asm_text
            and ".hidden poly1305_emit_mips" in asm_text
        ),
        "generated assembly contains MIPS32 multiply-accumulate path": (
            ".globl\tpoly1305_blocks" in asm_text
            and "multu" in asm_text
            and "maddu" in asm_text
        ),
        "CMake adds generated assembly only for 32-bit MIPS": (
            'CMAKE_SYSTEM_PROCESSOR MATCHES "mips" AND CMAKE_SIZEOF_VOID_P EQUAL 4' in cmake_text
            and 'set(_poly1305_mips_asm "${CMAKE_CURRENT_SOURCE_DIR}/poly1305-core.S")' in cmake_text
            and 'list(APPEND _sources "${_poly1305_mips_asm}")' in cmake_text
            and 'COMPILE_OPTIONS "-mno-mips16;-mips32r2"' in cmake_text
        ),
    }

    failed = []
    for label, ok in checks.items():
        print(("PASS: " if ok else "FAIL: ") + label)
        if not ok:
            failed.append(label)
    if failed:
        print("FAIL: r54 Poly1305 source verification")
        return 1
    print("PASS: r54 MIPS32r2/o32 Poly1305 source configuration")
    return 0


def verify_disassembly(path: Path) -> int:
    content = path.read_text(errors="replace")
    failed = []
    for symbol in ("poly1305_init_mips", "poly1305_blocks_mips", "poly1305_emit_mips"):
        marker = f"===== DISASSEMBLE {symbol} ====="
        start = content.find(marker)
        if start < 0:
            print(f"FAIL: missing disassembly section {symbol}")
            failed.append(symbol)
            continue
        end = content.find("===== DISASSEMBLE ", start + len(marker))
        section = content[start + len(marker):end if end >= 0 else len(content)]
        label = re.search(rf"<{re.escape(symbol)}>:", section)
        if not label:
            print(f"FAIL: missing symbol label {symbol}")
            failed.append(symbol)
            continue
        instructions = []
        for line in section[label.end():].splitlines():
            match = re.match(
                r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{4,8})\s+([A-Za-z][A-Za-z0-9_.]*)",
                line,
            )
            if match:
                instructions.append((int(match.group(1), 16), match.group(2), match.group(3).lower()))
        native32 = (
            len(instructions) >= 8
            and all(len(word) == 8 and address % 4 == 0
                    for address, word, _mnemonic in instructions)
        )
        if not native32:
            print(f"FAIL: {symbol} is not consistently native 32-bit code")
            failed.append(symbol)
        else:
            print(f"PASS: {symbol} contains aligned 32-bit instructions ({len(instructions)})")
        if symbol == "poly1305_blocks_mips":
            mnemonics = [mnemonic for _address, _word, mnemonic in instructions]
            has_multu = "multu" in mnemonics
            has_maddu = "maddu" in mnemonics
            if not (has_multu and has_maddu):
                print(f"FAIL: expected MIPS32r2 multu/maddu; multu={has_multu} maddu={has_maddu}")
                failed.append("poly1305_blocks_mips multiply-accumulate opcodes")
            else:
                print("PASS: Poly1305 block loop uses MIPS32r2 MULTU/MADDU")
    if failed:
        return 1
    print("PASS: r54 MIPS32r2/o32 Poly1305 disassembly")
    return 0


def main() -> int:
    if len(sys.argv) == 2:
        return verify_source(Path(sys.argv[1]))
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-disasm":
        return verify_disassembly(Path(sys.argv[2]))
    print("usage: poly1305_mips_hotpath_test.py LIBSSH2_SOURCE_DIR | --verify-disasm DISASSEMBLY",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
