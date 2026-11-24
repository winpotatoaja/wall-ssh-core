#!/usr/bin/env python3
"""Verify source selection and built-code MIPS32r2 ChaCha assembly."""
from pathlib import Path
import re
import sys


def verify_source(root: Path) -> int:
    cmake = root / "src/CMakeLists.txt"
    chacha = root / "src/chacha.c"
    asm = root / "src/chacha-core.S"
    marker = root / ".passwall-r53-mips32r2-chacha-asm-patched"
    cmake_text = cmake.read_text() if cmake.is_file() else ""
    chacha_text = chacha.read_text() if chacha.is_file() else ""
    asm_text = asm.read_text() if asm.is_file() else ""

    checks = {
        "r53 MIPS32r2 assembly patch marker exists": marker.is_file(),
        "CMake includes assembly only for MIPS targets": (
            'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")' in cmake_text
            and 'list(APPEND _sources "${CMAKE_CURRENT_SOURCE_DIR}/chacha-core.S")' in cmake_text
        ),
        "assembly translation unit is forced to native MIPS32r2": (
            'COMPILE_OPTIONS "-mno-mips16;-mips32r2"' in cmake_text
        ),
        "assembly entry point is present": (
            ".globl\tchacha_crypt_mips" in asm_text and ".end chacha_crypt_mips" in asm_text
        ),
        "C dispatch guard limits assembly to MIPS32 ISA revisions 2-5": (
            "defined(__mips_isa_rev) && (__mips_isa_rev >= 2)" in chacha_text
            and "(__mips_isa_rev < 6)" in chacha_text
            and "defined(__mips64)" in chacha_text
        ),
        "counter-wrap packets remain on the portable C path": (
            "mips_blocks <= 0xffffffffULL - (unsigned long long)x->input[12]" in chacha_text
            and "chacha_crypt_mips(x->input, c, m, bytes, 20);" in chacha_text
        ),
        "r51 authenticate-before-decrypt remains in the build": (
            (root / ".passwall-r51-auth-before-decrypt-patched").is_file()
        ),
    }

    failed = []
    for name, ok in checks.items():
        print(("PASS: " if ok else "FAIL: ") + name)
        if not ok:
            failed.append(name)
    if failed:
        return 1
    print("PASS: r53 MIPS32r2 ChaCha source configuration")
    return 0


def verify_disassembly(path: Path) -> int:
    text = path.read_text(errors="replace")
    failed = []

    for symbol in ("chacha_encrypt_bytes", "poly1305_auth", "chacha_crypt_mips"):
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
                instructions.append((int(match.group(1), 16), match.group(2), match.group(3).lower()))

        native32 = (
            len(instructions) >= 8
            and all(len(word) == 8 and address % 4 == 0
                    for address, word, _mnemonic in instructions)
        )
        if native32:
            print(f"PASS: {symbol} uses aligned 32-bit instructions ({len(instructions)} instructions)")
        else:
            failed.append(f"{symbol}: instruction encoding is not consistently native 32-bit")
            widths = sorted({len(word) for _address, word, _mnemonic in instructions})
            print(f"FAIL: {symbol} native 32-bit encoding; parsed={len(instructions)}, opcode_widths={widths}")

        if symbol == "chacha_crypt_mips":
            mnemonics = {mnemonic for _address, _word, mnemonic in instructions}
            if "rotr" in mnemonics and "addu" in mnemonics:
                print("PASS: MIPS32r2 ChaCha assembly contains native rotate and add instructions")
            else:
                failed.append("chacha_crypt_mips: expected MIPS32r2 rotr/addu instructions")
                print("FAIL: MIPS32r2 ChaCha assembly rotate/add instruction check")

    if failed:
        print("FAIL: built MIPS32r2 ChaCha hotpath verification")
        return 1
    print("PASS: native MIPS32 codegen and the ChaCha assembly entry point are present")
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
