#!/usr/bin/env python3
"""Verify source selection and built-code MIPS32r2 ChaCha assembly."""
from pathlib import Path
import re
import sys


def instruction_word_variants(raw_word: str) -> set[int]:
    """Return both normal and byte-swapped interpretations of one MIPS word."""
    try:
        value = int(raw_word, 16)
    except ValueError:
        return set()
    if value < 0 or value > 0xFFFFFFFF:
        return set()
    swapped = int.from_bytes(value.to_bytes(4, "big"), "little")
    return {value, swapped}


def is_mips32r2_rotr(word: int) -> bool:
    """Recognize SPECIAL/ROTR: rs=1, funct=2, nonzero shift amount."""
    return (
        ((word >> 26) & 0x3F) == 0
        and ((word >> 21) & 0x1F) == 1
        and (word & 0x3F) == 0x02
        and ((word >> 6) & 0x1F) != 0
    )


def is_mips_addu(word: int) -> bool:
    """Recognize the native 32-bit SPECIAL/ADDU instruction encoding."""
    return ((word >> 26) & 0x3F) == 0 and (word & 0x3F) == 0x21


def verify_opcode_decoder() -> bool:
    """Self-test opcode recognition in both common objdump byte orders."""
    cases = (
        ("ROTR", "00294402", is_mips32r2_rotr),
        ("ROTR byte-swapped", "02442900", is_mips32r2_rotr),
        ("ADDU", "016c5021", is_mips_addu),
        ("ADDU byte-swapped", "21506c01", is_mips_addu),
    )
    failed = []
    for name, raw_word, predicate in cases:
        if not any(predicate(word) for word in instruction_word_variants(raw_word)):
            failed.append(name)
    if failed:
        print("FAIL: MIPS instruction opcode decoder self-test: " + ", ".join(failed))
        return False
    print("PASS: MIPS32r2 ROTR/ADDU opcode decoder (both byte orders)")
    return True


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
            and "enable_language(ASM)" in cmake_text
            and 'set(_chacha_mips_asm "${CMAKE_CURRENT_SOURCE_DIR}/chacha-core.S")' in cmake_text
            and 'list(APPEND _sources "${_chacha_mips_asm}")' in cmake_text
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
            "mips_full_bytes = bytes & ~(CHACHA_BLOCKLEN - 1U)" in chacha_text
            and "mips_blocks <= 0xffffffffULL - (unsigned long long)x->input[12]" in chacha_text
            and "chacha_crypt_mips(x->input, c, m, mips_full_bytes, 20);" in chacha_text
            and "bytes -= mips_full_bytes;" in chacha_text
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
    if not verify_opcode_decoder():
        failed.append("MIPS32r2 ROTR/ADDU opcode decoder self-test")
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
            raw_words = set()
            mnemonics = {mnemonic for _address, _word, mnemonic in instructions}
            for _address, raw_word, _mnemonic in instructions:
                raw_words.update(instruction_word_variants(raw_word))
            has_rotr = any(is_mips32r2_rotr(word) for word in raw_words)
            has_addu = any(is_mips_addu(word) for word in raw_words)
            if has_rotr and has_addu:
                print("PASS: MIPS32r2 ChaCha assembly has encoded ROTR and ADDU instructions")
            else:
                failed.append("chacha_crypt_mips: expected MIPS32r2 ROTR/ADDU instruction encodings")
                print(
                    "FAIL: MIPS32r2 ChaCha opcode check; "
                    f"encoded_rotr={has_rotr}, encoded_addu={has_addu}, "
                    f"objdump_mnemonics={sorted(mnemonics)}"
                )

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
