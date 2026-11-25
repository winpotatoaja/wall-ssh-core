#!/usr/bin/env python3
"""r53: add a guarded MIPS32r2 ChaCha assembly backend to libssh2 1.11.1."""
from pathlib import Path
import shutil
import sys


ISA_GUARD = (
    "defined(__mips__) && !defined(__mips64) && "
    "defined(__mips_isa_rev) && (__mips_isa_rev >= 2) && "
    "(__mips_isa_rev < 6)"
)


def replace_once(src: str, old: str, new: str, label: str) -> str:
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return src.replace(old, new, 1)


def patch(root: Path, project_root: Path) -> None:
    if not (root / ".passwall-r51-auth-before-decrypt-patched").is_file():
        raise RuntimeError("Run r51 authenticate-before-decrypt patch first")
    if not (root / ".passwall-r52-worker-lifecycle-patched").is_file():
        raise RuntimeError("Run r52 worker lifecycle patch first")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("r53 assembly patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r53-mips32r2-chacha-asm-patched"
    if marker.exists():
        raise RuntimeError("r53 MIPS32r2 ChaCha assembly patch is already present")

    assembly_source = project_root / "tools/mips32/chacha-core.S"
    assembly_target = root / "src/chacha-core.S"
    if not assembly_source.is_file():
        raise RuntimeError(f"missing vendored assembly source: {assembly_source}")
    asm = assembly_source.read_text()
    for required in (".globl\tchacha_crypt_mips", ".ent\tchacha_crypt_mips",
                     ".end chacha_crypt_mips", "SPDX-License-Identifier: GPL-2.0 OR MIT"):
        if required not in asm:
            raise RuntimeError("unexpected MIPS ChaCha assembly source: " + required)
    shutil.copyfile(assembly_source, assembly_target)

    chacha_path = root / "src/chacha.c"
    chacha = chacha_path.read_text()
    chacha = replace_once(
        chacha,
        "typedef unsigned int u32;\n",
        "typedef unsigned int u32;\n\n"
        f"#if {ISA_GUARD}\n"
        "extern void chacha_crypt_mips(u32 state[16], u8 *out, const u8 *in,\n"
        "                              u32 bytes, int rounds);\n"
        "#define LIBSSH2_HAVE_MIPS32R2_CHACHA_ASM 1\n"
        "#endif\n",
        "declare the guarded MIPS32r2 ChaCha assembly entry point",
    )
    chacha = replace_once(
        chacha,
        "  u_int i;\n\n"
        "  if(!bytes)\n"
        "      return;\n",
        "  u_int i;\n"
        "#if defined(LIBSSH2_HAVE_MIPS32R2_CHACHA_ASM)\n"
        "  u_int mips_full_bytes;\n"
        "  unsigned long long mips_blocks;\n"
        "#endif\n\n"
        "#if defined(LIBSSH2_HAVE_MIPS32R2_CHACHA_ASM)\n"
        "  /* Assembly processes complete blocks; portable C handles any tail.\n"
        "   * Fall back entirely if the 32-bit counter would wrap into word 13.\n"
        "   */\n"
        "  mips_full_bytes = bytes & ~(CHACHA_BLOCKLEN - 1U);\n"
        "  if(mips_full_bytes != 0U) {\n"
        "      mips_blocks = (unsigned long long)mips_full_bytes / CHACHA_BLOCKLEN;\n"
        "      if(mips_blocks <= 0xffffffffULL - (unsigned long long)x->input[12]) {\n"
        "          chacha_crypt_mips(x->input, c, m, mips_full_bytes, 20);\n"
        "          m += mips_full_bytes;\n"
        "          c += mips_full_bytes;\n"
        "          bytes -= mips_full_bytes;\n"
        "      }\n"
        "  }\n"
        "#endif\n\n"
        "  if(!bytes)\n"
        "      return;\n",
        "dispatch MIPS32r2 packets without 32-bit counter wrap to assembly",
    )
    chacha_path.write_text(chacha)

    cmake_path = root / "src/CMakeLists.txt"
    cmake = cmake_path.read_text()
    cmake = replace_once(
        cmake,
        'include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")\n'
        'set(_sources ${CSOURCES} ${HHEADERS})',
        'include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")\n'
        'set(_sources ${CSOURCES} ${HHEADERS})\n\n'
        '# r53: use the audited MIPS32r2 ChaCha core only on 32-bit MIPS targets.\n'
        'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")\n'
        '  set(_chacha_mips_asm "${CMAKE_CURRENT_SOURCE_DIR}/chacha-core.S")\n'
        '  list(APPEND _sources "${_chacha_mips_asm}")\n'
        '  set_source_files_properties("${_chacha_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        'endif()',
        "add the MIPS32r2 ChaCha assembly source with source-specific ISA flags",
    )
    cmake_path.write_text(cmake)

    marker.write_text(
        "libssh2 1.11.1 Passwall r53 guarded MIPS32r2 ChaCha assembly backend\n"
    )
    print(
        "PASS: MIPS32r2 assembly is selected only for 32-bit MIPS revision 2-5; "
        "counter-wrap packets retain the portable C fallback"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "usage: apply_libssh2_r53_mips32_chacha_asm.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
            file=sys.stderr,
        )
        sys.exit(2)
    patch(Path(sys.argv[1]), Path(sys.argv[2]))
