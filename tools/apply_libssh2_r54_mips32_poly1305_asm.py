#!/usr/bin/env python3
"""r54: add a guarded MIPS32r2/o32 Poly1305 backend to libssh2 1.11.1."""
from pathlib import Path
import shutil
import subprocess
import sys

ISA_GUARD = (
    "defined(__mips__) && !defined(__mips64) && "
    "defined(__mips_isa_rev) && (__mips_isa_rev >= 2) && "
    "(__mips_isa_rev < 6) && !defined(__mips16)"
)

ASM_ALIASES = (
    "/* Passwall r54: keep Cryptogams symbols private to this libssh2 backend. */\n"
    "#define poly1305_init poly1305_init_mips\n"
    "#define poly1305_blocks poly1305_blocks_mips\n"
    "#define poly1305_emit poly1305_emit_mips\n"
)

WRAPPER = r'''
#if LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM
typedef struct {
    uint32_t h[5];
    uint32_t r[4];
    uint32_t r5[3];
} poly1305_mips32r2_state;

extern void poly1305_init_mips(void *state, const unsigned char *key);
extern void poly1305_blocks_mips(void *state, const unsigned char *message,
                                 unsigned int length, unsigned int padbit);
extern void poly1305_emit_mips(void *state, unsigned char *tag,
                               const uint32_t *pad);
#endif

void
poly1305_auth(unsigned char out[POLY1305_TAGLEN], const unsigned char *m,
              size_t inlen, const unsigned char key[POLY1305_KEYLEN])
{
#if LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM
    poly1305_mips32r2_state state;
    uint32_t pad[4];
    unsigned char final_block[16];
    size_t full_len = inlen & ~(size_t)15U;
    size_t tail_len = inlen - full_len;

    poly1305_init_mips(&state, key);
    if(full_len != 0U)
        poly1305_blocks_mips(&state, m, (unsigned int)full_len, 1U);

    if(tail_len != 0U) {
        memset(final_block, 0, sizeof(final_block));
        memcpy(final_block, m + full_len, tail_len);
        final_block[tail_len] = 1U;
        poly1305_blocks_mips(&state, final_block, 16U, 0U);
        memset(final_block, 0, sizeof(final_block));
    }

    pad[0] = U8TO32_LE(key + 16);
    pad[1] = U8TO32_LE(key + 20);
    pad[2] = U8TO32_LE(key + 24);
    pad[3] = U8TO32_LE(key + 28);
    poly1305_emit_mips(&state, out, pad);

    memset(&state, 0, sizeof(state));
    memset(pad, 0, sizeof(pad));
#else
    poly1305_auth_portable(out, m, inlen, key);
#endif
}
'''

def replace_once(src: str, old: str, new: str, label: str) -> str:
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return src.replace(old, new, 1)


def patch(root: Path, project_root: Path) -> None:
    for marker_name in (
        ".passwall-r51-auth-before-decrypt-patched",
        ".passwall-r52-worker-lifecycle-patched",
        ".passwall-r53-mips32r2-chacha-asm-patched",
    ):
        if not (root / marker_name).is_file():
            raise RuntimeError(f"Run prior crypto patch first: {marker_name}")

    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("r54 Poly1305 patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r54-mips32r2-poly1305-asm-patched"
    if marker.exists():
        raise RuntimeError("r54 MIPS32r2 Poly1305 patch is already present")

    generator = project_root / "tools/mips32/poly1305-mips.pl"
    if not generator.is_file():
        raise RuntimeError(f"missing vendored Cryptogams generator: {generator}")
    generator_text = generator.read_text()
    if "SPDX-License-Identifier: GPL-1.0+ OR BSD-3-Clause" not in generator_text:
        raise RuntimeError("unexpected Poly1305 generator license identifier")
    if "MIPS32R2" not in generator_text or "maddu" not in generator_text:
        raise RuntimeError("Poly1305 generator lacks the MIPS32r2 MADDU path")

    perl = shutil.which("perl")
    if not perl:
        raise RuntimeError("Perl is required to generate the audited o32 assembly")

    asm_path = root / "src/poly1305-core.S"
    generated = subprocess.run(
        [perl, str(generator), "o32", str(asm_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if generated.returncode != 0 or not asm_path.is_file():
        raise RuntimeError(
            "Poly1305 o32 generation failed: "
            + (generated.stderr[-4000:] if generated.stderr else "no output")
        )

    asm_text = asm_path.read_text()
    for required in (
        ".globl\tpoly1305_init",
        ".globl\tpoly1305_blocks",
        ".globl\tpoly1305_emit",
        "maddu",
        "multu",
    ):
        if required not in asm_text:
            raise RuntimeError(f"generated Poly1305 assembly missing {required}")
    asm_path.write_text(ASM_ALIASES + asm_text)

    poly_path = root / "src/poly1305.c"
    poly = poly_path.read_text()
    poly = replace_once(
        poly,
        "void\npoly1305_auth(",
        "void\npoly1305_auth_portable(",
        "retain the existing portable Poly1305 implementation as an independent oracle",
    )
    if "LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM" in poly:
        raise RuntimeError("Poly1305 backend macro unexpectedly already exists")

    guard = (
        f"#if {ISA_GUARD}\n"
        "#define LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM 1\n"
        "#else\n"
        "#define LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM 0\n"
        "#endif\n\n"
    )
    poly = replace_once(
        poly,
        '#include "poly1305.h"\n',
        '#include "poly1305.h"\n\n'
        "void poly1305_auth_portable(unsigned char out[POLY1305_TAGLEN], const unsigned char *m, size_t inlen, const unsigned char key[POLY1305_KEYLEN]);\n\n"
        + guard,
        "select the backend only on 32-bit MIPS ISA revisions 2-5 outside MIPS16",
    )
    poly = poly.rstrip() + "\n\n" + WRAPPER.lstrip()
    poly_path.write_text(poly)

    cmake_path = root / "src/CMakeLists.txt"
    cmake = cmake_path.read_text()
    cmake = replace_once(
        cmake,
        '  set_source_files_properties("${_chacha_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        "endif()",
        '  set_source_files_properties("${_chacha_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        "endif()\n\n"
        "# r54: Poly1305 Cryptogams backend is the MIPS32 o32 ABI only.\n"
        'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips" AND CMAKE_SIZEOF_VOID_P EQUAL 4)\n'
        '  set(_poly1305_mips_asm "${CMAKE_CURRENT_SOURCE_DIR}/poly1305-core.S")\n'
        '  list(APPEND _sources "${_poly1305_mips_asm}")\n'
        '  set_source_files_properties("${_poly1305_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        "endif()",
        "add generated o32 assembly only to 32-bit MIPS builds",
    )
    cmake_path.write_text(cmake)

    marker.write_text(
        "libssh2 1.11.1 Passwall r54 guarded MIPS32r2/o32 Poly1305 assembly backend\n"
    )
    print(
        "PASS: r54 adds MIPS32r2/o32 Poly1305 init/blocks/emit; "
        "the C implementation remains the non-MIPS fallback and test oracle"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "usage: apply_libssh2_r54_mips32_poly1305_asm.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(2)
