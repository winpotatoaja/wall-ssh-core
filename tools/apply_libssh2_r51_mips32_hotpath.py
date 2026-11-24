#!/usr/bin/env python3
"""Select native MIPS32 code generation for libssh2's two crypto hotpath TUs."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


def patch(root: Path) -> None:
    if not (root / ".passwall-r51-auth-before-decrypt-patched").is_file():
        raise RuntimeError("Run r51 authenticate-before-decrypt patch first")

    marker = root / ".passwall-r51-mips32-hotpath-patched"
    if marker.exists():
        raise RuntimeError("r51 MIPS32 hotpath patch is already present")

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r51 MIPS32 hotpath patch is pinned to libssh2 1.11.1")

    src_cmake = root / "src/CMakeLists.txt"
    replace_once(
        src_cmake,
        'include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")\n'
        'set(_sources ${CSOURCES} ${HHEADERS})',
        'include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")\n'
        'set(_sources ${CSOURCES} ${HHEADERS})\n\n'
        '# Keep only the crypto hotpath translation units in native MIPS32 mode.\n'
        'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")\n'
        '  set_source_files_properties(\n'
        '    chacha.c\n'
        '    poly1305.c\n'
        '    PROPERTIES COMPILE_OPTIONS "-mno-mips16")\n'
        'endif()',
        "apply MIPS32-only compiler option to ChaCha and Poly1305 source files",
    )

    marker.write_text(
        "libssh2 1.11.1 Passwall r51 native-MIPS32 source-specific compiler options\n"
    )
    print(
        "PASS: only chacha.c and poly1305.c receive -mno-mips16 on MIPS targets; "
        "all other libssh2 translation units retain SDK defaults"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r51_mips32_hotpath.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
