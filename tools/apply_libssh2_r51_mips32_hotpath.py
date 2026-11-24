#!/usr/bin/env python3
"""Keep the two libssh2 crypto hot paths in native MIPS32 mode on MIPS builds."""
from pathlib import Path
import sys


HEADER = r'''#ifndef LIBSSH2_MIPS32_HOT_H
#define LIBSSH2_MIPS32_HOT_H

#if defined(__mips__) && defined(__GNUC__)
# define LIBSSH2_MIPS32_HOT __attribute__((nomips16))
#else
# define LIBSSH2_MIPS32_HOT
#endif

#endif /* LIBSSH2_MIPS32_HOT_H */
'''


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

    src = root / "src"
    hot_header = src / "libssh2_mips32_hot.h"
    if hot_header.exists():
        raise RuntimeError("refusing to overwrite existing libssh2_mips32_hot.h")
    hot_header.write_text(HEADER)

    chacha_h = src / "chacha.h"
    poly_h = src / "poly1305.h"

    replace_once(
        chacha_h,
        "#define CHACHA_H\n",
        "#define CHACHA_H\n\n#include \"libssh2_mips32_hot.h\"\n",
        "include MIPS32 hotpath attribute header in chacha.h",
    )
    replace_once(
        poly_h,
        "#define POLY1305_H\n",
        "#define POLY1305_H\n\n#include \"libssh2_mips32_hot.h\"\n",
        "include MIPS32 hotpath attribute header in poly1305.h",
    )
    replace_once(
        chacha_h,
        "void chacha_encrypt_bytes(",
        "void LIBSSH2_MIPS32_HOT chacha_encrypt_bytes(",
        "mark chacha_encrypt_bytes as native MIPS32",
    )
    replace_once(
        poly_h,
        "void poly1305_auth(",
        "void LIBSSH2_MIPS32_HOT poly1305_auth(",
        "mark poly1305_auth as native MIPS32",
    )

    marker.write_text(
        "libssh2 1.11.1 Passwall r51 native-MIPS32 hotpath code generation\n"
    )
    print(
        "PASS: chacha_encrypt_bytes and poly1305_auth declarations use "
        "nomips16 on MIPS; non-MIPS builds retain normal compiler defaults"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r51_mips32_hotpath.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
