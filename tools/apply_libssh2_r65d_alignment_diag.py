#!/usr/bin/env python3
"""R65-D: record live RX pointer alignment for AES-128-CTR."""
from pathlib import Path
import sys

MARKER = ".passwall-r65d-aes-ctr-alignment-diagnostics-patched"


def once(source, old, new, label):
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return source.replace(old, new, 1)


def patch(root: Path, project: Path) -> None:
    for marker in (
        ".passwall-r64-portable-aes-ctr-patched",
        ".passwall-r65a-crypto-diagnostics-patched",
        ".passwall-r65b-hmac-context-reuse-patched",
        ".passwall-r65c-rx-outofplace-patched",
    ):
        if not (root / marker).is_file():
            raise RuntimeError(f"R65-D prerequisite missing: {marker}")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("R65-D expects libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R65-D marker already exists")

    private_fields = (
        "        unsigned int ctr_rx_src_align_mask;\n"
        "        unsigned int ctr_rx_dst_align_mask;\n"
    )
    snapshot_fields = (
        "    unsigned int ctr_rx_src_align_mask;\n"
        "    unsigned int ctr_rx_dst_align_mask;\n"
    )

    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    source = once(
        source,
        "        unsigned long long ctr_tx_block_bytes;\n"
        "        unsigned long long ctr_rx_evp_ns;",
        "        unsigned long long ctr_tx_block_bytes;\n" + private_fields +
        "        unsigned long long ctr_rx_evp_ns;",
        "extend private session alignment masks"
    )
    source = once(
        source,
        "    unsigned long long ctr_tx_block_bytes;\n"
        "    unsigned long long ctr_rx_evp_ns;",
        "    unsigned long long ctr_tx_block_bytes;\n" + snapshot_fields +
        "    unsigned long long ctr_rx_evp_ns;",
        "extend private snapshot alignment masks"
    )
    priv.write_text(source)

    public = project / "libssh2_diag.h"
    source = public.read_text()
    source = once(
        source,
        "    unsigned long long ctr_tx_block_bytes;\n"
        "    unsigned long long ctr_rx_evp_ns;",
        "    unsigned long long ctr_tx_block_bytes;\n" + snapshot_fields +
        "    unsigned long long ctr_rx_evp_ns;",
        "extend public snapshot alignment masks"
    )
    public.write_text(source)

    session = root / "src/session.c"
    source = session.read_text()
    source = once(
        source,
        "    timing->ctr_tx_block_bytes = session->passwall_diag.ctr_tx_block_bytes;\n"
        "    timing->ctr_rx_evp_ns = session->passwall_diag.ctr_rx_evp_ns;",
        "    timing->ctr_tx_block_bytes = session->passwall_diag.ctr_tx_block_bytes;\n"
        "    timing->ctr_rx_src_align_mask = session->passwall_diag.ctr_rx_src_align_mask;\n"
        "    timing->ctr_rx_dst_align_mask = session->passwall_diag.ctr_rx_dst_align_mask;\n"
        "    timing->ctr_rx_evp_ns = session->passwall_diag.ctr_rx_evp_ns;",
        "copy alignment masks into snapshot"
    )
    source = once(
        source,
        "        session->passwall_diag.ctr_tx_block_bytes = 0;\n"
        "        session->passwall_diag.ctr_rx_evp_ns = 0;",
        "        session->passwall_diag.ctr_tx_block_bytes = 0;\n"
        "        session->passwall_diag.ctr_rx_src_align_mask = 0;\n"
        "        session->passwall_diag.ctr_rx_dst_align_mask = 0;\n"
        "        session->passwall_diag.ctr_rx_evp_ns = 0;",
        "reset alignment masks with interval counters"
    )
    session.write_text(source)

    transport = root / "src/transport.c"
    source = transport.read_text()
    source = once(
        source,
        '#include "libssh2_priv.h"\n',
        '#include "libssh2_priv.h"\n#include <stdint.h>\n',
        "include uintptr_t for alignment telemetry"
    )
    source = once(
        source,
        "        if(session->passwall_diag.enabled)\n"
        "            ctr_rx_start_ns = _libssh2_diag_now_ns();\n",
        "        if(session->passwall_diag.enabled) {\n"
        "            ctr_rx_start_ns = _libssh2_diag_now_ns();\n"
        "            session->passwall_diag.ctr_rx_src_align_mask |=\n"
        "                1U << ((unsigned int)(uintptr_t)source & 15U);\n"
        "            session->passwall_diag.ctr_rx_dst_align_mask |=\n"
        "                1U << ((unsigned int)(uintptr_t)dest & 15U);\n"
        "        }\n",
        "record RX source/destination residues in R65-C bulk path"
    )
    transport.write_text(source)

    core = project / "ssh-core.c"
    source = core.read_text()
    source = once(
        source,
        '"ctr_rx_evp_us=%llu ctr_rx_copy_calls=%llu ctr_rx_copy_bytes=%llu ctr_rx_copy_us=%llu",\n',
        '"ctr_rx_evp_us=%llu ctr_rx_copy_calls=%llu ctr_rx_copy_bytes=%llu ctr_rx_copy_us=%llu "\n'
        '"ctr_rx_src_align_mask=0x%04x ctr_rx_dst_align_mask=0x%04x",\n',
        "append alignment masks to PERF-CTR format"
    )
    source = once(
        source,
        "            (unsigned long long)(libssh2_diag.ctr_rx_copy_ns / 1000U));",
        "            (unsigned long long)(libssh2_diag.ctr_rx_copy_ns / 1000U),\n"
        "            libssh2_diag.ctr_rx_src_align_mask,\n"
        "            libssh2_diag.ctr_rx_dst_align_mask);",
        "append alignment mask arguments"
    )
    core.write_text(source)

    (root / MARKER).write_text("R65-D: AES-128-CTR RX pointer alignment masks\n")
    print("PASS: R65-D alignment telemetry added; R65-C crypto operation unchanged")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply_libssh2_r65d_alignment_diag.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
