#!/usr/bin/env python3
"""R65-E: realistic AES-CTR RX size/workset diagnostics and backend-vs-bridge timing."""
from pathlib import Path
import sys

MARKER = ".passwall-r65e-realistic-rx-diagnostics-patched"

PRIVATE_COUNTERS = (
    "        unsigned long long ctr_rx_backend_ns;\n"
    "        unsigned long long ctr_rx_bridge_ns;\n"
    "        unsigned long long ctr_rx_size_le4k_calls;\n"
    "        unsigned long long ctr_rx_size_4k_8k_calls;\n"
    "        unsigned long long ctr_rx_size_8k_12k_calls;\n"
    "        unsigned long long ctr_rx_size_12k_16k_calls;\n"
    "        unsigned long long ctr_rx_size_16k_20k_calls;\n"
    "        unsigned long long ctr_rx_size_20k_24k_calls;\n"
    "        unsigned long long ctr_rx_size_24k_28k_calls;\n"
    "        unsigned long long ctr_rx_size_28k_32k_calls;\n"
    "        unsigned long long ctr_rx_size_gt32k_calls;\n"
    "        unsigned long long ctr_rx_size_min;\n"
    "        unsigned long long ctr_rx_size_max;\n"
)

SNAPSHOT_COUNTERS = (
    "    unsigned long long ctr_rx_backend_ns;\n"
    "    unsigned long long ctr_rx_bridge_ns;\n"
    "    unsigned long long ctr_rx_size_le4k_calls;\n"
    "    unsigned long long ctr_rx_size_4k_8k_calls;\n"
    "    unsigned long long ctr_rx_size_8k_12k_calls;\n"
    "    unsigned long long ctr_rx_size_12k_16k_calls;\n"
    "    unsigned long long ctr_rx_size_16k_20k_calls;\n"
    "    unsigned long long ctr_rx_size_20k_24k_calls;\n"
    "    unsigned long long ctr_rx_size_24k_28k_calls;\n"
    "    unsigned long long ctr_rx_size_28k_32k_calls;\n"
    "    unsigned long long ctr_rx_size_gt32k_calls;\n"
    "    unsigned long long ctr_rx_size_min;\n"
    "    unsigned long long ctr_rx_size_max;\n"
)

COUNTERS = [
    "ctr_rx_backend_ns",
    "ctr_rx_bridge_ns",
    "ctr_rx_size_le4k_calls",
    "ctr_rx_size_4k_8k_calls",
    "ctr_rx_size_8k_12k_calls",
    "ctr_rx_size_12k_16k_calls",
    "ctr_rx_size_16k_20k_calls",
    "ctr_rx_size_20k_24k_calls",
    "ctr_rx_size_24k_28k_calls",
    "ctr_rx_size_28k_32k_calls",
    "ctr_rx_size_gt32k_calls",
    "ctr_rx_size_min",
    "ctr_rx_size_max",
]


def once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return source.replace(old, new, 1)


def patch_layout(root: Path, project: Path) -> None:
    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    source = once(
        source,
        "        unsigned int ctr_rx_dst_align_mask;\n",
        "        unsigned int ctr_rx_dst_align_mask;\n" + PRIVATE_COUNTERS,
        "extend private R65-D diagnostic state"
    )
    source = once(
        source,
        "    unsigned int ctr_rx_dst_align_mask;\n",
        "    unsigned int ctr_rx_dst_align_mask;\n" + SNAPSHOT_COUNTERS,
        "extend private diagnostic snapshot structure"
    )
    source = once(
        source,
        "    const unsigned char *source, size_t len);\n",
        "    const unsigned char *source, size_t len,\n"
        "    unsigned long long *backend_elapsed_ns);\n",
        "extend the internal CTR bridge prototype"
    )
    priv.write_text(source)

    public = project / "libssh2_diag.h"
    source = public.read_text()
    source = once(
        source,
        "    unsigned int ctr_rx_dst_align_mask;\n",
        "    unsigned int ctr_rx_dst_align_mask;\n" + SNAPSHOT_COUNTERS,
        "synchronize public R65-E snapshot layout"
    )
    public.write_text(source)

    session = root / "src/session.c"
    source = session.read_text()
    snapshot_copy = (
        "    timing->ctr_rx_dst_align_mask = session->passwall_diag.ctr_rx_dst_align_mask;\n"
    )
    copy_lines = "".join(
        f"    timing->{name} = session->passwall_diag.{name};\n"
        for name in COUNTERS
    )
    source = once(
        source,
        snapshot_copy,
        snapshot_copy + copy_lines,
        "copy R65-E backend, bridge and size counters to snapshot"
    )
    reset_anchor = (
        "        session->passwall_diag.ctr_rx_dst_align_mask = 0;\n"
    )
    reset_lines = "".join(
        f"        session->passwall_diag.{name} = 0;\n"
        for name in COUNTERS
    )
    source = once(
        source,
        reset_anchor,
        reset_anchor + reset_lines,
        "reset R65-E interval counters"
    )
    session.write_text(source)


def patch_backend_and_bridge(root: Path) -> None:
    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    if "unsigned long long *backend_elapsed_ns" not in source:
        raise RuntimeError("R65-E bridge timing prototype was not applied")

    openssl_h = root / "src/openssl.h"
    source = openssl_h.read_text()
    source = once(
        source,
        "                                    const unsigned char *source,\n"
        "                                    size_t len);\n",
        "                                    const unsigned char *source,\n"
        "                                    size_t len,\n"
        "                                    unsigned long long *backend_elapsed_ns);\n",
        "extend OpenSSL backend timing prototype"
    )
    openssl_h.write_text(source)

    openssl_c = root / "src/openssl.c"
    source = openssl_c.read_text()
    source = once(
        source,
        "                                const unsigned char *source, size_t len)\n",
        "                                const unsigned char *source, size_t len,\n"
        "                                unsigned long long *backend_elapsed_ns)\n",
        "extend OpenSSL backend timing implementation signature"
    )
    source = once(
        source,
        "    int outl = 0;\n"
        "    int ret;\n\n"
        "    if(len == 0U)\n",
        "    int outl = 0;\n"
        "    int ret;\n"
        "    unsigned long long backend_start_ns = 0;\n"
        "    unsigned long long backend_end_ns = 0;\n\n"
        "    if(backend_elapsed_ns)\n"
        "        *backend_elapsed_ns = 0;\n\n"
        "    if(len == 0U)\n",
        "initialize R65-E backend timing"
    )
    source = once(
        source,
        "    ret = EVP_CipherUpdate(evp_ctx, dest, &outl, source, (int)len);\n"
        "    return (ret == 1 && outl == (int)len) ? 0 : 1;",
        "    if(backend_elapsed_ns)\n"
        "        backend_start_ns = _libssh2_diag_now_ns();\n"
        "    ret = EVP_CipherUpdate(evp_ctx, dest, &outl, source, (int)len);\n"
        "    if(backend_elapsed_ns) {\n"
        "        backend_end_ns = _libssh2_diag_now_ns();\n"
        "        if(backend_start_ns && backend_end_ns >= backend_start_ns)\n"
        "            *backend_elapsed_ns = backend_end_ns - backend_start_ns;\n"
        "    }\n"
        "    return (ret == 1 && outl == (int)len) ? 0 : 1;",
        "measure only the OpenSSL EVP update"
    )
    openssl_c.write_text(source)

    crypt_c = root / "src/crypt.c"
    source = crypt_c.read_text()
    source = once(
        source,
        "                                   const unsigned char *source, size_t len)\n",
        "                                   const unsigned char *source, size_t len,\n"
        "                                   unsigned long long *backend_elapsed_ns)\n",
        "extend bridge implementation signature"
    )
    source = once(
        source,
        "    return _libssh2_openssl_ctr_bulk_crypt(&cctx->h, dest, source, len);\n",
        "    return _libssh2_openssl_ctr_bulk_crypt(\n"
        "        &cctx->h, dest, source, len, backend_elapsed_ns);\n",
        "pass backend timer through RX bridge"
    )
    source = once(
        source,
        "    (void)source;\n"
        "    (void)len;\n"
        "    return 1;",
        "    (void)source;\n"
        "    (void)len;\n"
        "    (void)backend_elapsed_ns;\n"
        "    return 1;",
        "silence non-OpenSSL bridge output parameter"
    )
    crypt_c.write_text(source)


def patch_transport(root: Path) -> None:
    path = root / "src/transport.c"
    source = path.read_text()
    source = once(
        source,
        "        unsigned long long ctr_rx_evp_end_ns = 0;\n",
        "        unsigned long long ctr_rx_evp_end_ns = 0;\n"
        "        unsigned long long ctr_rx_backend_ns = 0;\n",
        "add local backend-only timer"
    )
    source = once(
        source,
        "               dest, source, (size_t)len)) {\n",
        "               dest, source, (size_t)len,\n"
        "               session->passwall_diag.enabled ? &ctr_rx_backend_ns : NULL)) {\n",
        "capture pure backend EVP duration from bridge"
    )
    old = (
        "            session->passwall_diag.ctr_rx_dst_align_mask |=\n"
        "                1U << ((unsigned int)(uintptr_t)dest & 15U);\n"
        "        }\n"
    )
    histogram = (
        "            session->passwall_diag.ctr_rx_dst_align_mask |=\n"
        "                1U << ((unsigned int)(uintptr_t)dest & 15U);\n"
        "            if((size_t)len <= 4096U)\n"
        "                session->passwall_diag.ctr_rx_size_le4k_calls++;\n"
        "            else if((size_t)len <= 8192U)\n"
        "                session->passwall_diag.ctr_rx_size_4k_8k_calls++;\n"
        "            else if((size_t)len <= 12288U)\n"
        "                session->passwall_diag.ctr_rx_size_8k_12k_calls++;\n"
        "            else if((size_t)len <= 16384U)\n"
        "                session->passwall_diag.ctr_rx_size_12k_16k_calls++;\n"
        "            else if((size_t)len <= 20480U)\n"
        "                session->passwall_diag.ctr_rx_size_16k_20k_calls++;\n"
        "            else if((size_t)len <= 24576U)\n"
        "                session->passwall_diag.ctr_rx_size_20k_24k_calls++;\n"
        "            else if((size_t)len <= 28672U)\n"
        "                session->passwall_diag.ctr_rx_size_24k_28k_calls++;\n"
        "            else if((size_t)len <= 32768U)\n"
        "                session->passwall_diag.ctr_rx_size_28k_32k_calls++;\n"
        "            else\n"
        "                session->passwall_diag.ctr_rx_size_gt32k_calls++;\n"
        "            if(session->passwall_diag.ctr_rx_size_min == 0 ||\n"
        "               (unsigned long long)len < session->passwall_diag.ctr_rx_size_min)\n"
        "                session->passwall_diag.ctr_rx_size_min = (unsigned long long)len;\n"
        "            if((unsigned long long)len > session->passwall_diag.ctr_rx_size_max)\n"
        "                session->passwall_diag.ctr_rx_size_max = (unsigned long long)len;\n"
        "        }\n"
    )
    source = once(source, old, histogram, "record exact RX bulk size distribution")

    old_time = (
        "            if(ctr_rx_start_ns && ctr_rx_evp_end_ns >= ctr_rx_start_ns)\n"
        "                session->passwall_diag.ctr_rx_evp_ns +=\n"
        "                    ctr_rx_evp_end_ns - ctr_rx_start_ns;\n"
    )
    new_time = (
        "            if(ctr_rx_start_ns && ctr_rx_evp_end_ns >= ctr_rx_start_ns) {\n"
        "                unsigned long long total_ns = ctr_rx_evp_end_ns - ctr_rx_start_ns;\n"
        "                session->passwall_diag.ctr_rx_evp_ns += total_ns;\n"
        "                session->passwall_diag.ctr_rx_backend_ns += ctr_rx_backend_ns;\n"
        "                if(total_ns >= ctr_rx_backend_ns)\n"
        "                    session->passwall_diag.ctr_rx_bridge_ns +=\n"
        "                        total_ns - ctr_rx_backend_ns;\n"
        "            }\n"
    )
    source = once(source, old_time, new_time, "split backend EVP from bridge/dispatch overhead")
    path.write_text(source)


def patch_core(project: Path) -> None:
    core = project / "ssh-core.c"
    source = core.read_text()
    anchor = (
        "            libssh2_diag.ctr_rx_src_align_mask,\n"
        "            libssh2_diag.ctr_rx_dst_align_mask);\n"
    )
    extra = (
        "            libssh2_diag.ctr_rx_src_align_mask,\n"
        "            libssh2_diag.ctr_rx_dst_align_mask);\n\n"
        "    log_raw(\"[PERF-CTR-SIZE] span_ms=%lld backend_us=%llu bridge_us=%llu \"\n"
        "            \"size_le4k=%llu size_4k_8k=%llu size_8k_12k=%llu size_12k_16k=%llu \"\n"
        "            \"size_16k_20k=%llu size_20k_24k=%llu size_24k_28k=%llu \"\n"
        "            \"size_28k_32k=%llu size_gt32k=%llu size_min=%llu size_max=%llu\",\n"
        "            span_ms,\n"
        "            (unsigned long long)(libssh2_diag.ctr_rx_backend_ns / 1000U),\n"
        "            (unsigned long long)(libssh2_diag.ctr_rx_bridge_ns / 1000U),\n"
        "            libssh2_diag.ctr_rx_size_le4k_calls,\n"
        "            libssh2_diag.ctr_rx_size_4k_8k_calls,\n"
        "            libssh2_diag.ctr_rx_size_8k_12k_calls,\n"
        "            libssh2_diag.ctr_rx_size_12k_16k_calls,\n"
        "            libssh2_diag.ctr_rx_size_16k_20k_calls,\n"
        "            libssh2_diag.ctr_rx_size_20k_24k_calls,\n"
        "            libssh2_diag.ctr_rx_size_24k_28k_calls,\n"
        "            libssh2_diag.ctr_rx_size_28k_32k_calls,\n"
        "            libssh2_diag.ctr_rx_size_gt32k_calls,\n"
        "            libssh2_diag.ctr_rx_size_min,\n"
        "            libssh2_diag.ctr_rx_size_max);\n"
    )
    source = once(source, anchor, extra, "emit R65-E packet histogram and backend/bridge split")
    core.write_text(source)


def patch(root: Path, project: Path) -> None:
    if not (root / ".passwall-r65d-aes-ctr-alignment-diagnostics-patched").is_file():
        raise RuntimeError("R65-E requires the R65-D alignment diagnostics patch")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("R65-E expects libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R65-E marker already exists")

    patch_layout(root, project)
    patch_backend_and_bridge(root)
    patch_transport(root)
    patch_core(project)
    (root / MARKER).write_text(
        "R65-E: RX size histogram, backend-vs-bridge timing and realistic workset benchmark\n"
    )
    print(
        "PASS: R65-E records runtime packet-size distribution and separates "
        "EVP backend time from bridge/dispatch overhead; crypto operation unchanged"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply_libssh2_r65e_realistic_rx_diag.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
