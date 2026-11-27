#!/usr/bin/env python3
"""R65-A diagnostic-only instrumentation for libssh2 1.11.1."""
from pathlib import Path
import sys

MARKER = ".passwall-r65a-crypto-diagnostics-patched"


def once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new, 1)


def patch_layout(root: Path, project: Path) -> None:
    private_fields = (
        "        unsigned long long ctr_rx_evp_ns;\n"
        "        unsigned long long ctr_rx_copy_calls;\n"
        "        unsigned long long ctr_rx_copy_bytes;\n"
        "        unsigned long long ctr_rx_copy_ns;\n"
        "        unsigned long long mac_rx_calls;\n"
        "        unsigned long long mac_rx_bytes;\n"
        "        unsigned long long mac_rx_ns;\n"
        "        unsigned long long mac_tx_calls;\n"
        "        unsigned long long mac_tx_bytes;\n"
        "        unsigned long long mac_tx_ns;\n"
        "        unsigned long long mac_sha256_setup_calls;\n"
    )
    snapshot_fields = (
        "    unsigned long long ctr_rx_evp_ns;\n"
        "    unsigned long long ctr_rx_copy_calls;\n"
        "    unsigned long long ctr_rx_copy_bytes;\n"
        "    unsigned long long ctr_rx_copy_ns;\n"
        "    unsigned long long mac_rx_calls;\n"
        "    unsigned long long mac_rx_bytes;\n"
        "    unsigned long long mac_rx_ns;\n"
        "    unsigned long long mac_tx_calls;\n"
        "    unsigned long long mac_tx_bytes;\n"
        "    unsigned long long mac_tx_ns;\n"
        "    unsigned long long mac_sha256_setup_calls;\n"
    )

    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    source = once(
        source,
        "        unsigned long long ctr_tx_block_bytes;\n"
        "        unsigned long long decrypt_path_ns;",
        "        unsigned long long ctr_tx_block_bytes;\n" + private_fields +
        "        unsigned long long decrypt_path_ns;",
        "extend session diagnostic fields"
    )
    source = once(
        source,
        "    unsigned long long ctr_tx_block_bytes;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "    unsigned long long ctr_tx_block_bytes;\n" + snapshot_fields +
        "} LIBSSH2_DIAG_TIMING;",
        "extend libssh2 snapshot layout"
    )
    priv.write_text(source)

    public_header = project / "libssh2_diag.h"
    source = public_header.read_text()
    source = once(
        source,
        "    unsigned long long ctr_tx_block_bytes;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "    unsigned long long ctr_tx_block_bytes;\n" + snapshot_fields +
        "} LIBSSH2_DIAG_TIMING;",
        "synchronize application snapshot layout"
    )
    public_header.write_text(source)

    session_c = root / "src/session.c"
    source = session_c.read_text()
    source = once(
        source,
        "    timing->ctr_tx_block_bytes = session->passwall_diag.ctr_tx_block_bytes;\n\n"
        "    if(reset) {",
        "    timing->ctr_tx_block_bytes = session->passwall_diag.ctr_tx_block_bytes;\n"
        "    timing->ctr_rx_evp_ns = session->passwall_diag.ctr_rx_evp_ns;\n"
        "    timing->ctr_rx_copy_calls = session->passwall_diag.ctr_rx_copy_calls;\n"
        "    timing->ctr_rx_copy_bytes = session->passwall_diag.ctr_rx_copy_bytes;\n"
        "    timing->ctr_rx_copy_ns = session->passwall_diag.ctr_rx_copy_ns;\n"
        "    timing->mac_rx_calls = session->passwall_diag.mac_rx_calls;\n"
        "    timing->mac_rx_bytes = session->passwall_diag.mac_rx_bytes;\n"
        "    timing->mac_rx_ns = session->passwall_diag.mac_rx_ns;\n"
        "    timing->mac_tx_calls = session->passwall_diag.mac_tx_calls;\n"
        "    timing->mac_tx_bytes = session->passwall_diag.mac_tx_bytes;\n"
        "    timing->mac_tx_ns = session->passwall_diag.mac_tx_ns;\n"
        "    timing->mac_sha256_setup_calls =\n"
        "        session->passwall_diag.mac_sha256_setup_calls;\n\n"
        "    if(reset) {",
        "copy R65-A counters into snapshot"
    )
    source = once(
        source,
        "        session->passwall_diag.ctr_tx_block_bytes = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "        session->passwall_diag.ctr_tx_block_bytes = 0;\n"
        "        session->passwall_diag.ctr_rx_evp_ns = 0;\n"
        "        session->passwall_diag.ctr_rx_copy_calls = 0;\n"
        "        session->passwall_diag.ctr_rx_copy_bytes = 0;\n"
        "        session->passwall_diag.ctr_rx_copy_ns = 0;\n"
        "        session->passwall_diag.mac_rx_calls = 0;\n"
        "        session->passwall_diag.mac_rx_bytes = 0;\n"
        "        session->passwall_diag.mac_rx_ns = 0;\n"
        "        session->passwall_diag.mac_tx_calls = 0;\n"
        "        session->passwall_diag.mac_tx_bytes = 0;\n"
        "        session->passwall_diag.mac_tx_ns = 0;\n"
        "        session->passwall_diag.mac_sha256_setup_calls = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "reset R65-A counters for the next interval"
    )
    session_c.write_text(source)


def patch_ctr_rx(root: Path) -> None:
    path = root / "src/transport.c"
    source = path.read_text()
    source = once(
        source,
        "        if(session->remote.crypt->crypt(\n"
        "               session, 0, source, (size_t)len,\n"
        "               &session->remote.crypt_abstract, MIDDLE_BLOCK)) {\n"
        "            if(p->payload) {\n"
        "                LIBSSH2_FREE(session, p->payload);\n"
        "                p->payload = NULL;\n"
        "            }\n"
        "            return LIBSSH2_ERROR_DECRYPT;\n"
        "        }\n"
        "        if(session->passwall_diag.enabled) {\n"
        "            session->passwall_diag.ctr_rx_bulk_calls++;\n"
        "            session->passwall_diag.ctr_rx_bulk_bytes +=\n"
        "                (unsigned long long)len;\n"
        "        }\n"
        "        memcpy(dest, source, (size_t)len);\n",
        "        unsigned long long ctr_rx_start_ns = 0;\n"
        "        unsigned long long ctr_rx_evp_end_ns = 0;\n"
        "        unsigned long long ctr_rx_copy_end_ns = 0;\n"
        "        if(session->passwall_diag.enabled)\n"
        "            ctr_rx_start_ns = _libssh2_diag_now_ns();\n"
        "        if(session->remote.crypt->crypt(\n"
        "               session, 0, source, (size_t)len,\n"
        "               &session->remote.crypt_abstract, MIDDLE_BLOCK)) {\n"
        "            if(p->payload) {\n"
        "                LIBSSH2_FREE(session, p->payload);\n"
        "                p->payload = NULL;\n"
        "            }\n"
        "            return LIBSSH2_ERROR_DECRYPT;\n"
        "        }\n"
        "        if(session->passwall_diag.enabled) {\n"
        "            ctr_rx_evp_end_ns = _libssh2_diag_now_ns();\n"
        "            session->passwall_diag.ctr_rx_bulk_calls++;\n"
        "            session->passwall_diag.ctr_rx_bulk_bytes +=\n"
        "                (unsigned long long)len;\n"
        "            if(ctr_rx_start_ns && ctr_rx_evp_end_ns >= ctr_rx_start_ns)\n"
        "                session->passwall_diag.ctr_rx_evp_ns +=\n"
        "                    ctr_rx_evp_end_ns - ctr_rx_start_ns;\n"
        "        }\n"
        "        memcpy(dest, source, (size_t)len);\n"
        "        if(session->passwall_diag.enabled) {\n"
        "            ctr_rx_copy_end_ns = _libssh2_diag_now_ns();\n"
        "            session->passwall_diag.ctr_rx_copy_calls++;\n"
        "            session->passwall_diag.ctr_rx_copy_bytes +=\n"
        "                (unsigned long long)len;\n"
        "            if(ctr_rx_evp_end_ns && ctr_rx_copy_end_ns >= ctr_rx_evp_end_ns)\n"
        "                session->passwall_diag.ctr_rx_copy_ns +=\n"
        "                    ctr_rx_copy_end_ns - ctr_rx_evp_end_ns;\n"
        "        }\n",
        "time R64 EVP CTR RX and the following memcpy separately"
    )
    path.write_text(source)


def patch_mac(root: Path) -> None:
    transport_path = root / "src/transport.c"
    source = transport_path.read_text()

    rx_old = (
        "            if(etm) {\n"
        "                /* store hash here */\n"
        "                remote_mac->hash(session, macbuf,\n"
        "                                 session->remote.seqno,\n"
        "                                 p->payload, p->total_num - mac_len,\n"
        "                                 NULL, 0,\n"
        "                                 &session->remote.mac_abstract);\n"
        "            }\n"
        "            else {\n"
        "                /* store hash here */\n"
        "                remote_mac->hash(session, macbuf,\n"
        "                                 session->remote.seqno,\n"
        "                                 p->init, 5,\n"
        "                                 p->payload,\n"
        "                                 session->fullpacket_payload_len,\n"
        "                                 &session->remote.mac_abstract);\n"
        "            }\n"
    )
    rx_new = (
        "            if(etm) {\n"
        "                unsigned long long mac_start_ns = 0;\n"
        "                unsigned long long mac_end_ns;\n"
        "                /* store hash here */\n"
        "                if(session->passwall_diag.enabled)\n"
        "                    mac_start_ns = _libssh2_diag_now_ns();\n"
        "                remote_mac->hash(session, macbuf,\n"
        "                                 session->remote.seqno,\n"
        "                                 p->payload, p->total_num - mac_len,\n"
        "                                 NULL, 0,\n"
        "                                 &session->remote.mac_abstract);\n"
        "                if(session->passwall_diag.enabled) {\n"
        "                    mac_end_ns = _libssh2_diag_now_ns();\n"
        "                    session->passwall_diag.mac_rx_calls++;\n"
        "                    session->passwall_diag.mac_rx_bytes +=\n"
        "                        4ULL + (unsigned long long)(p->total_num - mac_len);\n"
        "                    if(mac_start_ns && mac_end_ns >= mac_start_ns)\n"
        "                        session->passwall_diag.mac_rx_ns +=\n"
        "                            mac_end_ns - mac_start_ns;\n"
        "                }\n"
        "            }\n"
        "            else {\n"
        "                unsigned long long mac_start_ns = 0;\n"
        "                unsigned long long mac_end_ns;\n"
        "                /* store hash here */\n"
        "                if(session->passwall_diag.enabled)\n"
        "                    mac_start_ns = _libssh2_diag_now_ns();\n"
        "                remote_mac->hash(session, macbuf,\n"
        "                                 session->remote.seqno,\n"
        "                                 p->init, 5,\n"
        "                                 p->payload,\n"
        "                                 session->fullpacket_payload_len,\n"
        "                                 &session->remote.mac_abstract);\n"
        "                if(session->passwall_diag.enabled) {\n"
        "                    mac_end_ns = _libssh2_diag_now_ns();\n"
        "                    session->passwall_diag.mac_rx_calls++;\n"
        "                    session->passwall_diag.mac_rx_bytes +=\n"
        "                        9ULL + (unsigned long long)session->fullpacket_payload_len;\n"
        "                    if(mac_start_ns && mac_end_ns >= mac_start_ns)\n"
        "                        session->passwall_diag.mac_rx_ns +=\n"
        "                            mac_end_ns - mac_start_ns;\n"
        "                }\n"
        "            }\n"
    )
    source = once(source, rx_old, rx_new, "instrument RX ETM/non-ETM MAC time")

    tx_non_etm_old = (
        "        if(!etm && local_mac && !CRYPT_FLAG_L(session, INTEGRATED_MAC)) {\n"
        "            if(local_mac->hash(session, p->outbuf + packet_length,\n"
        "                               session->local.seqno, p->outbuf,\n"
        "                               packet_length, NULL, 0,\n"
        "                               &session->local.mac_abstract))\n"
        "                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,\n"
        "                                      \"Failed to calculate MAC\");\n"
        "        }\n"
    )
    tx_non_etm_new = (
        "        if(!etm && local_mac && !CRYPT_FLAG_L(session, INTEGRATED_MAC)) {\n"
        "            unsigned long long mac_start_ns = 0;\n"
        "            unsigned long long mac_end_ns;\n"
        "            int mac_rc;\n"
        "            if(session->passwall_diag.enabled)\n"
        "                mac_start_ns = _libssh2_diag_now_ns();\n"
        "            mac_rc = local_mac->hash(session, p->outbuf + packet_length,\n"
        "                                     session->local.seqno, p->outbuf,\n"
        "                                     packet_length, NULL, 0,\n"
        "                                     &session->local.mac_abstract);\n"
        "            if(session->passwall_diag.enabled) {\n"
        "                mac_end_ns = _libssh2_diag_now_ns();\n"
        "                session->passwall_diag.mac_tx_calls++;\n"
        "                session->passwall_diag.mac_tx_bytes +=\n"
        "                    4ULL + (unsigned long long)packet_length;\n"
        "                if(mac_start_ns && mac_end_ns >= mac_start_ns)\n"
        "                    session->passwall_diag.mac_tx_ns +=\n"
        "                        mac_end_ns - mac_start_ns;\n"
        "            }\n"
        "            if(mac_rc)\n"
        "                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,\n"
        "                                      \"Failed to calculate MAC\");\n"
        "        }\n"
    )
    source = once(source, tx_non_etm_old, tx_non_etm_new,
                  "instrument non-ETM TX MAC time")

    tx_etm_old = (
        "            if(local_mac->hash(session, p->outbuf + packet_length,\n"
        "                               session->local.seqno, p->outbuf,\n"
        "                               packet_length, NULL, 0,\n"
        "                               &session->local.mac_abstract))\n"
        "                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,\n"
        "                                      \"Failed to calculate MAC\");\n"
    )
    tx_etm_new = (
        "            unsigned long long mac_start_ns = 0;\n"
        "            unsigned long long mac_end_ns;\n"
        "            int mac_rc;\n"
        "            if(session->passwall_diag.enabled)\n"
        "                mac_start_ns = _libssh2_diag_now_ns();\n"
        "            mac_rc = local_mac->hash(session, p->outbuf + packet_length,\n"
        "                                     session->local.seqno, p->outbuf,\n"
        "                                     packet_length, NULL, 0,\n"
        "                                     &session->local.mac_abstract);\n"
        "            if(session->passwall_diag.enabled) {\n"
        "                mac_end_ns = _libssh2_diag_now_ns();\n"
        "                session->passwall_diag.mac_tx_calls++;\n"
        "                session->passwall_diag.mac_tx_bytes +=\n"
        "                    4ULL + (unsigned long long)packet_length;\n"
        "                if(mac_start_ns && mac_end_ns >= mac_start_ns)\n"
        "                    session->passwall_diag.mac_tx_ns +=\n"
        "                        mac_end_ns - mac_start_ns;\n"
        "            }\n"
        "            if(mac_rc)\n"
        "                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,\n"
        "                                      \"Failed to calculate MAC\");\n"
    )
    source = once(source, tx_etm_old, tx_etm_new, "instrument ETM TX MAC time")
    transport_path.write_text(source)

    mac_path = root / "src/mac.c"
    source = mac_path.read_text()
    source = once(
        source,
        "    (void)session;\n\n"
        "    _libssh2_htonu32(seqno_buf, seqno);\n\n"
        "    if(!_libssh2_hmac_ctx_init(&ctx))\n"
        "        return 1;\n"
        "    res = _libssh2_hmac_sha256_init(&ctx, *abstract, 32) &&\n",
        "    _libssh2_htonu32(seqno_buf, seqno);\n\n"
        "    if(!_libssh2_hmac_ctx_init(&ctx))\n"
        "        return 1;\n"
        "    if(session->passwall_diag.enabled)\n"
        "        session->passwall_diag.mac_sha256_setup_calls++;\n"
        "    res = _libssh2_hmac_sha256_init(&ctx, *abstract, 32) &&\n",
        "count HMAC-SHA256 setup calls"
    )
    mac_path.write_text(source)


def patch_core(project: Path) -> None:
    core = project / "ssh-core.c"
    source = core.read_text()
    old = (
        "    log_raw(\"[PERF-CTR] span_ms=%lld \"\n"
        "            \"ctr_rx_bulk_calls=%llu ctr_rx_bulk_bytes=%llu \"\n"
        "            \"ctr_rx_first_block_calls=%llu ctr_rx_block_calls=%llu ctr_rx_block_bytes=%llu \"\n"
        "            \"ctr_tx_bulk_calls=%llu ctr_tx_bulk_bytes=%llu \"\n"
        "            \"ctr_tx_block_calls=%llu ctr_tx_block_bytes=%llu\",\n"
        "            span_ms,\n"
        "            libssh2_diag.ctr_rx_bulk_calls,\n"
        "            libssh2_diag.ctr_rx_bulk_bytes,\n"
        "            libssh2_diag.ctr_rx_first_block_calls,\n"
        "            libssh2_diag.ctr_rx_block_calls,\n"
        "            libssh2_diag.ctr_rx_block_bytes,\n"
        "            libssh2_diag.ctr_tx_bulk_calls,\n"
        "            libssh2_diag.ctr_tx_bulk_bytes,\n"
        "            libssh2_diag.ctr_tx_block_calls,\n"
        "            libssh2_diag.ctr_tx_block_bytes);\n\n"
        "    memset(&g_perf_stats, 0, sizeof(g_perf_stats));"
    )
    new = (
        "    log_raw(\"[PERF-CTR] span_ms=%lld \"\n"
        "            \"ctr_rx_bulk_calls=%llu ctr_rx_bulk_bytes=%llu \"\n"
        "            \"ctr_rx_first_block_calls=%llu ctr_rx_block_calls=%llu ctr_rx_block_bytes=%llu \"\n"
        "            \"ctr_tx_bulk_calls=%llu ctr_tx_bulk_bytes=%llu \"\n"
        "            \"ctr_tx_block_calls=%llu ctr_tx_block_bytes=%llu \"\n"
        "            \"ctr_rx_evp_us=%llu ctr_rx_copy_calls=%llu ctr_rx_copy_bytes=%llu ctr_rx_copy_us=%llu\",\n"
        "            span_ms,\n"
        "            libssh2_diag.ctr_rx_bulk_calls,\n"
        "            libssh2_diag.ctr_rx_bulk_bytes,\n"
        "            libssh2_diag.ctr_rx_first_block_calls,\n"
        "            libssh2_diag.ctr_rx_block_calls,\n"
        "            libssh2_diag.ctr_rx_block_bytes,\n"
        "            libssh2_diag.ctr_tx_bulk_calls,\n"
        "            libssh2_diag.ctr_tx_bulk_bytes,\n"
        "            libssh2_diag.ctr_tx_block_calls,\n"
        "            libssh2_diag.ctr_tx_block_bytes,\n"
        "            (unsigned long long)(libssh2_diag.ctr_rx_evp_ns / 1000U),\n"
        "            libssh2_diag.ctr_rx_copy_calls,\n"
        "            libssh2_diag.ctr_rx_copy_bytes,\n"
        "            (unsigned long long)(libssh2_diag.ctr_rx_copy_ns / 1000U));\n\n"
        "    log_raw(\"[PERF-MAC] span_ms=%lld \"\n"
        "            \"mac_rx_calls=%llu mac_rx_bytes=%llu mac_rx_us=%llu \"\n"
        "            \"mac_tx_calls=%llu mac_tx_bytes=%llu mac_tx_us=%llu \"\n"
        "            \"mac_sha256_setup_calls=%llu\",\n"
        "            span_ms,\n"
        "            libssh2_diag.mac_rx_calls,\n"
        "            libssh2_diag.mac_rx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_rx_ns / 1000U),\n"
        "            libssh2_diag.mac_tx_calls,\n"
        "            libssh2_diag.mac_tx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_tx_ns / 1000U),\n"
        "            libssh2_diag.mac_sha256_setup_calls);\n\n"
        "    memset(&g_perf_stats, 0, sizeof(g_perf_stats));"
    )
    source = once(source, old, new, "add R65-A compact PERF records")
    core.write_text(source)


def patch(root: Path, project: Path) -> None:
    if not (root / ".passwall-r64-portable-aes-ctr-patched").is_file():
        raise RuntimeError("R65-A requires the R64 patch")
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("R65-A expects libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R65-A marker already exists")
    if "_libssh2_diag_now_ns" not in (root / "src/libssh2_priv.h").read_text():
        raise RuntimeError("R65-A requires the R43 monotonic diagnostic clock")

    patch_layout(root, project)
    patch_ctr_rx(root)
    patch_mac(root)
    patch_core(project)
    (root / MARKER).write_text(
        "Passwall R65-A: diagnostic timing for AES-CTR RX copy and HMAC-SHA256 MAC\n"
    )
    print("PASS: R65-A instrumentation added; crypto behavior is unchanged")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply_libssh2_r65a_diagnostics.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
