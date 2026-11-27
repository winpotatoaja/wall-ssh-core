#!/usr/bin/env python3
"""R65-E source checks for packet histogram, backend/bridge timing and benchmark."""
from pathlib import Path
import sys


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return bool(ok)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: r65e_aes_ctr_realistic_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    root = Path(sys.argv[1])
    project = Path(sys.argv[2])
    priv = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()
    transport = (root / "src/transport.c").read_text()
    openssl_h = (root / "src/openssl.h").read_text()
    openssl_c = (root / "src/openssl.c").read_text()
    crypt_c = (root / "src/crypt.c").read_text()
    public = (project / "libssh2_diag.h").read_text()
    core = (project / "ssh-core.c").read_text()
    patcher = (project / "tools/apply_libssh2_r65e_realistic_rx_diag.py").read_text()
    bench = (project / "tests/r65e_aes_ctr_realistic_bench.c").read_text()

    buckets = [
        "ctr_rx_size_le4k_calls", "ctr_rx_size_4k_8k_calls",
        "ctr_rx_size_8k_12k_calls", "ctr_rx_size_12k_16k_calls",
        "ctr_rx_size_16k_20k_calls", "ctr_rx_size_20k_24k_calls",
        "ctr_rx_size_24k_28k_calls", "ctr_rx_size_28k_32k_calls",
        "ctr_rx_size_gt32k_calls"
    ]
    fields = ["ctr_rx_backend_ns", "ctr_rx_bridge_ns", "ctr_rx_size_min",
              "ctr_rx_size_max"] + buckets
    checks = [
        check(all((root / m).is_file() for m in (
            ".passwall-r64-portable-aes-ctr-patched",
            ".passwall-r65a-crypto-diagnostics-patched",
            ".passwall-r65b-hmac-context-reuse-patched",
            ".passwall-r65c-rx-outofplace-patched",
            ".passwall-r65d-aes-ctr-alignment-diagnostics-patched",
            ".passwall-r65e-realistic-rx-diagnostics-patched")),
            "R64/R65-A/B/C/D/E patch prerequisites are present"),
        check(all(x in priv and x in public for x in fields),
              "private and public snapshot layouts contain all R65-E counters"),
        check(all(f"timing->{x} = session->passwall_diag.{x};" in session for x in fields) and
              all(f"session->passwall_diag.{x} = 0;" in session for x in fields),
              "snapshot copies and resets every new R65-E counter"),
        check("backend_elapsed_ns" in priv and "backend_elapsed_ns" in openssl_h and
              "backend_elapsed_ns" in openssl_c and
              "_libssh2_diag_now_ns()" in openssl_c and
              "*backend_elapsed_ns = backend_end_ns - backend_start_ns" in openssl_c,
              "OpenSSL helper measures only EVP_CipherUpdate"),
        check("backend_elapsed_ns" in crypt_c and
              "session->passwall_diag.enabled ? &ctr_rx_backend_ns : NULL" in transport and
              "session->passwall_diag.ctr_rx_bridge_ns +=" in transport,
              "runtime splits backend time from bridge/dispatch/outer timing"),
        check(all(f"session->passwall_diag.{x}++;" in transport for x in buckets) and
              "ctr_rx_size_min" in transport and "ctr_rx_size_max" in transport,
              "runtime records 4 KiB size buckets and exact min/max"),
        check("[PERF-CTR-SIZE]" in core and "backend_us=%llu bridge_us=%llu" in core and
              all(x in core for x in buckets),
              "application emits separate PERF-CTR-SIZE line"),
        check("worksets[WORKSET_CASES]" in bench and
              "256U * 1024U" in bench and "4U * 1024U * 1024U" in bench and
              "32U * 1024U * 1024U" in bench,
              "benchmark includes 256 KiB, 4 MiB and 32 MiB working sets"),
        check("chunks[CHUNK_CASES]" in bench and
              "16U * 1024U" in bench and "29U * 1024U" in bench and
              "32U * 1024U" in bench,
              "benchmark includes 16/29/32 KiB update sizes"),
        check("{12U, 11U}" in bench and "{4U, 11U}" in bench and "{4U, 15U}" in bench,
              "benchmark uses observed source/destination alignment pairs"),
        check("run_inplace_copy" in bench and "run_outofplace" in bench and
              "memcpy(dst + pos, buffer + pos, amount);" in bench and
              "checksum64(cipher, total) != cipher_hash" in bench,
              "baseline reproduces packet-by-packet in-place EVP then memcpy; candidate checks immutable source"),
        check("decrypt_impl" not in patcher and "EVP_CipherUpdate" not in patcher,
              "R65-E is diagnostic/benchmark-only; production decrypt operation unchanged"),
    ]
    if not all(checks):
        return 1
    print("PASS: R65-E realistic runtime diagnostic and workset benchmark source regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
