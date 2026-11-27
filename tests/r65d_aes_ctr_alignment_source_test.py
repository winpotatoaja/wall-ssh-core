#!/usr/bin/env python3
"""R65-D source checks for live AES-CTR pointer alignment telemetry."""
from pathlib import Path
import sys


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return bool(ok)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: r65d_aes_ctr_alignment_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    root = Path(sys.argv[1])
    project = Path(sys.argv[2])
    priv = (root / "src/libssh2_priv.h").read_text()
    transport = (root / "src/transport.c").read_text()
    session = (root / "src/session.c").read_text()
    public = (project / "libssh2_diag.h").read_text()
    core = (project / "ssh-core.c").read_text()
    patcher = (project / "tools/apply_libssh2_r65d_alignment_diag.py").read_text()
    bench = (project / "tests/r65d_aes_ctr_alignment_bench.c").read_text()

    checks = [
        check(all((root / marker).is_file() for marker in (
            ".passwall-r64-portable-aes-ctr-patched",
            ".passwall-r65a-crypto-diagnostics-patched",
            ".passwall-r65b-hmac-context-reuse-patched",
            ".passwall-r65c-rx-outofplace-patched",
            ".passwall-r65d-aes-ctr-alignment-diagnostics-patched")),
            "R64 and R65-A/B/C/D prerequisite markers are present"),
        check("ctr_rx_src_align_mask" in priv and "ctr_rx_dst_align_mask" in priv and
              "ctr_rx_src_align_mask" in public and "ctr_rx_dst_align_mask" in public,
              "private and public diagnostic layouts include both masks"),
        check("timing->ctr_rx_src_align_mask" in session and
              "timing->ctr_rx_dst_align_mask" in session and
              "session->passwall_diag.ctr_rx_src_align_mask = 0;" in session and
              "session->passwall_diag.ctr_rx_dst_align_mask = 0;" in session,
              "snapshot copies and interval reset handle alignment masks"),
        check("1U << ((unsigned int)(uintptr_t)source & 15U)" in transport and
              "1U << ((unsigned int)(uintptr_t)dest & 15U)" in transport,
              "runtime records source/destination residues modulo 16"),
        check("ctr_rx_src_align_mask=0x%04x" in core and
              "ctr_rx_dst_align_mask=0x%04x" in core and
              "libssh2_diag.ctr_rx_src_align_mask" in core and
              "libssh2_diag.ctr_rx_dst_align_mask" in core,
              "PERF-CTR publishes both alignment masks"),
        check("EVP_CipherUpdate(ctx, buffer + pos, &outl," in bench and
              "EVP_CipherUpdate(ctx, dst + pos, &outl," in bench and
              "memcpy(dst + pos, src + pos, CHUNK_BYTES)" in bench,
              "benchmark compares in-place EVP, packet copy and out-of-place EVP"),
        check("#define ALIGN_COUNT 16U" in bench and
              "#define CHUNK_BYTES (16U * 1024U)" in bench and
              "#define TOTAL_BYTES (256U * 1024U)" in bench and
              "#define TRIALS 5U" in bench and
              "PAIR src=" in bench and "SUMMARY pairs=" in bench,
              "benchmark covers all 256 alignment pairs, 16 KiB updates, five trials"),
        check("memcmp(output, expected, TOTAL_BYTES)" in bench and
              "memcmp(mut, expected, TOTAL_BYTES)" in bench and
              "memcmp(cipher, snapshot, TOTAL_BYTES)" in bench,
              "benchmark validates plaintext and immutable OOP source"),
        check("decrypt_impl" not in patcher and "EVP_CipherUpdate" not in patcher and
              "ctr_rx_src_align_mask" in patcher,
              "R65-D is telemetry-only; R65-C crypto operation stays unchanged"),
    ]
    if not all(checks):
        return 1
    print("PASS: R65-D source-level alignment telemetry and benchmark regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
