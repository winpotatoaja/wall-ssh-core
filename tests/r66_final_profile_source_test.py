#!/usr/bin/env python3
"""R66 final profile regression: retain R64 in-place CTR RX + copy and R65-B HMAC reuse."""
from pathlib import Path
import sys


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return bool(ok)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: r66_final_profile_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    root, project = Path(sys.argv[1]), Path(sys.argv[2])
    transport = (root / "src/transport.c").read_text()
    crypt = (root / "src/crypt.c").read_text()
    openssl = (root / "src/openssl.c").read_text()
    mac = (root / "src/mac.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    diag = (project / "libssh2_diag.h").read_text()
    makefile = (project / "Makefile").read_text()
    workflow = (project / ".github/workflows/passwall-ssh-core-openwrt24-mipsel-vm.yml").read_text()

    markers = [
        ".passwall-r64-portable-aes-ctr-patched",
        ".passwall-r65a-crypto-diagnostics-patched",
        ".passwall-r65b-hmac-context-reuse-patched",
    ]
    experimental_markers = [
        ".passwall-r65c-rx-outofplace-patched",
        ".passwall-r65d-aes-ctr-alignment-diagnostics-patched",
        ".passwall-r65e-realistic-rx-diagnostics-patched",
    ]

    bulk_marker = "if(CRYPT_FLAG_R(session, CTR_BULK) && !IS_FIRST(firstlast))"
    bulk_start = transport.find(bulk_marker)
    crypt_call = transport.find("session->remote.crypt->crypt(", bulk_start)
    memcpy_call = transport.find("memcpy(dest, source, (size_t)len);", bulk_start)
    copy_call_end = transport.find("return LIBSSH2_ERROR_NONE;", memcpy_call)
    helper = "_libssh2_ctr_bulk_crypt_outofplace"

    checks = [
        check(all((root / marker).is_file() for marker in markers),
              "R64 AES-CTR, R65-A diagnostics, and R65-B HMAC context markers exist"),
        check(not any((root / marker).exists() for marker in experimental_markers),
              "R65-C/D/E experimental patch markers are absent"),
        check(bulk_start >= 0 and crypt_call > bulk_start and
              memcpy_call > crypt_call and copy_call_end > memcpy_call,
              "bulk AES-CTR RX decrypts in-place through crypt callback, then copies plaintext"),
        check("memcpy(dest, source, (size_t)len);" in transport and
              helper not in crypt and helper not in priv and helper not in openssl and
              "ctr_rx_src_align_mask" not in priv,
              "out-of-place bridge and R65-D alignment telemetry are absent from final libssh2"),
        check("ctr_rx_evp_ns" in priv and "ctr_rx_copy_calls" in priv and
              "ctr_rx_copy_bytes" in priv and "mac_rx_ns" in priv and
              "mac_tx_ns" in priv and "ctr_rx_copy_calls" in diag and
              "mac_sha256_setup_calls" in diag,
              "R65-A diagnostics remain synchronized between libssh2 and the application"),
        check("EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL)" in mac and
              "EVP_MAC_CTX_new(mac)" in mac and
              "EVP_MAC_CTX_dup(state->ctx)" in mac and
              "EVP_MAC_update(ctx, packet, packet_len)" in mac,
              "R65-B per-direction HMAC context reuse remains selected"),
        check("PKG_RELEASE:=68" in makefile,
              "OpenWrt package release is exactly r68"),
        check("experiment/r68-queue-accounting" in workflow and
              "passwall-ssh-core-openwrt-24.10.7-mipsel-r68-queue-accounting-ipk" in workflow and
              "passwall-ssh-core_1.0.0-r68_mipsel_24kc.ipk" in workflow and
              "Version: 1.0.0-r68" in workflow and
              "opkg installed passwall-ssh-core r68-queue-accounting" in workflow,
              "SDK/VM artifact names and embedded IPK metadata target r68"),
        check("apply_libssh2_r65c_outofplace.py" not in workflow and
              "apply_libssh2_r65d_alignment_diag.py" not in workflow and
              "apply_libssh2_r65e_realistic_rx_diag.py" not in workflow,
              "R66 workflow does not apply R65-C/D/E experimental patchers"),
        check("r66_final_profile_source_test.py" in workflow and
              "r66-final-profile-source.log" in workflow,
              "R66 source gate runs in SDK and is retained in the SDK artifact"),
    ]
    if not all(checks):
        return 1
    print("PASS: R66 final profile keeps R64 in-place CTR RX + copy and R65-B HMAC reuse")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
