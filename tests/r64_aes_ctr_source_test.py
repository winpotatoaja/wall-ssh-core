#!/usr/bin/env python3
"""R64 source checks for transport backports and OpenSSL EVP AES-128-CTR batching."""
from pathlib import Path
import sys


def check(ok: bool, label: str) -> bool:
    print(("PASS: " if ok else "FAIL: ") + label)
    return ok


def extract(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = source.find("{", start)
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if c == "\n":
                line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "/" and n == "/":
            line_comment = True
            i += 2
            continue
        elif c == "/" and n == "*":
            block_comment = True
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r64_aes_ctr_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
              file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    project = Path(sys.argv[2])
    transport = (root / "src/transport.c").read_text()
    openssl = (root / "src/openssl.c").read_text()
    openssl_h = (root / "src/openssl.h").read_text()
    crypt = (root / "src/crypt.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()
    core = (project / "ssh-core.c").read_text()
    diag = (project / "libssh2_diag.h").read_text()
    patcher = (project / "tools/apply_libssh2_r64.py").read_text()

    decrypt = extract(
        transport,
        "static int\ndecrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,",
    )
    fullpacket = extract(
        transport,
        "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted",
    )
    read_impl = extract(
        transport,
        "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)",
    )
    send_impl = extract(
        transport,
        "int _libssh2_transport_send(LIBSSH2_SESSION *session,",
    )
    evp_crypt = extract(
        openssl,
        "int\n_libssh2_cipher_crypt(_libssh2_cipher_ctx * ctx,",
    )
    bulk_start = evp_crypt.find("#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)")
    bulk_end = evp_crypt.find("#endif /* LIBSSH2_CRYPT_HAS_CTR_BULK */", bulk_start)
    bulk_branch = (evp_crypt[bulk_start:bulk_end]
                   if bulk_start >= 0 and bulk_end > bulk_start else "")

    checks = [
        check((root / ".passwall-r62-runtime-ab-controls-patched").is_file() and
              (root / ".passwall-r63-crypto-transport-hardening-patched").is_file() and
              (root / ".passwall-r64-portable-aes-ctr-patched").is_file(),
              "R62/R63 prerequisites and R64 patch marker exist"),
        check("LIBSSH2_CRYPT_FLAG_CTR_BULK" in priv and
              "LIBSSH2_CRYPT_HAS_CTR_BULK" in openssl_h and
              "LIBSSH2_CRYPT_FLAG_CTR_BULK" in crypt and
              "_libssh2_cipher_aes128ctr" in crypt,
              "bulk capability is restricted to OpenSSL 3 AES-128-CTR method"),
        check("EVP_CIPHER_CTX_mode(evp_ctx) == EVP_CIPH_CTR_MODE" in bulk_branch and
              "EVP_CIPHER_CTX_nid(evp_ctx) == NID_aes_128_ctr" in bulk_branch and
              "EVP_CipherUpdate(evp_ctx, block, &outl, block" in bulk_branch and
              "ret == 1 && outl == (int)blocksize" in bulk_branch,
              "EVP bulk callback checks context mode/NID, exact success and output length"),
        check("EVP_CipherFinal" not in bulk_branch and
              "EVP_Cipher(" not in bulk_branch and
              "EVP_CipherUpdate" in bulk_branch,
              "AES-128-CTR bulk branch uses Update only, without packet-boundary Final"),
        check("blocksize % 16U" in bulk_branch and
              "blocksize > (size_t)INT_MAX" in bulk_branch and
              "if(!*h)" in openssl,
              "EVP callback has SSH alignment, INT_MAX and allocation guards"),
        check(decrypt.count("CRYPT_FLAG_R(session, PKTLEN_AAD)") == 2 and
              "CRYPT_FLAG_L(session, PKTLEN_AAD)" not in decrypt and
              "CRYPT_FLAG_R(session, CTR_BULK)" in decrypt and
              "memcpy(dest, source, (size_t)len)" in decrypt,
              "RX uses remote flags and one aligned in-place EVP update with one destination copy"),
        check("ctr_rx_first_block_calls++" in decrypt and
              "ctr_rx_bulk_calls++" in decrypt and
              "ctr_rx_block_calls++" in decrypt and
              "ctr_rx_block_bytes" in decrypt,
              "RX first-block, bulk and fallback per-block metrics are distinct"),
        check("CRYPT_FLAG_L(session, CTR_BULK)" in send_impl and
              "packet_length - etm_crypt_offset" in send_impl and
              "crypt_len % (size_t)blocksize" in send_impl and
              "ctr_tx_bulk_calls++" in send_impl,
              "TX batches only the encrypted region and preserves ETM offset/MAC placement"),
        check("p->total_num < mac_len + 4U + (size_t)blocksize" in fullpacket and
              "LIBSSH2_FREE(session, decrypt_buffer)" in fullpacket and
              "p->payload = NULL" in fullpacket,
              "ETM short-packet guard and error-path buffer cleanup are present"),
        check("p->padding_length = 0" in read_impl and
              "p->packet_length > LIBSSH2_PACKET_MAXPAYLOAD" in read_impl and
              "p->padding_length > p->packet_length - 1U" in fullpacket,
              "ETM padding reset and packet-length min/max checks are present"),
        check("session->fullpacket_payload_len < 1U" in fullpacket and
              "packAdd_state == libssh2_NB_state_idle" in fullpacket and
              "if(session->packet.payload)" in session,
              "empty payload, EAGAIN ownership transfer and session teardown are hardened"),
        check("ctr_rx_bulk_calls" in priv and "ctr_tx_bulk_calls" in priv and
              "ctr_rx_bulk_calls" in diag and "ctr_tx_bulk_calls" in diag and
              "timing->ctr_rx_bulk_calls" in session and
              "timing->ctr_tx_bulk_calls" in session,
              "private/public diagnostic snapshot layouts and reset/snapshot wiring are synchronized"),
        check("[SSH-METHODS] cs_crypt=%s cs_mac=%s sc_crypt=%s sc_mac=%s" in core and
              'SSH Cipher: %s | MAC: %s' in core,
              "both negotiated directions are logged while legacy cipher line is preserved"),
        check('getenv("SSH_CIPHER_PROFILE")' in core and
              'ssh_cipher_pref = "aes128-ctr"' in core and
              '"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr"' in core,
              "AES profile is opt-in and the production default cipher preference is unchanged"),
        check("LIBSSH2_ERROR_ENCRYPT" in core and
              "int fatal = (err == LIBSSH2_ERROR_DECRYPT" in core,
              "failed SSH encryption is classified as a terminal upstream-session error"),
        check('log_raw("[PERF-CTR] span_ms=%lld "' in core and
              "ctr_rx_bulk_bytes=%llu" in core and "ctr_tx_bulk_bytes=%llu" in core,
              "AES-CTR performance counters use their own short PERF record"),
        check("AF_ALG" not in patcher and "eip93" not in patcher.lower() and
              "EVP_CipherUpdate" in patcher,
              "R64 uses portable EVP only; no AF_ALG or EIP93 backend"),
    ]

    if not all(checks):
        return 1
    print("PASS: R64 source-level AES-CTR bulk and transport hardening checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
