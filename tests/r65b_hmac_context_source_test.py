#!/usr/bin/env python3
"""R65-B source checks for OpenSSL 3 HMAC context reuse and fail-closed errors."""
from pathlib import Path
import sys


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return ok


def extract(src, signature):
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = src.find("{", start)
    depth, quote, line_comment, block_comment = 0, None, False, False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n": line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False; i += 2; continue
        elif quote:
            if c == "\\": i += 2; continue
            if c == quote: quote = None
        elif c == "/" and n == "/":
            line_comment = True; i += 2; continue
        elif c == "/" and n == "*":
            block_comment = True; i += 2; continue
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0: return src[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def main():
    if len(sys.argv) != 3:
        print("usage: r65b_hmac_context_source_test.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
              file=sys.stderr)
        return 2
    root, project = Path(sys.argv[1]), Path(sys.argv[2])
    mac = (root / "src/mac.c").read_text()
    kex = (root / "src/kex.c").read_text()
    transport = (root / "src/transport.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()
    diag = (project / "libssh2_diag.h").read_text()
    core = (project / "ssh-core.c").read_text()

    fullpacket = extract(transport,
        "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted")
    hmac_hash = extract(mac, "static int\nmac_method_hmac_sha2_256_hash(")
    init = extract(mac, "static int\nmac_method_hmac_sha2_256_init(")
    dtor = extract(mac, "static int\nmac_method_hmac_sha2_256_dtor(")
    names = ("mac_sha256_fetch_calls", "mac_sha256_ctx_allocs",
             "mac_sha256_key_inits", "mac_sha256_reuse_resets",
             "mac_sha256_ctx_dups")
    local_init = kex.count("if(session->local.mac->init(session, key, &free_key,")
    remote_init = kex.count("if(session->remote.mac->init(session, key, &free_key,")

    checks = [
        check((root / ".passwall-r65a-crypto-diagnostics-patched").is_file() and
              (root / ".passwall-r65b-hmac-context-reuse-patched").is_file(),
              "R65-A prerequisite and R65-B marker exist"),
        check("EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL)" in init and
              "EVP_MAC_CTX_new(mac)" in init and
              "EVP_MAC_init(state->ctx, NULL, 0, params)" in init and
              "*free_key = 1" in init,
              "one provider-owned context captures the HMAC key per direction/key epoch"),
        check("*abstract = NULL" in init and "*free_key = 0" in init and
              "EVP_MAC_CTX_free(state->ctx)" in init and "goto fail" in init and
              "EVP_MAC_CTX_free(state->ctx)" in dtor,
              "failed setup cleans partial state; dtor frees the owned provider context"),
        check("EVP_MAC_init(ctx, NULL, 0, NULL)" in hmac_hash and
              "OPENSSL_VERSION_NUMBER >= 0x30000030L" in hmac_hash and
              "EVP_MAC_CTX_dup(state->ctx)" in hmac_hash,
              "3.0.3+ uses key-preserving reset; 3.0.0-3.0.2 duplicates an immutable template"),
        check("EVP_MAC_update(ctx, seqno_buf, sizeof(seqno_buf))" in hmac_hash and
              "EVP_MAC_update(ctx, packet, packet_len)" in hmac_hash and
              "EVP_MAC_update(ctx, addtl, addtl_len)" in hmac_hash and
              "EVP_MAC_final(ctx, buf, &out_len, 32)" in hmac_hash and
              "out_len == 32" in hmac_hash,
              "HMAC input order and exact 32-byte output are preserved"),
        check(mac.count("mac_method_hmac_sha2_256_init,") == 2 and
              mac.count("mac_method_hmac_sha2_256_dtor,") == 2,
              "standard and ETM SHA-256 MAC methods both use context init/dtor"),
        check(local_init == 3 and remote_init == 3 and
              kex.count("_libssh2_explicit_zero(key, session->local.mac->key_len)") >= 3 and
              kex.count("_libssh2_explicit_zero(key, session->remote.mac->key_len)") >= 3,
              "all six KEX MAC init paths check errors and wipe/free the derived key"),
        check(fullpacket.count("int mac_rc;") == 2 and
              fullpacket.count("if(mac_rc)") == 2 and
              fullpacket.count("return LIBSSH2_ERROR_MAC_FAILURE;") >= 2 and
              fullpacket.index("if(mac_rc)") < fullpacket.index("memcmp(macbuf"),
              "both RX MAC callback failures abort before compare/decrypt"),
        check(all(n in priv and n in diag for n in names) and
              all(f"timing->{n}" in session for n in names) and
              all(f"session->passwall_diag.{n} = 0" in session for n in names),
              "context lifecycle diagnostics are snapshotted and reset"),
        check(all(f"{n}=%llu" in core for n in names) and
              'log_raw("[PERF-MAC]' in core,
              "PERF-MAC emits lifecycle counters"),
        check("static EVP_MAC_CTX" not in mac and
              "static LIBSSH2_HMAC_SHA256_STATE" not in mac,
              "no global or cross-session HMAC context is introduced"),
    ]
    if not all(checks):
        return 1
    print("PASS: R65-B HMAC reuse and fail-closed source checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
