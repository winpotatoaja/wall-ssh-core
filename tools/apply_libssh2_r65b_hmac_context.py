#!/usr/bin/env python3
"""R65-B: persistent per-direction OpenSSL 3 HMAC-SHA256 contexts."""
from pathlib import Path
import re
import sys

MARKER = ".passwall-r65b-hmac-context-reuse-patched"


def once(src, old, new, label):
    n = src.count(old)
    if n != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {n}")
    return src.replace(old, new, 1)


def bounds(src, signature):
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
                block_comment = False
                i += 2
                continue
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
            if depth == 0: return start, i + 1
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def replace_function(src, signature, replacement):
    a, b = bounds(src, signature)
    return src[:a] + replacement + src[b:]


def patch_diag(root, project):
    pf = (
        "        unsigned long long mac_sha256_fetch_calls;\n"
        "        unsigned long long mac_sha256_ctx_allocs;\n"
        "        unsigned long long mac_sha256_key_inits;\n"
        "        unsigned long long mac_sha256_reuse_resets;\n"
        "        unsigned long long mac_sha256_ctx_dups;\n"
    )
    sf = (
        "    unsigned long long mac_sha256_fetch_calls;\n"
        "    unsigned long long mac_sha256_ctx_allocs;\n"
        "    unsigned long long mac_sha256_key_inits;\n"
        "    unsigned long long mac_sha256_reuse_resets;\n"
        "    unsigned long long mac_sha256_ctx_dups;\n"
    )
    p = root / "src/libssh2_priv.h"
    s = p.read_text()
    s = once(s, "        unsigned long long mac_sha256_setup_calls;\n        unsigned long long decrypt_path_ns;",
             "        unsigned long long mac_sha256_setup_calls;\n" + pf +
             "        unsigned long long decrypt_path_ns;", "private diag fields")
    s = once(s, "    unsigned long long mac_sha256_setup_calls;\n} LIBSSH2_DIAG_TIMING;",
             "    unsigned long long mac_sha256_setup_calls;\n" + sf +
             "} LIBSSH2_DIAG_TIMING;", "private snapshot fields")
    p.write_text(s)

    p = project / "libssh2_diag.h"
    s = p.read_text()
    s = once(s, "    unsigned long long mac_sha256_setup_calls;\n} LIBSSH2_DIAG_TIMING;",
             "    unsigned long long mac_sha256_setup_calls;\n" + sf +
             "} LIBSSH2_DIAG_TIMING;", "public snapshot fields")
    p.write_text(s)

    p = root / "src/session.c"
    s = p.read_text()
    s = once(s,
        "    timing->mac_sha256_setup_calls =\n"
        "        session->passwall_diag.mac_sha256_setup_calls;\n\n"
        "    if(reset) {",
        "    timing->mac_sha256_setup_calls =\n"
        "        session->passwall_diag.mac_sha256_setup_calls;\n"
        "    timing->mac_sha256_fetch_calls = session->passwall_diag.mac_sha256_fetch_calls;\n"
        "    timing->mac_sha256_ctx_allocs = session->passwall_diag.mac_sha256_ctx_allocs;\n"
        "    timing->mac_sha256_key_inits = session->passwall_diag.mac_sha256_key_inits;\n"
        "    timing->mac_sha256_reuse_resets = session->passwall_diag.mac_sha256_reuse_resets;\n"
        "    timing->mac_sha256_ctx_dups = session->passwall_diag.mac_sha256_ctx_dups;\n\n"
        "    if(reset) {", "snapshot metrics")
    s = once(s,
        "        session->passwall_diag.mac_sha256_setup_calls = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "        session->passwall_diag.mac_sha256_setup_calls = 0;\n"
        "        session->passwall_diag.mac_sha256_fetch_calls = 0;\n"
        "        session->passwall_diag.mac_sha256_ctx_allocs = 0;\n"
        "        session->passwall_diag.mac_sha256_key_inits = 0;\n"
        "        session->passwall_diag.mac_sha256_reuse_resets = 0;\n"
        "        session->passwall_diag.mac_sha256_ctx_dups = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "reset metrics")
    p.write_text(s)


def patch_mac(root):
    p = root / "src/mac.c"
    s = p.read_text()
    anchor = "#if LIBSSH2_HMAC_SHA256\n/* mac_method_hmac_sha256_hash"
    add = r'''#if defined(LIBSSH2_OPENSSL) && defined(USE_OPENSSL_3)
typedef struct {
    EVP_MAC_CTX *ctx;
} LIBSSH2_HMAC_SHA256_STATE;

/* One private, pre-keyed context per MAC direction and KEX key epoch. */
static int
mac_method_hmac_sha2_256_init(LIBSSH2_SESSION *session, unsigned char *key,
                              int *free_key, void **abstract)
{
    LIBSSH2_HMAC_SHA256_STATE *state = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PARAM params[3];

    *abstract = NULL;
    *free_key = 0;
    state = LIBSSH2_ALLOC(session, sizeof(*state));
    if(!state)
        return 1;
    memset(state, 0, sizeof(*state));

    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_fetch_calls++;
    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if(!mac)
        goto fail;
    state->ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    mac = NULL;
    if(!state->ctx)
        goto fail;
    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_ctx_allocs++;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, 32);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)OSSL_DIGEST_NAME_SHA2_256, 0);
    params[2] = OSSL_PARAM_construct_end();
    if(EVP_MAC_init(state->ctx, NULL, 0, params) != 1)
        goto fail;
    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_key_inits++;

    *abstract = state;
    *free_key = 1; /* the provider context now owns its key copy */
    return 0;

fail:
    if(mac)
        EVP_MAC_free(mac);
    if(state) {
        EVP_MAC_CTX_free(state->ctx);
        LIBSSH2_FREE(session, state);
    }
    *abstract = NULL;
    *free_key = 0; /* KEX still owns and must wipe/free key */
    return 1;
}

static int
mac_method_hmac_sha2_256_dtor(LIBSSH2_SESSION *session, void **abstract)
{
    LIBSSH2_HMAC_SHA256_STATE *state;
    if(!abstract || !*abstract)
        return 0;
    state = (LIBSSH2_HMAC_SHA256_STATE *)*abstract;
    *abstract = NULL;
    EVP_MAC_CTX_free(state->ctx);
    LIBSSH2_FREE(session, state);
    return 0;
}
#endif /* OpenSSL 3 HMAC-SHA256 context reuse */


'''
    s = once(s, anchor, add + anchor, "HMAC SHA-256 state/init/dtor")

    hash_fn = r'''static int
mac_method_hmac_sha2_256_hash(LIBSSH2_SESSION * session,
                              unsigned char *buf, uint32_t seqno,
                              const unsigned char *packet,
                              size_t packet_len,
                              const unsigned char *addtl,
                              size_t addtl_len, void **abstract)
{
#if defined(LIBSSH2_OPENSSL) && defined(USE_OPENSSL_3)
    LIBSSH2_HMAC_SHA256_STATE *state = (LIBSSH2_HMAC_SHA256_STATE *)*abstract;
    EVP_MAC_CTX *ctx;
    int owns_ctx = 0;
    unsigned char seqno_buf[4];
    size_t out_len = 0;
    int ok;

    if(!state || !state->ctx)
        return 1;
#if OPENSSL_VERSION_NUMBER >= 0x30000030L
    /* OpenSSL 3.0.3+: reset finalised digest state while retaining HMAC key state. */
    ctx = state->ctx;
    ok = EVP_MAC_init(ctx, NULL, 0, NULL);
    if(ok != 1)
        return 1;
    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_reuse_resets++;
#else
    /* OpenSSL 3.0.0-3.0.2: duplicate the untouched, pre-keyed template. */
    ctx = EVP_MAC_CTX_dup(state->ctx);
    if(!ctx)
        return 1;
    owns_ctx = 1;
    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_ctx_dups++;
#endif
    _libssh2_htonu32(seqno_buf, seqno);
    ok = EVP_MAC_update(ctx, seqno_buf, sizeof(seqno_buf));
    if(ok == 1)
        ok = EVP_MAC_update(ctx, packet, packet_len);
    if(ok == 1 && addtl && addtl_len)
        ok = EVP_MAC_update(ctx, addtl, addtl_len);
    if(ok == 1)
        ok = EVP_MAC_final(ctx, buf, &out_len, 32);
    if(owns_ctx)
        EVP_MAC_CTX_free(ctx);
    return (ok == 1 && out_len == 32) ? 0 : 1;
#else
    libssh2_hmac_ctx ctx;
    unsigned char seqno_buf[4];
    int res;
    _libssh2_htonu32(seqno_buf, seqno);
    if(!_libssh2_hmac_ctx_init(&ctx))
        return 1;
    if(session->passwall_diag.enabled)
        session->passwall_diag.mac_sha256_setup_calls++;
    res = _libssh2_hmac_sha256_init(&ctx, *abstract, 32) &&
          _libssh2_hmac_update(&ctx, seqno_buf, 4) &&
          _libssh2_hmac_update(&ctx, packet, packet_len);
    if(res && addtl && addtl_len)
        res = _libssh2_hmac_update(&ctx, addtl, addtl_len);
    if(res)
        res = _libssh2_hmac_final(&ctx, buf);
    _libssh2_hmac_cleanup(&ctx);
    return !res;
#endif
}


'''
    s = replace_function(s, "static int\nmac_method_hmac_sha2_256_hash(", hash_fn.rstrip())
    old = ("    mac_method_common_init,\n"
           "    mac_method_hmac_sha2_256_hash,\n"
           "    mac_method_common_dtor,\n")
    new = ("#if defined(LIBSSH2_OPENSSL) && defined(USE_OPENSSL_3)\n"
           "    mac_method_hmac_sha2_256_init,\n"
           "#else\n"
           "    mac_method_common_init,\n"
           "#endif\n"
           "    mac_method_hmac_sha2_256_hash,\n"
           "#if defined(LIBSSH2_OPENSSL) && defined(USE_OPENSSL_3)\n"
           "    mac_method_hmac_sha2_256_dtor,\n"
           "#else\n"
           "    mac_method_common_dtor,\n"
           "#endif\n")
    if s.count(old) != 2:
        raise RuntimeError("expected exactly two standard/ETM SHA-256 method tables")
    s = s.replace(old, new)
    p.write_text(s)


def patch_kex(root):
    p = root / "src/kex.c"
    s = p.read_text()
    for direction in ("local", "remote"):
        pat = re.compile(
            r"(?P<indent>^[ \t]*)session->" + direction +
            r"\.mac->init\(session, key, &free_key,\n[ \t]*&session->" +
            direction + r"\.mac_abstract\);\n[ \t]*\n"
            r"(?P<ifindent>[ \t]*)if\(free_key\) \{", re.MULTILINE)
        n = [0]

        def repl(m):
            n[0] += 1
            ind, ifind = m.group("indent"), m.group("ifindent")
            return (
                f"{ind}if(session->{direction}.mac->init(session, key, &free_key,\n"
                f"{ind}                                      &session->{direction}.mac_abstract)) {{\n"
                f"{ind}    /* Failed init leaves the derived key owned by KEX. */\n"
                f"{ind}    _libssh2_explicit_zero(key, session->{direction}.mac->key_len);\n"
                f"{ind}    LIBSSH2_FREE(session, key);\n"
                f"{ind}    ret = LIBSSH2_ERROR_KEX_FAILURE;\n"
                f"{ind}    goto clean_exit;\n"
                f"{ind}}}\n"
                f"{ifind}if(free_key) {{")
        s = pat.sub(repl, s)
        if n[0] != 3:
            raise RuntimeError(f"{direction} MAC init paths: expected 3, found {n[0]}")
    p.write_text(s)


def patch_rx(root):
    p = root / "src/transport.c"
    s = p.read_text()
    sig = "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted"
    start, end = bounds(s, sig)
    fn = s[start:end]

    pairs = [
        (
            "                remote_mac->hash(session, macbuf,\n"
            "                                 session->remote.seqno,\n"
            "                                 p->payload, p->total_num - mac_len,\n"
            "                                 NULL, 0,\n"
            "                                 &session->remote.mac_abstract);\n",
            "                mac_rc = remote_mac->hash(session, macbuf,\n"
            "                                           session->remote.seqno,\n"
            "                                           p->payload, p->total_num - mac_len,\n"
            "                                           NULL, 0,\n"
            "                                           &session->remote.mac_abstract);\n"
            "                if(mac_rc)\n"
            "                    return LIBSSH2_ERROR_MAC_FAILURE;\n",
            "ETM receive MAC check"
        ),
        (
            "                remote_mac->hash(session, macbuf,\n"
            "                                 session->remote.seqno,\n"
            "                                 p->init, 5,\n"
            "                                 p->payload,\n"
            "                                 session->fullpacket_payload_len,\n"
            "                                 &session->remote.mac_abstract);\n",
            "                mac_rc = remote_mac->hash(session, macbuf,\n"
            "                                           session->remote.seqno,\n"
            "                                           p->init, 5,\n"
            "                                           p->payload,\n"
            "                                           session->fullpacket_payload_len,\n"
            "                                           &session->remote.mac_abstract);\n"
            "                if(mac_rc)\n"
            "                    return LIBSSH2_ERROR_MAC_FAILURE;\n",
            "non-ETM receive MAC check"
        )
    ]
    for old, new, label in pairs:
        fn = once(fn, old, new, label)

    fn = once(fn,
        "                unsigned long long mac_end_ns;\n"
        "                /* store hash here */",
        "                unsigned long long mac_end_ns;\n"
        "                int mac_rc;\n"
        "                /* store hash here */", "declare ETM mac_rc")
    fn = once(fn,
        "                unsigned long long mac_end_ns;\n"
        "                /* store hash here */",
        "                unsigned long long mac_end_ns;\n"
        "                int mac_rc;\n"
        "                /* store hash here */", "declare non-ETM mac_rc")
    p.write_text(s[:start] + fn + s[end:])


def patch_perf(project):
    p = project / "ssh-core.c"
    s = p.read_text()
    old = (
        '            "mac_sha256_setup_calls=%llu",\n'
        "            span_ms,\n"
        "            libssh2_diag.mac_rx_calls,\n"
        "            libssh2_diag.mac_rx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_rx_ns / 1000U),\n"
        "            libssh2_diag.mac_tx_calls,\n"
        "            libssh2_diag.mac_tx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_tx_ns / 1000U),\n"
        "            libssh2_diag.mac_sha256_setup_calls);"
    )
    new = (
        '            "mac_sha256_setup_calls=%llu mac_sha256_fetch_calls=%llu "\n'
        '            "mac_sha256_ctx_allocs=%llu mac_sha256_key_inits=%llu "\n'
        '            "mac_sha256_reuse_resets=%llu mac_sha256_ctx_dups=%llu",\n'
        "            span_ms,\n"
        "            libssh2_diag.mac_rx_calls,\n"
        "            libssh2_diag.mac_rx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_rx_ns / 1000U),\n"
        "            libssh2_diag.mac_tx_calls,\n"
        "            libssh2_diag.mac_tx_bytes,\n"
        "            (unsigned long long)(libssh2_diag.mac_tx_ns / 1000U),\n"
        "            libssh2_diag.mac_sha256_setup_calls,\n"
        "            libssh2_diag.mac_sha256_fetch_calls,\n"
        "            libssh2_diag.mac_sha256_ctx_allocs,\n"
        "            libssh2_diag.mac_sha256_key_inits,\n"
        "            libssh2_diag.mac_sha256_reuse_resets,\n"
        "            libssh2_diag.mac_sha256_ctx_dups);"
    )
    p.write_text(once(s, old, new, "extend PERF-MAC context lifecycle metrics"))


def patch(root, project):
    if not (root / ".passwall-r65a-crypto-diagnostics-patched").is_file():
        raise RuntimeError("R65-B requires the R65-A diagnostics patch")
    if not (root / ".passwall-r64-portable-aes-ctr-patched").is_file():
        raise RuntimeError("R65-B requires the R64 transport patch")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("R65-B is pinned to libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R65-B marker already exists")
    patch_diag(root, project)
    patch_mac(root)
    patch_kex(root)
    patch_rx(root)
    patch_perf(project)
    (root / MARKER).write_text(
        "R65-B: per-direction OpenSSL 3 HMAC-SHA256 reuse and fail-closed KEX/RX MAC errors\n"
    )
    print("PASS: R65-B per-direction HMAC reuse, compatibility fallback and MAC/KEX fail-closed checks added")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply_libssh2_r65b_hmac_context.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
