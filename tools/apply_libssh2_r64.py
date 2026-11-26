#!/usr/bin/env python3
"""R64: libssh2 1.11.1 transport hardening and OpenSSL EVP AES-128-CTR bulk path."""
from pathlib import Path
import sys

MARKER = ".passwall-r64-portable-aes-ctr-patched"


def once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one exact anchor, found {count}")
    return source.replace(old, new, 1)


def function_bounds(source: str, signature: str):
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one function {signature!r}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"missing function body for {signature!r}")
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
                return start, i + 1
        i += 1
    raise RuntimeError(f"unterminated function {signature!r}")


def replace_function(source: str, signature: str, transform, label: str) -> str:
    start, end = function_bounds(source, signature)
    fn = source[start:end]
    updated = transform(fn)
    if updated == fn:
        raise RuntimeError(f"{label}: function was not changed")
    return source[:start] + updated + source[end:]


def patch_transport_security(root: Path) -> None:
    transport = root / "src/transport.c"
    source = transport.read_text()

    def patch_decrypt(fn: str) -> str:
        fn = once(
            fn,
            "    int blocksize = session->remote.crypt->blocksize;\n\n"
            "    /* if we get called with a len that isn't an even number of blocksizes\n",
            "    int blocksize = session->remote.crypt->blocksize;\n\n"
            "    if(blocksize <= 0 || len < 0) {\n"
            "        if(p->payload) {\n"
            "            LIBSSH2_FREE(session, p->payload);\n"
            "            p->payload = NULL;\n"
            "        }\n"
            "        return LIBSSH2_ERROR_DECRYPT;\n"
            "    }\n"
            "    if(len == 0)\n"
            "        return LIBSSH2_ERROR_NONE;\n\n"
            "    /* R64: AES-128-CTR keeps the 16-byte SSH framing invariant but\n"
            "     * processes the complete aligned fragment with one EVP update. */\n"
            "    if(CRYPT_FLAG_R(session, CTR_BULK) && !IS_FIRST(firstlast)) {\n"
            "        if(((size_t)len % (size_t)blocksize) != 0U) {\n"
            "            if(p->payload) {\n"
            "                LIBSSH2_FREE(session, p->payload);\n"
            "                p->payload = NULL;\n"
            "            }\n"
            "            return LIBSSH2_ERROR_DECRYPT;\n"
            "        }\n"
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
            "        memcpy(dest, source, (size_t)len);\n"
            "        return LIBSSH2_ERROR_NONE;\n"
            "    }\n\n"
            "    /* if we get called with a len that isn't an even number of blocksizes\n",
            "insert receive AES-CTR bulk path and runtime guards"
        )
        count = fn.count("CRYPT_FLAG_L(session, PKTLEN_AAD)")
        if count != 2:
            raise RuntimeError(f"receive AAD direction fix: expected 2 local flags, found {count}")
        fn = fn.replace("CRYPT_FLAG_L(session, PKTLEN_AAD)",
                        "CRYPT_FLAG_R(session, PKTLEN_AAD)")
        fn = once(
            fn,
            "        if(session->remote.crypt->crypt(session, 0, source, decryptlen,\n"
            "                                        &session->remote.crypt_abstract,\n"
            "                                        lowerfirstlast)) {\n"
            "            LIBSSH2_FREE(session, p->payload);\n"
            "            return LIBSSH2_ERROR_DECRYPT;\n"
            "        }\n",
            "        if(session->remote.crypt->crypt(session, 0, source, decryptlen,\n"
            "                                        &session->remote.crypt_abstract,\n"
            "                                        lowerfirstlast)) {\n"
            "            if(p->payload) {\n"
            "                LIBSSH2_FREE(session, p->payload);\n"
            "                p->payload = NULL;\n"
            "            }\n"
            "            return LIBSSH2_ERROR_DECRYPT;\n"
            "        }\n"
            "        if(CRYPT_FLAG_R(session, CTR_BULK) && session->passwall_diag.enabled) {\n"
            "            if(IS_FIRST(firstlast))\n"
            "                session->passwall_diag.ctr_rx_first_block_calls++;\n"
            "            else {\n"
            "                session->passwall_diag.ctr_rx_block_calls++;\n"
            "                session->passwall_diag.ctr_rx_block_bytes +=\n"
            "                    (unsigned long long)decryptlen;\n"
            "            }\n"
            "        }\n",
            "make RX decrypt failure ownership-safe and count first block"
        )
        return fn

    source = replace_function(
        source,
        "static int\ndecrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,",
        patch_decrypt,
        "patch decrypt_impl",
    )

    def patch_fullpacket(fn: str) -> str:
        fn = once(
            fn,
            "    uint32_t seq = session->remote.seqno;\n\n",
            "    uint32_t seq = session->remote.seqno;\n\n"
            "    /* R64: keep error-path MAC scratch deterministic. */\n"
            "    memset(macbuf, 0, sizeof(macbuf));\n\n",
            "initialize transport MAC scratch"
        )
        fn = once(
            fn,
            "                int blocksize = session->remote.crypt->blocksize;\n\n"
            "                rc = decrypt(session, p->payload + 4,\n",
            "                int blocksize = session->remote.crypt->blocksize;\n\n"
            "                /* R64 backport: reject undersized ETM packets before\n"
            "                 * subtracting the header/MAC or allocating a buffer. */\n"
            "                if(blocksize <= 0 ||\n"
            "                   p->total_num < mac_len + 4U + (size_t)blocksize) {\n"
            "                    if(p->payload) {\n"
            "                        LIBSSH2_FREE(session, p->payload);\n"
            "                        p->payload = NULL;\n"
            "                    }\n"
            "                    return LIBSSH2_ERROR_DECRYPT;\n"
            "                }\n"
            "                decrypt_size = (ssize_t)(p->total_num - mac_len - 4U);\n\n"
            "                rc = decrypt(session, p->payload + 4,\n",
            "backport ETM minimum decrypt buffer bound"
        )
        fn = once(
            fn,
            "                /* we need buffer for decrypt */\n"
            "                decrypt_size = p->total_num - mac_len - 4;\n"
            "                decrypt_buffer = LIBSSH2_ALLOC(session, decrypt_size);\n"
            "                if(!decrypt_buffer) {\n"
            "                    return LIBSSH2_ERROR_ALLOC;\n"
            "                }\n",
            "                /* we need buffer for decrypt */\n"
            "                decrypt_buffer = LIBSSH2_ALLOC(session, (size_t)decrypt_size);\n"
            "                if(!decrypt_buffer) {\n"
            "                    if(p->payload) {\n"
            "                        LIBSSH2_FREE(session, p->payload);\n"
            "                        p->payload = NULL;\n"
            "                    }\n"
            "                    return LIBSSH2_ERROR_ALLOC;\n"
            "                }\n",
            "clean up payload on ETM allocation failure"
        )
        fn = once(
            fn,
            "                p->padding_length = first_block[0];\n"
            "                if(blocksize > 1) {\n",
            "                p->padding_length = first_block[0];\n"
            "                if(p->padding_length > p->packet_length - 1U) {\n"
            "                    LIBSSH2_FREE(session, decrypt_buffer);\n"
            "                    if(p->payload) {\n"
            "                        LIBSSH2_FREE(session, p->payload);\n"
            "                        p->payload = NULL;\n"
            "                    }\n"
            "                    return LIBSSH2_ERROR_PROTO;\n"
            "                }\n"
            "                if(blocksize > 1) {\n",
            "validate ETM padding and clean both buffers"
        )
        fn = once(
            fn,
            "            unsigned char *data;\n"
            "            size_t data_len;\n",
            "            unsigned char *data = NULL;\n"
            "            size_t data_len = 0;\n",
            "initialize decompression outputs"
        )
        fn = once(
            fn,
            "            LIBSSH2_FREE(session, p->payload);\n"
            "            if(rc)\n"
            "                return rc;\n"
            "\n"
            "            p->payload = data;\n",
            "            LIBSSH2_FREE(session, p->payload);\n"
            "            p->payload = NULL;\n"
            "            if(rc)\n"
            "                return rc;\n"
            "\n"
            "            p->payload = data;\n",
            "clear decompression input ownership on error"
        )
        fn = once(
            fn,
            "        session->fullpacket_packet_type = p->payload[0];\n",
            "        /* R64 backport: SSH payload must contain its message type. */\n"
            "        if(!p->payload || session->fullpacket_payload_len < 1U) {\n"
            "            if(p->payload) {\n"
            "                LIBSSH2_FREE(session, p->payload);\n"
            "                p->payload = NULL;\n"
            "            }\n"
            "            return LIBSSH2_ERROR_PROTO;\n"
            "        }\n"
            "        session->fullpacket_packet_type = p->payload[0];\n",
            "reject empty SSH packet payload"
        )
        fn = once(
            fn,
            "        rc = _libssh2_packet_add(session, p->payload,\n"
            "                                 session->fullpacket_payload_len,\n"
            "                                 session->fullpacket_macstate, seq);\n"
            "        if(rc == LIBSSH2_ERROR_EAGAIN)\n"
            "            return rc;\n"
            "        if(rc) {\n",
            "        rc = _libssh2_packet_add(session, p->payload,\n"
            "                                 session->fullpacket_payload_len,\n"
            "                                 session->fullpacket_macstate, seq);\n"
            "        if(rc == LIBSSH2_ERROR_EAGAIN) {\n"
            "            /* R64: packet_add may already have queued the payload\n"
            "             * before returning EAGAIN during a follow-up rekey. */\n"
            "            if(session->packAdd_state == libssh2_NB_state_idle)\n"
            "                p->payload = NULL;\n"
            "            return rc;\n"
            "        }\n"
            "        /* packet_add owns the payload on every non-EAGAIN path. */\n"
            "        p->payload = NULL;\n"
            "        if(rc) {\n",
            "backport packet payload ownership transfer"
        )
        return fn

    source = replace_function(
        source, "static int\nfullpacket(LIBSSH2_SESSION * session, int encrypted",
        patch_fullpacket, "patch fullpacket security backports"
    )

    def patch_read(fn: str) -> str:
        fn = once(
            fn,
            "                if(etm) {\n"
            "                    /* we collect entire undecrypted packet including the\n",
            "                if(etm) {\n"
            "                    /* R64 backport: padding is unknown until the full\n"
            "                     * ETM packet has passed its MAC check and decryption. */\n"
            "                    p->padding_length = 0;\n"
            "                    /* we collect entire undecrypted packet including the\n",
            "reset ETM padding state"
        )
        fn = once(
            fn,
            "                    p->packet_length = _libssh2_ntohu32(block);\n"
            "                    total_num = 4 + p->packet_length +\n",
            "                    p->packet_length = _libssh2_ntohu32(block);\n"
            "                    /* R64 backport for the ETM assignment missed by the\n"
            "                     * earlier generic check (GHSA-949f-w9qj-9q6h). */\n"
            "                    if(p->packet_length < 1U)\n"
            "                        return LIBSSH2_ERROR_DECRYPT;\n"
            "                    else if(p->packet_length > LIBSSH2_PACKET_MAXPAYLOAD)\n"
            "                        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;\n"
            "                    total_num = 4 + p->packet_length +\n",
            "validate the ETM packet length after its final assignment"
        )
        fn = once(
            fn,
            "                p->packet_length = _libssh2_ntohu32(block);\n"
            "                if(p->packet_length < 1)\n"
            "                    return LIBSSH2_ERROR_DECRYPT;\n\n"
            "                /* total_num may include size field, however due to existing\n",
            "                p->packet_length = _libssh2_ntohu32(block);\n"
            "                if(p->packet_length < 1U)\n"
            "                    return LIBSSH2_ERROR_DECRYPT;\n"
            "                else if(p->packet_length > LIBSSH2_PACKET_MAXPAYLOAD)\n"
            "                    return LIBSSH2_ERROR_OUT_OF_BOUNDARY;\n\n"
            "                /* total_num may include size field, however due to existing\n",
            "backport packet length upper bound for full-packet ciphers"
        )
        fn = once(
            fn,
            "                    else {\n"
            "                        if(p->payload)\n"
            "                            LIBSSH2_FREE(session, p->payload);\n"
            "                        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;\n"
            "                    }\n",
            "                    else {\n"
            "                        if(p->payload) {\n"
            "                            LIBSSH2_FREE(session, p->payload);\n"
            "                            p->payload = NULL;\n"
            "                        }\n"
            "                        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;\n"
            "                    }\n",
            "clear packet pointer on receive boundary error"
        )
        return fn

    source = replace_function(
        source,
        "static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)",
        patch_read,
        "patch transport read boundary checks"
    )
    transport.write_text(source)

    session_c = root / "src/session.c"
    session = session_c.read_text()
    session = once(
        session,
        "    /* Free payload buffer */\n"
        "    if(session->packet.total_num) {\n"
        "        LIBSSH2_FREE(session, session->packet.payload);\n"
        "    }\n",
        "    /* R64: payload ownership can be transferred while total_num remains set. */\n"
        "    if(session->packet.payload) {\n"
        "        LIBSSH2_FREE(session, session->packet.payload);\n"
        "        session->packet.payload = NULL;\n"
        "    }\n",
        "make session teardown follow payload ownership"
    )
    session_c.write_text(session)


def patch_openssl_backend(root: Path) -> None:
    openssl_h = root / "src/openssl.h"
    source = openssl_h.read_text()
    source = once(
        source,
        "#include <openssl/evp.h>\n"
        "#include <openssl/hmac.h>\n",
        "#include <openssl/evp.h>\n"
        "#include <openssl/hmac.h>\n\n"
        "/* R64 bulk CTR is intentionally restricted to OpenSSL 3 providers. */\n"
        "#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)\n"
        "# define LIBSSH2_CRYPT_HAS_CTR_BULK 1\n"
        "#endif\n",
        "declare OpenSSL 3 CTR bulk capability after version headers"
    )
    openssl_h.write_text(source)

    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    source = once(
        source,
        "#define LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET      4\n",
        "#define LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET      4\n"
        "/* OpenSSL EVP AES-128-CTR accepts an aligned bulk fragment. */\n"
        "#define LIBSSH2_CRYPT_FLAG_CTR_BULK                  8\n",
        "reserve the AES-CTR bulk method flag"
    )
    priv.write_text(source)

    crypt_c = root / "src/crypt.c"
    source = crypt_c.read_text()
    source = once(
        source,
        "    0,                          /* length of the authentication tag */\n"
        "    0,                          /* flags */\n"
        "    &crypt_init,\n"
        "    NULL,\n"
        "    &crypt_encrypt,\n"
        "    &crypt_dtor,\n"
        "    _libssh2_cipher_aes128ctr\n",
        "    0,                          /* length of the authentication tag */\n"
        "#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)\n"
        "    LIBSSH2_CRYPT_FLAG_CTR_BULK, /* flags */\n"
        "#else\n"
        "    0,                          /* flags */\n"
        "#endif\n"
        "    &crypt_init,\n"
        "    NULL,\n"
        "    &crypt_encrypt,\n"
        "    &crypt_dtor,\n"
        "    _libssh2_cipher_aes128ctr\n",
        "enable bulk capability only for AES-128-CTR"
    )
    crypt_c.write_text(source)

    openssl_c = root / "src/openssl.c"
    source = openssl_c.read_text()
    source = once(
        source,
        "#include <stdlib.h>\n"
        "#include <assert.h>\n",
        "#include <stdlib.h>\n"
        "#include <assert.h>\n"
        "#include <limits.h>\n",
        "include integer bounds for EVP update"
    )
    source = once(
        source,
        "    *h = EVP_CIPHER_CTX_new();\n"
        "    rc = !EVP_CipherInit(*h, algo(), secret, iv, encrypt);\n",
        "    *h = EVP_CIPHER_CTX_new();\n"
        "    if(!*h)\n"
        "        return 1;\n"
        "    rc = !EVP_CipherInit(*h, algo(), secret, iv, encrypt);\n",
        "check opaque EVP context allocation"
    )
    source = once(
        source,
        "    int ret = 1;\n"
        "    int rc = 1;\n\n"
        "#if LIBSSH2_AES_GCM\n",
        "    int ret = 1;\n"
        "    int rc = 1;\n\n"
        "#if defined(LIBSSH2_CRYPT_HAS_CTR_BULK)\n"
        "    /*\n"
        "     * R64: libssh2 preserves a 16-byte SSH packet invariant, while\n"
        "     * OpenSSL 3 EVP CTR internally has a one-byte stream block size.\n"
        "     * Therefore each aligned SSH fragment can be updated in-place in\n"
        "     * one call, without Final and without changing the cipher context.\n"
        "     */\n"
        "    {\n"
        "        EVP_CIPHER_CTX *evp_ctx;\n"
        "        int outl = 0;\n"
        "#ifdef HAVE_OPAQUE_STRUCTS\n"
        "        if(!ctx)\n"
        "            return 1;\n"
        "        evp_ctx = *ctx;\n"
        "#else\n"
        "        evp_ctx = ctx;\n"
        "#endif\n"
        "        if(!evp_ctx)\n"
        "            return 1;\n"
        "        if(EVP_CIPHER_CTX_mode(evp_ctx) == EVP_CIPH_CTR_MODE &&\n"
        "           EVP_CIPHER_CTX_nid(evp_ctx) == NID_aes_128_ctr) {\n"
        "            if(blocksize == 0U)\n"
        "                return 0;\n"
        "            if(blocksize > (size_t)INT_MAX || !block ||\n"
        "               (blocksize % 16U) != 0U)\n"
        "                return 1;\n"
        "            ret = EVP_CipherUpdate(evp_ctx, block, &outl, block,\n"
        "                                   (int)blocksize);\n"
        "            return (ret == 1 && outl == (int)blocksize) ? 0 : 1;\n"
        "        }\n"
        "    }\n"
        "#endif /* LIBSSH2_CRYPT_HAS_CTR_BULK */\n\n"
        "#if LIBSSH2_AES_GCM\n",
        "use checked in-place EVP_CipherUpdate for AES-128-CTR"
    )
    openssl_c.write_text(source)


def patch_transport_bulk_and_diag(root: Path, project_root: Path) -> None:
    priv = root / "src/libssh2_priv.h"
    source = priv.read_text()
    source = once(
        source,
        "        unsigned long long chacha20_profile_packets;\n"
        "        unsigned long long decrypt_path_ns;",
        "        unsigned long long chacha20_profile_packets;\n"
        "        unsigned long long ctr_rx_bulk_calls;\n"
        "        unsigned long long ctr_rx_bulk_bytes;\n"
        "        unsigned long long ctr_rx_first_block_calls;\n"
        "        unsigned long long ctr_rx_block_calls;\n"
        "        unsigned long long ctr_rx_block_bytes;\n"
        "        unsigned long long ctr_tx_bulk_calls;\n"
        "        unsigned long long ctr_tx_bulk_bytes;\n"
        "        unsigned long long ctr_tx_block_calls;\n"
        "        unsigned long long ctr_tx_block_bytes;\n"
        "        unsigned long long decrypt_path_ns;",
        "add session-owned AES-CTR performance counters"
    )
    source = once(
        source,
        "    unsigned long long chacha20_profile_packets;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "    unsigned long long chacha20_profile_packets;\n"
        "    unsigned long long ctr_rx_bulk_calls;\n"
        "    unsigned long long ctr_rx_bulk_bytes;\n"
        "    unsigned long long ctr_rx_first_block_calls;\n"
        "    unsigned long long ctr_rx_block_calls;\n"
        "    unsigned long long ctr_rx_block_bytes;\n"
        "    unsigned long long ctr_tx_bulk_calls;\n"
        "    unsigned long long ctr_tx_bulk_bytes;\n"
        "    unsigned long long ctr_tx_block_calls;\n"
        "    unsigned long long ctr_tx_block_bytes;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "extend libssh2 internal snapshot layout"
    )
    priv.write_text(source)

    public_header = project_root / "libssh2_diag.h"
    source = public_header.read_text()
    source = once(
        source,
        "    unsigned long long chacha20_profile_packets;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "    unsigned long long chacha20_profile_packets;\n"
        "    unsigned long long ctr_rx_bulk_calls;\n"
        "    unsigned long long ctr_rx_bulk_bytes;\n"
        "    unsigned long long ctr_rx_first_block_calls;\n"
        "    unsigned long long ctr_rx_block_calls;\n"
        "    unsigned long long ctr_rx_block_bytes;\n"
        "    unsigned long long ctr_tx_bulk_calls;\n"
        "    unsigned long long ctr_tx_bulk_bytes;\n"
        "    unsigned long long ctr_tx_block_calls;\n"
        "    unsigned long long ctr_tx_block_bytes;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "keep application diagnostic snapshot ABI synchronized"
    )
    public_header.write_text(source)

    session_c = root / "src/session.c"
    source = session_c.read_text()
    source = once(
        source,
        "    timing->chacha20_profile_packets =\n"
        "        session->passwall_diag.chacha20_profile_packets;\n\n"
        "    if(reset) {",
        "    timing->chacha20_profile_packets =\n"
        "        session->passwall_diag.chacha20_profile_packets;\n"
        "    timing->ctr_rx_bulk_calls = session->passwall_diag.ctr_rx_bulk_calls;\n"
        "    timing->ctr_rx_bulk_bytes = session->passwall_diag.ctr_rx_bulk_bytes;\n"
        "    timing->ctr_rx_first_block_calls =\n"
        "        session->passwall_diag.ctr_rx_first_block_calls;\n"
        "    timing->ctr_rx_block_calls = session->passwall_diag.ctr_rx_block_calls;\n"
        "    timing->ctr_rx_block_bytes = session->passwall_diag.ctr_rx_block_bytes;\n"
        "    timing->ctr_tx_bulk_calls = session->passwall_diag.ctr_tx_bulk_calls;\n"
        "    timing->ctr_tx_bulk_bytes = session->passwall_diag.ctr_tx_bulk_bytes;\n"
        "    timing->ctr_tx_block_calls = session->passwall_diag.ctr_tx_block_calls;\n"
        "    timing->ctr_tx_block_bytes = session->passwall_diag.ctr_tx_block_bytes;\n\n"
        "    if(reset) {",
        "copy AES-CTR metrics into snapshot"
    )
    source = once(
        source,
        "        session->passwall_diag.chacha20_profile_packets = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "        session->passwall_diag.chacha20_profile_packets = 0;\n"
        "        session->passwall_diag.ctr_rx_bulk_calls = 0;\n"
        "        session->passwall_diag.ctr_rx_bulk_bytes = 0;\n"
        "        session->passwall_diag.ctr_rx_first_block_calls = 0;\n"
        "        session->passwall_diag.ctr_rx_block_calls = 0;\n"
        "        session->passwall_diag.ctr_rx_block_bytes = 0;\n"
        "        session->passwall_diag.ctr_tx_bulk_calls = 0;\n"
        "        session->passwall_diag.ctr_tx_bulk_bytes = 0;\n"
        "        session->passwall_diag.ctr_tx_block_calls = 0;\n"
        "        session->passwall_diag.ctr_tx_block_bytes = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "reset AES-CTR counters per PERF interval"
    )
    session_c.write_text(source)

    transport = root / "src/transport.c"
    source = transport.read_text()
    source = once(
        source,
        "        if(CRYPT_FLAG_L(session, REQUIRES_FULL_PACKET)) {\n"
        "            if(session->local.crypt->crypt(session,\n",
        "        if(CRYPT_FLAG_L(session, CTR_BULK)) {\n"
        "            size_t crypt_len;\n"
        "            int blocksize = session->local.crypt->blocksize;\n"
        "            if(blocksize <= 0 || packet_length < etm_crypt_offset) {\n"
        "                memset(p->outbuf, 0, sizeof(p->outbuf));\n"
        "                return LIBSSH2_ERROR_ENCRYPT;\n"
        "            }\n"
        "            crypt_len = packet_length - etm_crypt_offset;\n"
        "            if(crypt_len == 0U || (crypt_len % (size_t)blocksize) != 0U) {\n"
        "                memset(p->outbuf, 0, sizeof(p->outbuf));\n"
        "                return LIBSSH2_ERROR_ENCRYPT;\n"
        "            }\n"
        "            if(session->local.crypt->crypt(\n"
        "                   session, 0, &p->outbuf[etm_crypt_offset], crypt_len,\n"
        "                   &session->local.crypt_abstract, MIDDLE_BLOCK)) {\n"
        "                memset(p->outbuf, 0, sizeof(p->outbuf));\n"
        "                return LIBSSH2_ERROR_ENCRYPT;\n"
        "            }\n"
        "            if(session->passwall_diag.enabled) {\n"
        "                session->passwall_diag.ctr_tx_bulk_calls++;\n"
        "                session->passwall_diag.ctr_tx_bulk_bytes +=\n"
        "                    (unsigned long long)crypt_len;\n"
        "            }\n"
        "        }\n"
        "        else if(CRYPT_FLAG_L(session, REQUIRES_FULL_PACKET)) {\n"
        "            if(session->local.crypt->crypt(session,\n",
        "batch the transmit AES-CTR fragment without changing MAC ordering"
    )
    transport.write_text(source)


def patch_core(project_root: Path) -> None:
    core = project_root / "ssh-core.c"
    source = core.read_text()
    source = once(
        source,
        "    int fatal = (err == LIBSSH2_ERROR_DECRYPT ||\n"
        "                 err == LIBSSH2_ERROR_OUT_OF_BOUNDARY ||\n"
        "                 err == LIBSSH2_ERROR_PROTO);",
        "    int fatal = (err == LIBSSH2_ERROR_DECRYPT ||\n"
        "                 err == LIBSSH2_ERROR_OUT_OF_BOUNDARY ||\n"
        "                 err == LIBSSH2_ERROR_PROTO ||\n"
        "                 err == LIBSSH2_ERROR_ENCRYPT);",
        "treat an upstream encryption failure as terminal"
    )
    source = once(
        source,
        "    const char *ssh_cipher_pref =\n"
        "        \"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr\";\n"
        "    int cipher_cs_rc = libssh2_session_method_pref(\n",
        "    const char *ssh_cipher_profile = getenv(\"SSH_CIPHER_PROFILE\");\n"
        "    const char *ssh_cipher_pref =\n"
        "        \"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr\";\n"
        "    if(ssh_cipher_profile && strcmp(ssh_cipher_profile, \"aes128-ctr\") == 0) {\n"
        "        ssh_cipher_pref = \"aes128-ctr\";\n"
        "        log_blue(\"[SSH-CIPHER-PROFILE] opt-in aes128-ctr test profile active\");\n"
        "    }\n"
        "    else if(ssh_cipher_profile && ssh_cipher_profile[0] &&\n"
        "            strcmp(ssh_cipher_profile, \"auto\") != 0) {\n"
        "        log_yellow(\"[SSH-CIPHER-PROFILE] unknown profile '%s'; retaining production defaults\",\n"
        "                   ssh_cipher_profile);\n"
        "    }\n"
        "    int cipher_cs_rc = libssh2_session_method_pref(\n",
        "add opt-in AES-CTR cipher profile without changing defaults"
    )
    source = once(
        source,
        "        log_blue(\"SSH cipher preference: chacha20-poly1305@openssh.com first; AES fallback enabled\");",
        "        if(ssh_cipher_profile && strcmp(ssh_cipher_profile, \"aes128-ctr\") == 0)\n"
        "            log_blue(\"SSH cipher preference: AES-128-CTR forced for R64 validation\");\n"
        "        else\n"
        "            log_blue(\"SSH cipher preference: chacha20-poly1305@openssh.com first; AES fallback enabled\");",
        "log the active SSH cipher preference profile"
    )
    source = once(
        source,
        "    {\n"
        "        const char *cp = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC);\n"
        "        const char *mc = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC);\n"
        "        log_blue(\"SSH Cipher: %s | MAC: %s\", cp ? cp : \"?\", mc ? mc : \"?\");\n"
        "    }\n",
        "    {\n"
        "        const char *cp_cs = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_CS);\n"
        "        const char *mc_cs = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_CS);\n"
        "        const char *cp_sc = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC);\n"
        "        const char *mc_sc = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC);\n"
        "        log_blue(\"[SSH-METHODS] cs_crypt=%s cs_mac=%s sc_crypt=%s sc_mac=%s\",\n"
        "                 cp_cs ? cp_cs : \"?\", mc_cs ? mc_cs : \"?\",\n"
        "                 cp_sc ? cp_sc : \"?\", mc_sc ? mc_sc : \"?\");\n"
        "        /* Keep this parser-stable legacy line for existing diagnostics. */\n"
        "        log_blue(\"SSH Cipher: %s | MAC: %s\", cp_sc ? cp_sc : \"?\", mc_sc ? mc_sc : \"?\");\n"
        "    }\n",
        "log negotiated cipher and MAC in both directions"
    )
    source = once(
        source,
        "            (unsigned long long)libssh2_diag.chacha20_profile_packets);\n\n"
        "    memset(&g_perf_stats, 0, sizeof(g_perf_stats));",
        "            (unsigned long long)libssh2_diag.chacha20_profile_packets);\n\n"
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
        "    memset(&g_perf_stats, 0, sizeof(g_perf_stats));",
        "add separate compact AES-CTR PERF record"
    )
    core.write_text(source)


def patch(root: Path, project_root: Path) -> None:
    if not (root / ".passwall-r63-crypto-transport-hardening-patched").is_file():
        raise RuntimeError("R64 requires the R63 hardening patch")
    if not (root / ".passwall-r62-runtime-ab-controls-patched").is_file():
        raise RuntimeError("R64 requires the R62 runtime-control patch")
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("R64 is pinned to libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("R64 patch marker already exists")

    patch_transport_security(root)
    patch_openssl_backend(root)
    patch_transport_bulk_and_diag(root, project_root)
    patch_core(project_root)

    (root / MARKER).write_text(
        "Passwall R64: ETM/packet ownership backports plus OpenSSL 3 EVP AES-128-CTR bulk RX/TX\n"
    )
    print(
        "PASS: R64 transport security backports, OpenSSL EVP AES-128-CTR bulk path, "
        "directional cipher logs and isolated CTR performance counters"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply_libssh2_r64.py LIBSSH2_SOURCE_DIR PROJECT_ROOT")
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
