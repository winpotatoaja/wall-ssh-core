#!/usr/bin/env python3
"""Static invariants for r55 authenticated out-of-place transport decryption."""
from pathlib import Path
import sys


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)
    print("PASS: " + message)


def main(root: Path) -> None:
    chacha = (root / "src/chacha.c").read_text()
    chacha_h = (root / "src/chacha.h").read_text()
    cipher = (root / "src/cipher-chachapoly.c").read_text()
    cipher_h = (root / "src/cipher-chachapoly.h").read_text()
    crypt = (root / "src/crypt.c").read_text()
    transport = (root / "src/transport.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()

    require(
        "pool->destination = destination + dest_aadlen;" in chacha,
        "worker pool writes payload at the independent destination offset",
    )
    require(
        "u_int dest_aadlen," in chacha and "u_int dest_aadlen," in chacha_h,
        "worker function definition and declaration expose destination AAD offset",
    )
    require(
        "pool->poly_input = source;" in chacha and
        "poly_len = (size_t)aadlen + (size_t)bytes;" in chacha,
        "Poly1305 still authenticates the original AAD plus ciphertext",
    )
    tag_check = chacha.find("if(tag_diff != 0U)")
    decrypt_dispatch = chacha.find("pool->task_kind[worker] = CHACHA_TASK_DECRYPT", tag_check)
    require(
        tag_check >= 0 and decrypt_dispatch > tag_check,
        "parallel ChaCha decrypt tasks are dispatched only after tag comparison",
    )

    require(
        "u_int aadlen,\n                 u_int dest_aadlen, int do_encrypt" in cipher and
        "u_int aadlen, u_int dest_aadlen, int do_encrypt" in cipher_h,
        "ChaCha20-Poly1305 API distinguishes authenticated AAD from emitted AAD",
    )
    mac = cipher.find("poly1305_auth(expected_tag, src, aadlen + len, poly_key)")
    tag_compare = cipher.find("chachapoly_timingsafe_bcmp(expected_tag, tag", mac)
    header_write = cipher.find("if(dest_aadlen)", mac)
    body_write = cipher.find("dest + dest_aadlen, len", mac)
    require(
        mac >= 0 and tag_compare > mac and header_write > tag_compare and
        body_write > tag_compare,
        "serial fallback authenticates source before writing AAD or payload",
    )
    require(
        "poly1305_auth(dest + dest_aadlen + len, dest,\n                      dest_aadlen + len, poly_key);" in cipher,
        "encryption tag follows the configured output AAD layout",
    )

    require(
        "_libssh2_chachapoly_decrypt_body" in crypt and
        "chachapoly_crypt(session, &ctx->chachapoly_ctx, seqno" in crypt and
        "destination, source, payload_len, 4U, 0U, 0" in crypt,
        "transport helper uses the session-aware crypto API for authenticated body-only output",
    )
    require(
        "_libssh2_chachapoly_decrypt_body" in priv,
        "internal body-only helper is declared for transport.c",
    )
    transport_gate = transport.find("int out_of_place_chachapoly")
    helper_call = transport.find("_libssh2_chachapoly_decrypt_body", transport_gate)
    guarded_copy = transport.find("if(!out_of_place_chachapoly)", helper_call)
    memcpy = transport.find("memcpy(p->wptr, &p->buf[p->readidx], numbytes)", guarded_copy)
    require(
        transport_gate >= 0 and helper_call > transport_gate and
        guarded_copy > helper_call and memcpy > guarded_copy,
        "ChaCha transport decrypt bypasses the packet memcpy; other ciphers retain it",
    )
    require(
        "strcmp(session->remote.crypt->name," in transport and
        '"chacha20-poly1305@openssh.com"' in transport,
        "out-of-place path is scoped to the negotiated OpenSSH ChaCha cipher",
    )
    require(
        "memmove(p->payload, &p->payload[1], p->packet_length - 1);" in transport,
        "existing padding-byte normalization remains unchanged in r55",
    )
    require(
        ".passwall-r55-out-of-place-chachapoly-patched" in
        (root / ".passwall-r55-out-of-place-chachapoly-patched").read_text(),
        "r55 patch marker exists",
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: r55_out_of_place_test.py LIBSSH2_SOURCE_DIR")
    main(Path(sys.argv[1]))
