#!/usr/bin/env python3
"""Static source invariants for r56 normalized ChaCha packet output."""
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
        "CHACHA_TASK_DECRYPT_SKIP_FIRST" in chacha and
        "pool->destination_offsets[worker]" in chacha,
        "worker pool has a dedicated first-block task and independent output offsets",
    )
    require(
        "chacha_encrypt_bytes(&local_state, zero_block, first_keystream" in chacha and
        "*padding_length_out = (u8)(source[0] ^ first_keystream[0])" in chacha and
        "destination[i - 1U] = (u8)(source[i] ^ first_keystream[i])" in chacha,
        "worker zero extracts padding length and writes the remaining first block without shifting",
    )

    auth_check = chacha.find("if(tag_diff != 0U)")
    skip_dispatch = chacha.find("CHACHA_TASK_DECRYPT_SKIP_FIRST", auth_check)
    require(
        auth_check >= 0 and skip_dispatch > auth_check and
        "pool->poly_input = source;" in chacha,
        "worker mode authenticates the complete original packet before normalized plaintext writes",
    )
    require(
        "counter += 1U + first_block;" in chacha and
        "CHACHA_BLOCKLEN + (u_int)(first_block * CHACHA_BLOCKLEN)" in chacha and
        "(CHACHA_BLOCKLEN - 1U) +" in chacha,
        "suffix workers use counter two and correctly shifted source/output offsets",
    )

    require(
        "unsigned int drop_first, u_char *padding_length_out" in cipher and
        "unsigned int drop_first, u_char *padding_length_out" in cipher_h and
        "drop_first && (do_encrypt || dest_aadlen != 0U" in cipher,
        "ChaCha-Poly API explicitly scopes authenticated padding-byte omission to decrypt",
    )
    mac = cipher.find("poly1305_auth(expected_tag, src, aadlen + len, poly_key)")
    tag_check = cipher.find("chachapoly_timingsafe_bcmp(expected_tag, tag", mac)
    skip_write = cipher.find("*padding_length_out = (u_char)(src[aadlen] ^ first_keystream[0])", tag_check)
    require(
        mac >= 0 and tag_check > mac and skip_write > tag_check,
        "serial fallback authenticates the original AAD and ciphertext before extracting padding length",
    )
    require(
        "src + aadlen + 64U" in cipher and "dest + 63U" in cipher and
        "len - 64U" in cipher,
        "serial fallback continues at ChaCha counter two after consuming the first block",
    )

    helper = crypt.find("_libssh2_chachapoly_decrypt_body")
    require(
        helper >= 0 and "1U, padding_length, 0" in crypt and
        "memset(destination + payload_len" not in crypt,
        "transport helper requests normalized output and no longer writes a discarded tag placeholder",
    )
    require(
        "_libssh2_chachapoly_decrypt_body" in priv and
        "unsigned char *padding_length" in priv,
        "private helper prototype carries the recovered padding length",
    )

    fullpacket = transport.find("fullpacket(LIBSSH2_SESSION")
    no_move_gate = transport.find(
        'strcmp(session->remote.crypt->name,\n                       "chacha20-poly1305@openssh.com") != 0',
        fullpacket,
    )
    move = transport.find("memmove(p->payload, &p->payload[1], p->packet_length - 1)", fullpacket)
    require(
        fullpacket >= 0 and no_move_gate > fullpacket and move > no_move_gate,
        "fullpacket skips the padding memmove only for the already-normalized ChaCha path",
    )
    require(
        "p->total_num -= (size_t)auth_len + 1U;" in transport and
        "numwrite = numdecrypt - (ssize_t)auth_len - 1;" in transport and
        "p->wptr += numwrite;" in transport and "p->data_num += numwrite;" in transport,
        "transport buffer accounting matches the shorter normalized plaintext while consuming the full wire packet",
    )
    require(
        "if(!out_of_place_chachapoly)\n                    p->padding_length = p->wptr[0];" in transport and
        "&p->padding_length," in transport,
        "transport uses the separately recovered padding length rather than packet type",
    )
    require(
        "if(!out_of_place_chachapoly)\n                    memcpy(p->wptr, &p->buf[p->readidx], numbytes);" in transport,
        "non-ChaCha full-packet ciphers retain the previous copy path",
    )
    require(
        ".passwall-r56-skip-padding-memmove-patched" in
        (root / ".passwall-r56-skip-padding-memmove-patched").read_text(),
        "r56 patch marker exists",
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: r56_skip_padding_test.py LIBSSH2_SOURCE_DIR")
    main(Path(sys.argv[1]))
