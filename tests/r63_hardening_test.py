#!/usr/bin/env python3
"""Source-level regression checks for the R63 crypto/transport hardening patch."""
from pathlib import Path
import sys


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


def check(condition: bool, label: str) -> bool:
    print(("PASS: " if condition else "FAIL: ") + label)
    return condition


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: r63_hardening_test.py LIBSSH2_SOURCE_DIR SSH_CORE_C CHACHAPOLY_TEST_C",
              file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    core = Path(sys.argv[2]).read_text()
    test_c = Path(sys.argv[3]).read_text()
    chacha = (root / "src/chacha.c").read_text()
    cipher = (root / "src/cipher-chachapoly.c").read_text()
    cmake = (root / "src/CMakeLists.txt").read_text()
    poly1305 = (root / "src/poly1305.c").read_text()
    poly1305_fn = extract(poly1305, "void\npoly1305_auth(")

    crypt_fn = extract(cipher, "int\nchachapoly_crypt(")
    worker_fn = extract(chacha, "static void *\nchacha_parallel_worker_main(void *opaque)")
    owner_fn = extract(chacha, "int\nchacha_decrypt_poly_worker_only(")

    checks = [
        check((root / ".passwall-r62-runtime-ab-controls-patched").is_file() and
              (root / ".passwall-r63-crypto-transport-hardening-patched").is_file(),
              "R62 prerequisites and R63 patch markers are present"),
        check("chacha_encrypt_bytes_parallel" not in crypt_fn,
              "legacy fixed-4-KiB parallel fallback is removed from chachapoly_crypt"),
        check("volatile unsigned char *p" in cipher and
              "chachapoly_secure_wipe(expected_tag" in crypt_fn and
              "chachapoly_secure_wipe(poly_key" in crypt_fn,
              "ChaCha stack secrets use non-elidable wiping"),
        check("#if LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM" in poly1305 and
              "poly1305_secure_wipe(&state" in poly1305_fn and
              "poly1305_secure_wipe(pad" in poly1305_fn and
              "poly1305_secure_wipe(final_block" in poly1305_fn,
              "MIPS Poly1305 accumulator, pad and tail scratch use guarded non-elidable wiping"),
        check(worker_fn.count("chacha_parallel_report_worker_error(pool, lock_rc)") == 2,
              "worker startup and completion mutex failures are reported"),
        check("__atomic_load_n(&pool->worker_error" in owner_fn and
              "pthread_cond_timedwait(&pool->work_done" in owner_fn and
              "deadline.tv_sec += 10" in owner_fn,
              "Owner observes worker failure atomically and has a bounded wait"),
        check("chacha_parallel_wipe(destination + dest_aadlen, bytes)" in owner_fn and
              "chacha_parallel_pool_stop(pool)" in owner_fn,
              "partial plaintext is wiped only after worker pool stop/join"),
        check('CMAKE_SYSTEM_PROCESSOR MATCHES "mips" AND CMAKE_SIZEOF_VOID_P EQUAL 4' in cmake,
              "MIPS ChaCha assembly is restricted to 32-bit ABI targets"),
        check("static int is_libssh2_protocol_fatal(int err)" in core and
              "LIBSSH2_ERROR_DECRYPT" in core and
              "LIBSSH2_ERROR_MAC_FAILURE" in core and
              "LIBSSH2_ERROR_OUT_OF_BOUNDARY" in core,
              "SSH integrity/decrypt/framing failures have a session-fatal class"),
        check(core.count("is_libssh2_protocol_fatal(") >= 8,
              "pending and immediate channel paths propagate session-fatal protocol errors"),
        check("chacha20_parallel_packets !=" in test_c and
              "chacha20_serial_packets !=" in test_c and
              "R63 threshold bypass" in test_c,
              "ChaCha A/B matrix asserts both serial and parallel execution counters"),
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
