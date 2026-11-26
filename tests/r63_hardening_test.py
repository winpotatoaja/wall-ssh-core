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
    cleanup_ctx_fn = extract(cipher, "void\nchachapoly_cleanup(")
    worker_fn = extract(chacha, "static void *\nchacha_parallel_worker_main(void *opaque)")
    owner_fn = extract(chacha, "int\nchacha_decrypt_poly_worker_only(")
    resume_fn = extract(core, "static int resume_pending_op(")
    pump_fn = extract(core, "static int pump_ssh_channels(")
    closing_start = pump_fn.find("} else if (c->state == ST_CLOSING)")
    closing_fn = pump_fn[closing_start:] if closing_start >= 0 else ""

    cleanup_start = crypt_fn.rfind("\nout:\n")
    cleanup_fn = crypt_fn[cleanup_start:] if cleanup_start >= 0 else ""

    checks = [
        check((root / ".passwall-r62-runtime-ab-controls-patched").is_file() and
              (root / ".passwall-r63-crypto-transport-hardening-patched").is_file(),
              "R62 prerequisites and R63 patch markers are present"),
        check("chacha_encrypt_bytes_parallel" not in crypt_fn,
              "legacy fixed-4-KiB parallel fallback is removed from chachapoly_crypt"),
        check("volatile unsigned char *p" in cipher and
              all("chachapoly_secure_wipe(" + name in crypt_fn
                  for name in ("expected_tag", "seqbuf", "poly_key",
                               "first_keystream", "zero_block")),
              "all five ChaCha packet-stack secrets use non-elidable wiping"),
        check("chachapoly_secure_wipe(ctx, sizeof(*ctx))" in cleanup_ctx_fn and
              "memset(ctx, 0, sizeof(*ctx))" not in cleanup_ctx_fn,
              "ChaCha context key schedule is securely wiped at cleanup"),
        check(crypt_fn.count("memset(poly_key, 0, sizeof(poly_key));") == 1 and
              "chachapoly_secure_wipe(poly_key" in crypt_fn,
              "poly_key zero-initialization is preserved and only final cleanup uses secure wipe"),
        check(cleanup_start >= 0 and
              cleanup_fn.count("chachapoly_secure_wipe(") == 5 and
              all("memset(" + name not in cleanup_fn
                  for name in ("expected_tag", "seqbuf", "poly_key",
                               "first_keystream", "zero_block")),
              "R63 out cleanup securely wipes exactly five ChaCha stack secrets"),
        check("#if LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM" in poly1305 and
              "poly1305_secure_wipe(&state" in poly1305_fn and
              "poly1305_secure_wipe(pad" in poly1305_fn and
              "poly1305_secure_wipe(final_block" in poly1305_fn,
              "MIPS Poly1305 accumulator, pad and tail scratch use guarded non-elidable wiping"),
        check(worker_fn.count("chacha_parallel_report_worker_error(pool, lock_rc)") == 2,
              "worker startup and completion mutex failures are reported"),
        check("chacha_parallel_report_worker_error(pool, lock_rc)" in worker_fn and
              worker_fn.count("chacha_parallel_report_worker_error(pool, lock_rc)") == 2,
              "worker startup and completion mutex failures are reported"),
        check("chacha_parallel_wait_for_workers(pool, workers)" in owner_fn and
              owner_fn.count("chacha_parallel_wait_for_workers(pool, workers)") == 2 and
              "pthread_cond_wait(&pool->work_done" not in owner_fn,
              "both Poly1305 and decrypt phases use bounded worker waits"),
        check("pthread_condattr_setclock(&work_done_attr, CLOCK_MONOTONIC)" in chacha and
              "work_done_monotonic" in chacha and
              "clock_gettime(clock_id, &deadline)" in chacha,
              "work_done uses MONOTONIC and a clock-matched fallback"),
        check("__atomic_load_n(&pool->stopping" in chacha and
              "__atomic_load_n(&pool->worker_error" in chacha and
              "pool->stopping =" not in chacha and
              "pool->worker_error =" not in chacha,
              "all shared stopping/error state accesses are atomic"),
        check("errno = first_error;\n        abort();" in chacha,
              "join failure is fail-stop to prevent caller-buffer use-after-free"),
        check("chacha_parallel_wipe(destination + dest_aadlen" in owner_fn and
              "skip_first ? bytes - 1U : bytes" in owner_fn and
              "if(chacha_parallel_pool_stop(pool) != 0) abort();" in owner_fn,
              "partial output is wiped after complete worker stop/join"),
        check('CMAKE_SYSTEM_PROCESSOR MATCHES "mips" AND CMAKE_SIZEOF_VOID_P EQUAL 4' in cmake,
              "MIPS ChaCha assembly is restricted to 32-bit ABI targets"),
        check("static int is_libssh2_protocol_fatal(int err)" in core and
              all(token in core for token in (
                  "LIBSSH2_ERROR_DECRYPT", "LIBSSH2_ERROR_MAC_FAILURE",
                  "LIBSSH2_ERROR_OUT_OF_BOUNDARY", "LIBSSH2_ERROR_PROTO")),
              "SSH decrypt/MAC/framing/protocol errors have a session-fatal class"),
        check("if (op == PENDING_KEEPALIVE)" in resume_fn and
              "is_libssh2_protocol_fatal(rc)" in resume_fn,
              "pending keepalive protocol errors terminate the SSH session"),
        check("if (op == PENDING_FREE)" in resume_fn and
              "is_libssh2_protocol_fatal(rc)" in resume_fn,
              "pending channel-free protocol errors terminate the SSH session"),
        check("is_libssh2_protocol_fatal(err)" in resume_fn and
              "is_libssh2_protocol_fatal((int)w)" in resume_fn and
              "is_libssh2_protocol_fatal(rc)" in resume_fn and
              "is_libssh2_protocol_fatal((int)r)" in resume_fn,
              "pending OPEN/WRITE/EOF/READ paths propagate fatal protocol errors"),
        check("is_libssh2_protocol_fatal(err)" in pump_fn and
              "is_libssh2_protocol_fatal((int)w)" in pump_fn and
              "is_libssh2_protocol_fatal(rc)" in pump_fn and
              "is_libssh2_protocol_fatal((int)r)" in pump_fn,
              "immediate OPEN/WRITE/EOF/READ paths propagate fatal protocol errors"),
        check("is_libssh2_protocol_fatal(rc)" in closing_fn,
              "ST_CLOSING channel-free protocol errors terminate the SSH session"),
        check("g_skip_libssh2_cleanup = 1" in core and
              "R63: fatal SSH integrity/protocol errors invalidate the upstream session." in core,
              "fatal SSH errors disable further libssh2 cleanup I/O"),
        check("chacha20_parallel_packets !=" in test_c and
              "chacha20_serial_packets !=" in test_c and
              "R63 threshold bypass" in test_c and
              "successful_decrypt_calls = payload_len == 0U ? 2U : 3U" in test_c,
              "ChaCha matrix counts only successful calls for empty payload"),
        check("bad_diag_session" in test_c and
              "bad_diag_session.passwall_diag.chacha20_parallel_packets != 0ULL" in test_c and
              "bad_diag_session.passwall_diag.chacha20_serial_packets != 0ULL" in test_c,
              "bad-tag regression requires zero serial and parallel dispatch counters"),
    ]
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
