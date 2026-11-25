#!/usr/bin/env python3
"""Source-level guards for r57 ChaCha20-Poly1305 phase profiling."""
from pathlib import Path
import sys


def check(condition: bool, label: str) -> bool:
    print(("PASS: " if condition else "FAIL: ") + label)
    return condition


def extract(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one {signature!r}")
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
                return source[start:i + 1]
        i += 1
    raise RuntimeError("unterminated function")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: r57_chachapoly_profile_test.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    chacha = (root / "src/chacha.c").read_text()
    cipher = (root / "src/cipher-chachapoly.c").read_text()
    private = (root / "src/libssh2_priv.h").read_text()
    session = (root / "src/session.c").read_text()

    worker = extract(chacha, "static void *\nchacha_parallel_worker_main(void *opaque)")
    parallel = extract(chacha, "int\nchacha_decrypt_poly_worker_only(")
    crypt = extract(cipher, "int\nchachapoly_crypt(")

    session_diag_start = private.find("/* Passwall r43 diagnostics.")
    session_diag_end = private.find("} passwall_diag;", session_diag_start)
    snapshot_start = private.find("typedef struct {", session_diag_end)
    snapshot_end = private.find("} LIBSSH2_DIAG_TIMING;", snapshot_start)
    r57_fields = (
        "chacha_poly1305_wall_ns",
        "chacha20_decrypt_wall_ns",
        "chacha20_worker_cpu_ns",
        "chacha20_worker_critical_ns",
        "chacha20_parallel_other_ns",
        "chacha20_profile_packets",
    )

    checks = [
        check(".passwall-r57-chachapoly-profile-patched" in
              (root / ".passwall-r57-chachapoly-profile-patched").read_text(),
              "r57 patch marker is present"),
        check("pool->poly_wall_ns" in parallel and
              "poly_wall_started_ns = chacha_parallel_now_ns()" in parallel,
              "Poly1305 phase wall time measures the direct Owner authentication call"),
        check("pool->decrypt_wall_ns" in parallel and
              "decrypt_wall_started_ns = chacha_parallel_now_ns()" in parallel,
              "ChaCha decrypt phase wall time includes worker dispatch and barrier"),
        check("if(measure_decrypt &&" in worker and
              "pool->decrypt_worker_ns += elapsed;" in worker and
              "pool->decrypt_worker_max_ns" in worker,
              "per-worker crypto time is measured only when diagnostics are enabled"),
        check(parallel.find("tag_diff != 0U") <
              parallel.find("CHACHA_TASK_DECRYPT_SKIP_FIRST") and
              parallel.find("tag_diff != 0U") <
              parallel.find("CHACHA_TASK_DECRYPT;"),
              "Poly1305 tag comparison remains before every decrypt task dispatch"),
        check("&poly_wall_ns" in crypt and "&decrypt_wall_ns" in crypt and
              "&decrypt_worker_ns" in crypt and
              "chacha20_parallel_other_ns" in crypt,
              "cipher entry point exports and records all profile phases"),
        check(session_diag_start >= 0 and session_diag_end > session_diag_start and
              snapshot_start >= 0 and snapshot_end > snapshot_start and
              all(("unsigned long long " + field + ";") in
                  private[session_diag_start:session_diag_end] and
                  ("unsigned long long " + field + ";") in
                  private[snapshot_start:snapshot_end]
                  for field in r57_fields),
              "session counters and public timing snapshot both expose every r57 field"),
        check("timing->chacha20_profile_packets" in session and
              "session->passwall_diag.chacha20_profile_packets = 0;" in session,
              "snapshot copies and resets all per-interval profile counters"),
    ]

    if not all(checks):
        return 1
    print("PASS: r57 ChaCha20-Poly1305 profiling source invariants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
