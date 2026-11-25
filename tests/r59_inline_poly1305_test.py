#!/usr/bin/env python3
"""Source invariants for r59 inline Owner Poly1305 and single worker dispatch."""
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
    raise RuntimeError("unterminated C function")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: r59_inline_poly1305_test.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    chacha = (root / "src/chacha.c").read_text()
    parallel = extract(chacha, "int\nchacha_decrypt_poly_worker_only(")
    worker = extract(chacha, "static void *\nchacha_parallel_worker_main(void *opaque)")

    auth = parallel.find(
        "poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);"
    )
    tag_check = parallel.find("if(tag_diff != 0U)")
    decrypt_skip = parallel.find("pool->task_kind[worker] = worker == 0U ?")
    decrypt_plain = parallel.find("pool->task_kind[worker] = CHACHA_TASK_DECRYPT;")

    checks = [
        check(auth >= 0 and "CHACHA_TASK_POLY1305" not in parallel,
              "Poly1305 executes directly in the Owner instead of a worker task"),
        check(parallel.count("pool->generation++") == 1 and
              parallel.count("(void)pthread_cond_broadcast(&pool->work_ready);") == 2 and
              parallel.find("pool->generation++") <
              parallel.find("(void)pthread_cond_broadcast(&pool->work_ready);"),
              "success path dispatches once; the additional broadcast is error recovery only"),
        check(0 <= auth < tag_check < decrypt_skip and
              0 <= auth < tag_check < decrypt_plain,
              "constant-time tag comparison precedes every decrypt task assignment"),
        check(tag_check < parallel.find("pool->destination = destination + dest_aadlen") and
              tag_check < parallel.find("pool->padding_length_out = skip_first"),
              "failed authentication cannot write plaintext or padding metadata"),
        check("pool->poly_ns = elapsed;" in parallel and
              "pool->poly_wall_ns = elapsed;" in parallel and
              "poly_wall_ns_out" in parallel,
              "legacy Poly1305 execution and wall counters measure the same inline call"),
        check("CHACHA_TASK_DECRYPT_SKIP_FIRST" in parallel and
              "pool->destination_offsets[worker]" in parallel and
              "pool->measure_decrypt = 0U;" in parallel,
              "r56 normalized-output handling and r57 worker timing cleanup are preserved"),
        check("pool->decrypt_worker_ns += elapsed;" in worker and
              "pool->decrypt_worker_max_ns" in worker,
              "per-worker CPU and critical-time accounting remains enabled"),
        check((root / ".passwall-r59-inline-owner-poly1305-patched").is_file(),
              "r59 patch marker is present"),
    ]
    if not all(checks):
        return 1
    print("PASS: r59 inline Owner Poly1305 invariants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
