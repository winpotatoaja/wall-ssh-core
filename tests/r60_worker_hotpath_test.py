#!/usr/bin/env python3
"""Source invariants for r60 decrypt-only worker and reduced hot-path wakeups."""
from pathlib import Path
import sys


def check(condition: bool, label: str) -> bool:
    print(("PASS: " if condition else "FAIL: ") + label)
    return condition


def extract(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one " + repr(signature))
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("function body missing")
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
        print("usage: r60_worker_hotpath_test.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    source = (root / "src/chacha.c").read_text()
    worker = extract(source, "static void *\nchacha_parallel_worker_main(void *opaque)")
    owner = extract(source, "int\nchacha_decrypt_poly_worker_only(")

    checks = [
        check("CHACHA_TASK_POLY1305" not in source and
              "pool->poly_input" not in source and
              "pool->poly_len" not in source and
              "pool->measure_poly" not in source,
              "obsolete Poly1305 worker task and snapshot state are removed"),
        check("malloc(CHACHA_PARALLEL_MAX_PACKET)" not in source,
              "no per-session Poly1305 scratch snapshot is allocated"),
        check(worker.count("prctl(PR_SET_NAME") == 1 and
              worker.count("snprintf(thread_name") == 1 and
              worker.find("prctl(PR_SET_NAME") < worker.find("pthread_mutex_lock"),
              "worker thread name is set once at thread startup, not per packet"),
        check("poly1305_auth" not in worker and
              "CHACHA_TASK_DECRYPT_SKIP_FIRST" in worker and
              "else if(task_kind == CHACHA_TASK_DECRYPT)" in worker,
              "persistent workers execute decrypt tasks only and preserve r56 normalized output"),
        check("pool->decrypt_worker_ns += elapsed;" in worker and
              "pool->decrypt_worker_max_ns" in worker and
              "measure_decrypt = pool->measure_decrypt;" in worker,
              "r57 per-worker CPU and critical-time profiling remains intact"),
        check("if(pool->completed >= pool->worker_count)" in worker and
              "pool->active_workers == 0U" not in worker,
              "Owner is signaled only after every worker completes the generation"),
        check("poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);" in owner and
              owner.find("poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);") <
              owner.find("if(tag_diff != 0U)") <
              owner.find("pool->task_kind[worker] = worker == 0U ?"),
              "r59 Owner authentication and tag check still precede decrypt dispatch"),
        check("pool->poly_key" in owner and "pool->poly_tag" in owner and
              "pool->decrypt_worker_ns" in source,
              "Owner key/tag state and worker timing storage remain available"),
        check((root / ".passwall-r52-worker-lifecycle-patched").is_file() and
              "pthread_join" in source,
              "r52 join-before-return lifecycle hardening remains in place"),
        check((root / ".passwall-r60-worker-hotpath-cleanup-patched").is_file(),
              "r60 patch marker is present"),
    ]
    if not all(checks):
        return 1
    print("PASS: r60 worker hot-path cleanup invariants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
