#!/usr/bin/env python3
"""Source-level guard for the r51 authenticate-before-decrypt ordering."""
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: chachapoly_auth_order_test.py PATH_TO_PATCHED_CHACHA_C", file=sys.stderr)
        return 2

    source = Path(sys.argv[1]).read_text()
    marker = "/*\n * r51: authenticate the complete ciphertext before any worker writes plaintext."
    signature = "int\nchacha_decrypt_poly_worker_only("
    if source.count(marker) != 1 or source.count(signature) != 1:
        print("FAIL: expected exactly one r51 worker-only decrypt implementation", file=sys.stderr)
        return 1

    start = source.find(marker)
    function_start = source.find(signature, start)
    function_end = source.find("\n}\n", function_start)
    if function_start < 0 or function_end < 0:
        print("FAIL: unable to isolate the r51 worker-only decrypt function", file=sys.stderr)
        return 1
    function = source[function_start:function_end + 3]

    poly_dispatch = function.find("CHACHA_TASK_POLY1305")
    poly_wait = function.find("while(pool->completed < workers", poly_dispatch)
    tag_compare = function.find("tag_diff != 0U", poly_wait)
    decrypt_dispatch = function.find("pool->task_kind[worker] = CHACHA_TASK_DECRYPT", tag_compare)

    checks = {
        "Poly1305 task is dispatched first": poly_dispatch >= 0,
        "Owner waits for every phase-one worker": poly_wait > poly_dispatch,
        "tag mismatch is checked before decrypt dispatch": tag_compare > poly_wait and decrypt_dispatch > tag_compare,
        "Poly1305 reads the original packet directly": "pool->poly_input = source;" in function,
        "no ciphertext snapshot copy remains": "memcpy(pool->poly_input" not in function,
        "tag failure returns before phase two": function.find("rc = -2;", tag_compare) < decrypt_dispatch,
    }
    failed = [name for name, passed in checks.items() if not passed]
    for name, passed in checks.items():
        print(("PASS: " if passed else "FAIL: ") + name)
    if failed:
        return 1
    print("PASS: r51 authenticate-before-decrypt source invariant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
