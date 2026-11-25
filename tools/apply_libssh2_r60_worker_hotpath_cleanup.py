#!/usr/bin/env python3
"""Passwall r60: remove obsolete Poly1305 worker path and per-packet worker overhead."""
from pathlib import Path
import sys


def find_matching_brace(source: str, brace: int) -> int:
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
                return i + 1
        i += 1
    raise RuntimeError("unterminated C block")


def replace_function(source: str, signature: str, replacement: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("function body missing: " + signature)
    end = find_matching_brace(source, brace)
    return source[:start] + replacement.rstrip() + source[end:]


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(label + ": expected one anchor, found " + str(count))
    return source.replace(old, new, 1)


def patch_pool_struct(source: str) -> str:
    field = "unsigned long long generation;"
    idx = source.find(field)
    if idx < 0 or source.find(field, idx + 1) >= 0:
        raise RuntimeError("expected one crypto pool generation field")
    start = source.rfind("struct chacha_parallel_pool", 0, idx)
    if start < 0:
        raise RuntimeError("crypto pool struct declaration not found")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("crypto pool struct body not found")
    end = find_matching_brace(source, brace)
    block = source[start:end]
    pointer_fields = (
        "    u8 *poly_input;\n",
        "    const u8 *poly_input;\n",
    )
    pointer_matches = [line for line in pointer_fields if block.count(line) == 1]
    if len(pointer_matches) != 1 or sum(block.count(line) for line in pointer_fields) != 1:
        raise RuntimeError(
            "remove obsolete Poly1305 borrowed/scratch pointer: "
            "expected exactly one mutable or const pool field"
        )
    block = block.replace(pointer_matches[0], "", 1)

    for line, label in (
        ("    size_t poly_len;\n", "remove obsolete Poly1305 worker length"),
        ("    unsigned int measure_poly;\n", "remove obsolete Poly1305 worker timing flag"),
    ):
        if block.count(line) != 1:
            raise RuntimeError(label + ": expected one pool field")
        block = block.replace(line, "", 1)
    return source[:start] + block + source[end:]


WORKER_MAIN = r'''
static void *
chacha_parallel_worker_main(void *opaque)
{
    chacha_parallel_worker_t *worker = (chacha_parallel_worker_t *)opaque;
    chacha_parallel_pool_t *pool = worker->pool;
    unsigned long long seen_generation = 0;
#if defined(__linux__)
    char thread_name[16];
    (void)snprintf(thread_name, sizeof(thread_name), "chacha-dec%u",
                   worker->index);
    (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return NULL;

    while(!pool->stopping) {
        chacha_ctx local_state;
        const u8 *source;
        u8 *destination;
        u8 *padding_length_out;
        u_int offset;
        u_int destination_offset;
        u_int length;
        unsigned int task_kind;
        unsigned int measure_decrypt;
        unsigned long long decrypt_started_ns = 0ULL;
        unsigned long long decrypt_ended_ns = 0ULL;

        memset(&local_state, 0, sizeof(local_state));
        while(!pool->stopping && seen_generation == pool->generation) {
            int wait_rc = pthread_cond_wait(&pool->work_ready, &pool->mutex);
            if(wait_rc != 0) {
                pool->worker_error = (unsigned int)wait_rc;
                pool->stopping = 1U;
                (void)pthread_cond_broadcast(&pool->work_ready);
                (void)pthread_cond_broadcast(&pool->work_done);
                break;
            }
        }
        if(pool->stopping)
            break;

        seen_generation = pool->generation;
        task_kind = pool->task_kind[worker->index];
        source = pool->source;
        destination = pool->destination;
        offset = pool->offsets[worker->index];
        destination_offset = pool->destination_offsets[worker->index];
        length = pool->lengths[worker->index];
        padding_length_out = pool->padding_length_out;
        measure_decrypt = pool->measure_decrypt;
        if(task_kind == CHACHA_TASK_DECRYPT ||
           task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST)
            local_state = pool->states[worker->index];
        pool->active_workers++;

        (void)pthread_mutex_unlock(&pool->mutex);
        if(measure_decrypt &&
           (task_kind == CHACHA_TASK_DECRYPT ||
            task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST))
            decrypt_started_ns = chacha_parallel_now_ns();

        if(task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST) {
            u8 zero_block[CHACHA_BLOCKLEN] = { 0 };
            u8 first_keystream[CHACHA_BLOCKLEN];
            u_int i;

            /* Worker zero consumes block one and writes normalized output. */
            chacha_encrypt_bytes(&local_state, zero_block, first_keystream,
                                 CHACHA_BLOCKLEN);
            if(padding_length_out)
                *padding_length_out = (u8)(source[0] ^ first_keystream[0]);
            for(i = 1U; i < CHACHA_BLOCKLEN; i++)
                destination[i - 1U] = (u8)(source[i] ^ first_keystream[i]);
            if(length)
                chacha_encrypt_bytes(&local_state, source + offset,
                                     destination + destination_offset, length);
            chacha_parallel_wipe(zero_block, sizeof(zero_block));
            chacha_parallel_wipe(first_keystream, sizeof(first_keystream));
        }
        else if(task_kind == CHACHA_TASK_DECRYPT) {
            chacha_encrypt_bytes(&local_state, source + offset,
                                 destination + destination_offset, length);
        }

        if(decrypt_started_ns)
            decrypt_ended_ns = chacha_parallel_now_ns();
        chacha_parallel_wipe(&local_state, sizeof(local_state));
        if(pthread_mutex_lock(&pool->mutex) != 0)
            return NULL;

        if(decrypt_started_ns && decrypt_ended_ns >= decrypt_started_ns) {
            unsigned long long elapsed = decrypt_ended_ns - decrypt_started_ns;
            pool->decrypt_worker_ns += elapsed;
            if(elapsed > pool->decrypt_worker_max_ns)
                pool->decrypt_worker_max_ns = elapsed;
        }
        if(pool->active_workers > 0U)
            pool->active_workers--;
        pool->completed++;
        /* R59 has one decrypt generation; wake Owner only when all lanes finish. */
        if(pool->completed >= pool->worker_count)
            (void)pthread_cond_broadcast(&pool->work_done);
    }

    (void)pthread_mutex_unlock(&pool->mutex);
    return NULL;
}
'''


def patch(root: Path) -> None:
    required = (
        ".passwall-r52-worker-lifecycle-patched",
        ".passwall-r56-skip-padding-memmove-patched",
        ".passwall-r57-chachapoly-profile-patched",
        ".passwall-r59-inline-owner-poly1305-patched",
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise RuntimeError("r60 requires prior patches: " + ", ".join(missing))

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r60 patch is pinned to libssh2 1.11.1")

    path = root / "src/chacha.c"
    source = path.read_text()

    # Replace the worker with a decrypt-only implementation. This keeps r56
    # normalized output and r57 per-worker timing, while making thread naming
    # a one-time startup operation rather than a per-packet syscall.
    source = replace_function(
        source,
        "static void *\nchacha_parallel_worker_main(void *opaque)",
        WORKER_MAIN,
    )

    # R51 already removed the owned Poly1305 snapshot allocation and teardown.
    # R60 only removes the borrowed-pointer field and stale metadata resets that
    # remained after r59 moved authentication directly onto the Owner.
    if "malloc(CHACHA_PARALLEL_MAX_PACKET)" in source:
        raise RuntimeError(
            "unexpected Poly1305 snapshot allocation: R51 should have removed it"
        )

    # Remove obsolete state resets from the R52 stop path and R59 Owner helper.
    for line, label in (
        ("    pool->poly_input = NULL;\n", "remove stale Poly1305 pointer reset"),
        ("    pool->poly_len = 0U;\n", "remove stale Poly1305 length reset"),
        ("    pool->measure_poly = 0U;\n", "remove stale Poly1305 worker timing reset"),
    ):
        count = source.count(line)
        if count < 1:
            raise RuntimeError(label + ": no stale references found")
        source = source.replace(line, "")

    source = replace_once(
        source,
        "#define CHACHA_TASK_DECRYPT 1U\n#define CHACHA_TASK_POLY1305 2U",
        "#define CHACHA_TASK_DECRYPT 1U",
        "remove obsolete Poly1305 worker task kind",
    )
    source = patch_pool_struct(source)

    if "pool->poly_input" in source or "pool->poly_len" in source or \
       "pool->measure_poly" in source or "CHACHA_TASK_POLY1305" in source:
        raise RuntimeError("r60 left obsolete Poly1305 worker state in chacha.c")
    if "malloc(CHACHA_PARALLEL_MAX_PACKET)" in source:
        raise RuntimeError("r60 still allocates the obsolete Poly1305 snapshot")
    worker = extract_worker(source)
    if "poly1305_auth" in worker:
        raise RuntimeError("r60 worker still contains a Poly1305 execution path")

    path.write_text(source)
    marker = root / ".passwall-r60-worker-hotpath-cleanup-patched"
    marker.write_text(
        "libssh2 1.11.1 Passwall r60 decrypt-only worker pool and hot-path cleanup\n"
    )
    print(
        "PASS: r60 removes the unused Poly1305 worker/snapshot path, keeps "
        "authenticate-before-decrypt, names threads once, and signals only "
        "after the complete decrypt generation"
    )


def extract_worker(source: str) -> str:
    start = source.find("static void *\nchacha_parallel_worker_main(void *opaque)")
    if start < 0:
        raise RuntimeError("r60 worker function missing")
    brace = source.find("{", start)
    end = find_matching_brace(source, brace)
    return source[start:end]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: apply_libssh2_r60_worker_hotpath_cleanup.py LIBSSH2_SOURCE_DIR",
              file=sys.stderr)
        sys.exit(2)
    patch(Path(sys.argv[1]))
