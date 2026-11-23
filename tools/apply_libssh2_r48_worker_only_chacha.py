#!/usr/bin/env python3
"""Convert r47 ChaCha payload lanes to worker-only r48 execution."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


NEW_FUNCTION = r'''
/*
 * Passwall r48: all ChaCha20 payload lanes run on persistent workers.
 * The SSH Owner dispatches the packet and waits; it does no payload crypto.
 * The caller must authenticate the complete packet before dispatch.
 * Return 1 when worker-only parallel work ran, 0 for the serial fallback,
 * and -1 if the worker pool cannot complete the dispatched packet.
 */
int
chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *opaque_pool,
                              const struct chacha_ctx *base_state,
                              const u_char *source, u_char *destination,
                              u_int bytes)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int workers, lane;
    uint64_t total_blocks;
    int rc = 0;

    if(!pool || !base_state || !source || !destination ||
       bytes < 4096U)
        return 0;

    workers = pool->worker_count;
    total_blocks = ((uint64_t)bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(workers == 0U || total_blocks < workers)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    pool->source = source;
    pool->destination = destination;
    pool->completed = 0U;

    for(lane = 0U; lane < workers; lane++) {
        uint64_t first_block = (total_blocks * lane) / workers;
        uint64_t end_block = (total_blocks * (lane + 1U)) / workers;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > bytes)
            end_byte = bytes;
        pool->offsets[lane] = (u_int)(first_block * CHACHA_BLOCKLEN);
        pool->lengths[lane] =
            (u_int)(end_byte - pool->offsets[lane]);
        pool->states[lane] = *base_state;

        counter = (uint64_t)base_state->input[12] |
                  ((uint64_t)base_state->input[13] << 32);
        counter += first_block;
        pool->states[lane].input[12] = (u32)counter;
        pool->states[lane].input[13] = (u32)(counter >> 32);
    }

    pool->generation++;
    (void)pthread_cond_broadcast(&pool->work_ready);

    /*
     * pthread_cond_wait releases the mutex while workers transform the
     * payload. No ChaCha20 payload blocks are processed by this Owner thread.
     */
    while(pool->completed < workers && !pool->stopping) {
        rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
        if(rc != 0) {
            pool->worker_error = (unsigned int)rc;
            pool->stopping = 1U;
            (void)pthread_cond_broadcast(&pool->work_ready);
            break;
        }
    }

    if(pool->stopping || pool->worker_error ||
       pool->completed != workers)
        rc = -1;

    pool->source = NULL;
    pool->destination = NULL;
    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    memset(pool->offsets, 0, sizeof(pool->offsets));
    memset(pool->lengths, 0, sizeof(pool->lengths));
    (void)pthread_mutex_unlock(&pool->mutex);
    return rc == 0 ? 1 : -1;
}
'''


def patch(root: Path) -> None:
    if not (root / ".passwall-r47-parallel-chacha-patched").is_file():
        raise RuntimeError("Run apply_libssh2_r47_parallel_chacha.py first")
    marker = root / ".passwall-r48-worker-only-chacha-patched"
    if marker.exists():
        raise RuntimeError("r48 worker-only ChaCha patch is already present")

    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        "#define CHACHA_PARALLEL_MAX_WORKERS 3U",
        "#define CHACHA_PARALLEL_MAX_WORKERS 4U",
        "increase pool capacity to four workers"
    )
    source = chacha_c.read_text()
    start_marker = "/*\n * Run lane zero on the SSH Owner and the remaining lanes on persistent\n"
    end_marker = "    return rc == 0 ? 1 : -1;\n}"
    if source.count(start_marker) != 1:
        raise RuntimeError("chacha.c: expected one r47 Owner-plus-workers function")
    start = source.index(start_marker)
    end = source.index(end_marker, start) + len(end_marker)
    source = source[:start] + NEW_FUNCTION.strip("\n") + source[end:]
    chacha_c.write_text(source)

    session_c = root / "src/session.c"
    replace_once(
        session_c,
        "if(workers > 3U)\n        workers = 3U;",
        "if(workers > 4U)\n        workers = 4U;",
        "allow four persistent ChaCha workers"
    )

    marker.write_text(
        "libssh2 1.11.1 Passwall r48 worker-only packet-local ChaCha20\n"
    )
    print(
        "PASS: r48 assigns every ChaCha20 payload lane to up to four persistent "
        "workers; the SSH Owner only dispatches and waits"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError(
            "usage: apply_libssh2_r48_worker_only_chacha.py "
            "<libssh2-1.11.1-source-dir>"
        )
    patch(Path(sys.argv[1]).resolve())
