#!/usr/bin/env python3
"""Passwall r51: authenticate ChaCha20-Poly1305 before dispatching decrypt workers."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


R51_FUNCTION = r'''
/*
 * r51: authenticate the complete ciphertext before any worker writes plaintext.
 * Phase one assigns a Poly1305 task to one persistent worker and idle tasks to
 * the others. Only after the Owner compares the complete tag does phase two
 * dispatch disjoint ChaCha20 ranges to every worker.
 *
 * The MAC worker reads directly from the packet's ciphertext; no scratch copy
 * is needed because the packet remains untouched throughout phase one.
 *
 * Return 1 on authenticated worker-only decrypt, 0 for serial/fallback handling,
 * -2 for an invalid tag, and -1 for a pool/worker failure.
 */
int
chacha_decrypt_poly_worker_only(struct chacha_parallel_pool *opaque_pool,
                                const struct chacha_ctx *base_state,
                                const u_char *source, u_char *destination,
                                u_int bytes, u_int aadlen,
                                const u_char poly_key[POLY1305_KEYLEN],
                                const u_char wire_tag[POLY1305_TAGLEN],
                                unsigned long long *poly_ns_out, int measure)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int workers, worker;
    uint64_t total_blocks;
    size_t poly_len;
    unsigned int tag_diff = 0U;
    int rc = -1;

    if(!pool || !base_state || !source || !destination || !poly_key ||
       !wire_tag || bytes < 4096U)
        return 0;

    workers = pool->worker_count;
    if(workers < 2U || workers > CHACHA_PARALLEL_MAX_WORKERS)
        return 0;

    poly_len = (size_t)aadlen + (size_t)bytes;
    if(poly_len > CHACHA_PARALLEL_MAX_PACKET)
        return 0;

    total_blocks = ((uint64_t)bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(total_blocks < workers)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    /* Phase 1: Poly1305 only. Every worker receives a task, but only one
     * worker reads the ciphertext and calculates the tag. No destination
     * byte is written until the Owner has checked the tag below. */
    pool->poly_input = source;
    memcpy(pool->poly_key, poly_key, POLY1305_KEYLEN);
    pool->poly_len = poly_len;
    pool->poly_ns = 0ULL;
    pool->measure_poly = measure ? 1U : 0U;
    pool->source = NULL;
    pool->destination = NULL;
    pool->completed = 0U;

    for(worker = 0U; worker < workers; worker++) {
        pool->task_kind[worker] =
            worker == workers - 1U ? CHACHA_TASK_POLY1305 : CHACHA_TASK_IDLE;
        pool->offsets[worker] = 0U;
        pool->lengths[worker] = 0U;
        memset(&pool->states[worker], 0, sizeof(pool->states[worker]));
    }

    pool->generation++;
    (void)pthread_cond_broadcast(&pool->work_ready);

    while(pool->completed < workers && !pool->stopping) {
        int wait_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
        if(wait_rc != 0) {
            pool->worker_error = (unsigned int)wait_rc;
            pool->stopping = 1U;
            (void)pthread_cond_broadcast(&pool->work_ready);
            break;
        }
    }

    if(pool->stopping || pool->worker_error || pool->completed != workers) {
        (void)pthread_cond_broadcast(&pool->work_ready);
        while(pool->active_workers > 0U) {
            int drain_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
            if(drain_rc != 0)
                break;
        }
        if(pool->active_workers > 0U) {
            /* Do not clear the borrowed packet pointer while a worker may use it. */
            (void)pthread_mutex_unlock(&pool->mutex);
            return -1;
        }
        goto cleanup;
    }

    for(worker = 0U; worker < POLY1305_TAGLEN; worker++)
        tag_diff |= (unsigned int)(pool->poly_tag[worker] ^ wire_tag[worker]);
    if(poly_ns_out)
        *poly_ns_out = pool->poly_ns;

    if(tag_diff != 0U) {
        /* Authentication failed: return without touching destination. */
        rc = -2;
        goto cleanup;
    }

    /* Phase 2 starts only after a constant-time tag comparison succeeded. */
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    pool->source = source + aadlen;
    pool->destination = destination + aadlen;
    pool->completed = 0U;

    for(worker = 0U; worker < workers; worker++) {
        uint64_t first_block = (total_blocks * (uint64_t)worker) / workers;
        uint64_t end_block = (total_blocks * (uint64_t)(worker + 1U)) / workers;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > bytes)
            end_byte = bytes;
        pool->task_kind[worker] = CHACHA_TASK_DECRYPT;
        pool->offsets[worker] = (u_int)(first_block * CHACHA_BLOCKLEN);
        pool->lengths[worker] =
            (u_int)(end_byte - pool->offsets[worker]);
        pool->states[worker] = *base_state;

        counter = (uint64_t)base_state->input[12] |
                  ((uint64_t)base_state->input[13] << 32);
        counter += first_block;
        pool->states[worker].input[12] = (u32)counter;
        pool->states[worker].input[13] = (u32)(counter >> 32);
    }

    pool->generation++;
    (void)pthread_cond_broadcast(&pool->work_ready);

    while(pool->completed < workers && !pool->stopping) {
        int wait_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
        if(wait_rc != 0) {
            pool->worker_error = (unsigned int)wait_rc;
            pool->stopping = 1U;
            (void)pthread_cond_broadcast(&pool->work_ready);
            break;
        }
    }

    if(pool->stopping || pool->worker_error || pool->completed != workers) {
        (void)pthread_cond_broadcast(&pool->work_ready);
        while(pool->active_workers > 0U) {
            int drain_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
            if(drain_rc != 0)
                break;
        }
        if(pool->active_workers > 0U) {
            (void)pthread_mutex_unlock(&pool->mutex);
            return -1;
        }
        goto cleanup;
    }

    rc = 1;

cleanup:
    pool->source = NULL;
    pool->destination = NULL;
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));
    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));
    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    memset(pool->offsets, 0, sizeof(pool->offsets));
    memset(pool->lengths, 0, sizeof(pool->lengths));
    for(worker = 0U; worker < workers; worker++)
        pool->task_kind[worker] = CHACHA_TASK_IDLE;
    (void)pthread_mutex_unlock(&pool->mutex);
    return rc;
}
'''


def replace_r49_function(chacha_c: Path) -> None:
    source = chacha_c.read_text()
    marker = "/*\n * r49: the Owner dispatches all crypto work and performs no payload transform."
    if source.count(marker) != 1:
        raise RuntimeError("chacha.c: expected exactly one r49 worker-only function marker")
    start = source.find(marker)
    signature = "int\nchacha_decrypt_poly_worker_only("
    if source.count(signature) != 1 or source.find(signature) < start:
        raise RuntimeError("chacha.c: expected exactly one r49 worker-only function")
    function_start = source.find(signature, start)
    function_end = source.find("\n}\n", function_start)
    if function_end < 0:
        raise RuntimeError("chacha.c: cannot locate worker-only function end")
    end = function_end + len("\n}\n")
    if source[end:].strip():
        raise RuntimeError("chacha.c: unexpected content follows the r49 worker-only function")
    chacha_c.write_text(source[:start] + R51_FUNCTION.lstrip() + "\n")


def patch(root: Path) -> None:
    if not (root / ".passwall-r49-poly1305-worker-overlap-patched").is_file():
        raise RuntimeError("Run r49 Poly1305 worker patch first")
    marker = root / ".passwall-r51-auth-before-decrypt-patched"
    if marker.exists():
        raise RuntimeError("r51 authenticate-before-decrypt patch is already present")

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r51 patch is pinned to libssh2 1.11.1")

    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        "    u8 *poly_input;\n",
        "    const u8 *poly_input;\n",
        "make Poly1305 input a borrowed read-only packet pointer"
    )
    replace_once(
        chacha_c,
        "    if(pool->poly_input) {\n"
        "        chacha_parallel_wipe(pool->poly_input, CHACHA_PARALLEL_MAX_PACKET);\n"
        "        free(pool->poly_input);\n"
        "        pool->poly_input = NULL;\n"
        "    }\n",
        "",
        "remove owned Poly1305 snapshot teardown"
    )
    replace_once(
        chacha_c,
        "    pool->poly_input = (u8 *)malloc(CHACHA_PARALLEL_MAX_PACKET);\n"
        "    if(!pool->poly_input) {\n"
        "        free(pool);\n"
        "        errno = ENOMEM;\n"
        "        return NULL;\n"
        "    }\n\n",
        "",
        "remove per-pool packet snapshot allocation"
    )

    replace_r49_function(chacha_c)

    marker.write_text(
        "libssh2 1.11.1 Passwall r51 authenticate-before-decrypt worker phases\n"
    )
    print(
        "PASS: r51 authenticates the original ciphertext before dispatching any "
        "ChaCha20 decrypt task; Poly1305 reads the packet directly without a snapshot"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r51_auth_then_decrypt.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
