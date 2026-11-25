#!/usr/bin/env python3
"""Passwall r59: execute Poly1305 on the SSH Owner before one decrypt dispatch."""
from pathlib import Path
import sys


def find_function(source: str, signature: str):
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one function {signature!r}")
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
                return start, i + 1, source[start:i + 1]
        i += 1
    raise RuntimeError("unterminated C function")


R59_FUNCTION = r'''
/*
 * r59: authenticate the original wire packet directly on the SSH Owner,
 * before any destination byte or padding-length result is written. This
 * removes the Poly1305-only worker broadcast/barrier. After the constant-time
 * tag check succeeds, all persistent workers receive one decrypt dispatch.
 *
 * Return 1 on authenticated worker-only decrypt, 0 for serial/fallback handling,
 * -2 for an invalid tag, and -1 for a pool/worker failure.
 */
int
chacha_decrypt_poly_worker_only(struct chacha_parallel_pool *opaque_pool,
                                const struct chacha_ctx *base_state,
                                const u_char *source, u_char *destination,
                                u_int bytes, u_int aadlen, u_int dest_aadlen,
                                unsigned int skip_first,
                                u_char *padding_length_out,
                                const u_char poly_key[POLY1305_KEYLEN],
                                const u_char wire_tag[POLY1305_TAGLEN],
                                unsigned long long *poly_ns_out,
                                unsigned long long *poly_wall_ns_out,
                                unsigned long long *decrypt_wall_ns_out,
                                unsigned long long *decrypt_worker_ns_out,
                                unsigned long long *decrypt_worker_max_ns_out,
                                int measure)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int workers, worker;
    uint64_t total_blocks, decrypt_bytes;
    size_t poly_len;
    unsigned int tag_diff = 0U;
    unsigned long long poly_wall_started_ns = 0ULL;
    unsigned long long poly_wall_ended_ns = 0ULL;
    unsigned long long decrypt_wall_started_ns = 0ULL;
    unsigned long long decrypt_wall_ended_ns = 0ULL;
    int rc = -1;

    if(!pool || !base_state || !source || !destination || !poly_key ||
       !wire_tag || bytes < 4096U)
        return 0;
    if(dest_aadlen != 0U && dest_aadlen != aadlen)
        return 0;
    if(skip_first && (dest_aadlen != 0U || !padding_length_out ||
                      bytes < CHACHA_BLOCKLEN))
        return 0;
    if(!skip_first && padding_length_out)
        return 0;

    workers = pool->worker_count;
    if(workers < 2U || workers > CHACHA_PARALLEL_MAX_WORKERS)
        return 0;

    poly_len = (size_t)aadlen + (size_t)bytes;
    if(poly_len > CHACHA_PARALLEL_MAX_PACKET)
        return 0;

    decrypt_bytes = skip_first ? (uint64_t)(bytes - CHACHA_BLOCKLEN) :
                                 (uint64_t)bytes;
    total_blocks = (decrypt_bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(total_blocks < workers)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    pool->poly_input = NULL;
    pool->poly_len = 0U;
    memcpy(pool->poly_key, poly_key, POLY1305_KEYLEN);
    pool->poly_ns = 0ULL;
    pool->poly_wall_ns = 0ULL;
    pool->decrypt_wall_ns = 0ULL;
    pool->decrypt_worker_ns = 0ULL;
    pool->decrypt_worker_max_ns = 0ULL;
    pool->measure_poly = 0U;
    pool->measure_decrypt = measure ? 1U : 0U;
    pool->source = NULL;
    pool->destination = NULL;
    pool->padding_length_out = NULL;
    pool->completed = 0U;

    /*
     * Phase one is now a direct Owner call: the persistent workers remain
     * asleep, so there is no Poly1305 task broadcast or empty-worker barrier.
     * Both legacy Poly1305 timing counters deliberately measure this same
     * direct operation, preserving the existing diagnostic field names.
     */
    if(measure)
        poly_wall_started_ns = chacha_parallel_now_ns();
    poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);
    if(measure) {
        poly_wall_ended_ns = chacha_parallel_now_ns();
        if(poly_wall_started_ns &&
           poly_wall_ended_ns >= poly_wall_started_ns) {
            unsigned long long elapsed =
                poly_wall_ended_ns - poly_wall_started_ns;
            pool->poly_ns = elapsed;
            pool->poly_wall_ns = elapsed;
        }
    }
    if(poly_ns_out)
        *poly_ns_out = pool->poly_ns;
    if(poly_wall_ns_out)
        *poly_wall_ns_out = pool->poly_wall_ns;

    for(worker = 0U; worker < POLY1305_TAGLEN; worker++)
        tag_diff |= (unsigned int)(pool->poly_tag[worker] ^ wire_tag[worker]);
    if(tag_diff != 0U) {
        /* Authentication failed: no decrypt task and no destination write. */
        rc = -2;
        goto cleanup;
    }

    /* Phase two starts only after the constant-time tag comparison succeeds. */
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    pool->source = source + aadlen;
    pool->destination = destination + dest_aadlen;
    pool->padding_length_out = skip_first ? padding_length_out : NULL;
    pool->completed = 0U;

    for(worker = 0U; worker < workers; worker++) {
        uint64_t first_block =
            (total_blocks * (uint64_t)worker) / workers;
        uint64_t end_block =
            (total_blocks * (uint64_t)(worker + 1U)) / workers;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > decrypt_bytes)
            end_byte = decrypt_bytes;

        if(skip_first) {
            pool->task_kind[worker] = worker == 0U ?
                CHACHA_TASK_DECRYPT_SKIP_FIRST : CHACHA_TASK_DECRYPT;
            pool->offsets[worker] =
                CHACHA_BLOCKLEN + (u_int)(first_block * CHACHA_BLOCKLEN);
            pool->destination_offsets[worker] =
                (CHACHA_BLOCKLEN - 1U) +
                (u_int)(first_block * CHACHA_BLOCKLEN);
            pool->lengths[worker] =
                (u_int)(end_byte - first_block * CHACHA_BLOCKLEN);
            pool->states[worker] = *base_state;
            counter = (uint64_t)base_state->input[12] |
                      ((uint64_t)base_state->input[13] << 32);
            if(worker != 0U)
                counter += 1U + first_block;
        }
        else {
            pool->task_kind[worker] = CHACHA_TASK_DECRYPT;
            pool->offsets[worker] = (u_int)(first_block * CHACHA_BLOCKLEN);
            pool->destination_offsets[worker] = pool->offsets[worker];
            pool->lengths[worker] =
                (u_int)(end_byte - pool->offsets[worker]);
            pool->states[worker] = *base_state;
            counter = (uint64_t)base_state->input[12] |
                      ((uint64_t)base_state->input[13] << 32);
            counter += first_block;
        }

        pool->states[worker].input[12] = (u32)counter;
        pool->states[worker].input[13] = (u32)(counter >> 32);
    }

    if(measure)
        decrypt_wall_started_ns = chacha_parallel_now_ns();
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
        (void)pthread_mutex_unlock(&pool->mutex);
        (void)chacha_parallel_pool_stop(pool);
        return -1;
    }

    if(measure) {
        decrypt_wall_ended_ns = chacha_parallel_now_ns();
        if(decrypt_wall_started_ns &&
           decrypt_wall_ended_ns >= decrypt_wall_started_ns)
            pool->decrypt_wall_ns =
                decrypt_wall_ended_ns - decrypt_wall_started_ns;
    }
    if(decrypt_wall_ns_out)
        *decrypt_wall_ns_out = pool->decrypt_wall_ns;
    if(decrypt_worker_ns_out)
        *decrypt_worker_ns_out = pool->decrypt_worker_ns;
    if(decrypt_worker_max_ns_out)
        *decrypt_worker_max_ns_out = pool->decrypt_worker_max_ns;

    rc = 1;

cleanup:
    pool->source = NULL;
    pool->destination = NULL;
    pool->padding_length_out = NULL;
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    pool->measure_decrypt = 0U;
    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));
    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));
    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    memset(pool->offsets, 0, sizeof(pool->offsets));
    memset(pool->destination_offsets, 0, sizeof(pool->destination_offsets));
    memset(pool->lengths, 0, sizeof(pool->lengths));
    for(worker = 0U; worker < workers; worker++)
        pool->task_kind[worker] = CHACHA_TASK_IDLE;
    (void)pthread_mutex_unlock(&pool->mutex);
    return rc;
}
'''


def patch(root: Path) -> None:
    required = (
        ".passwall-r56-skip-padding-memmove-patched",
        ".passwall-r57-chachapoly-profile-patched",
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise RuntimeError("r59 requires prior patches: " + ", ".join(missing))

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r59 patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r59-inline-owner-poly1305-patched"
    if marker.exists():
        raise RuntimeError("r59 inline Owner Poly1305 patch is already present")

    chacha_c = root / "src/chacha.c"
    source = chacha_c.read_text()
    signature = "int\nchacha_decrypt_poly_worker_only("
    start, end, previous = find_function(source, signature)

    if "unsigned long long *poly_wall_ns_out" not in previous:
        raise RuntimeError("r59 requires the r57 phase timing function signature")
    if previous.count("pool->generation++") != 2:
        raise RuntimeError(
            "r59 expected the existing two-phase Poly1305/decrypt worker dispatch"
        )
    if "CHACHA_TASK_DECRYPT_SKIP_FIRST" not in previous:
        raise RuntimeError("r59 requires the r56 normalized-output worker path")

    updated = R59_FUNCTION.strip()
    if updated.count("pool->generation++") != 1:
        raise RuntimeError("r59 must leave exactly one worker-pool generation dispatch")
    if "poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);" not in updated:
        raise RuntimeError("r59 direct Owner Poly1305 call is missing")
    auth = updated.find("poly1305_auth(pool->poly_tag, source, poly_len, pool->poly_key);")
    tag = updated.find("if(tag_diff != 0U)")
    decrypt = updated.find("pool->task_kind[worker] = worker == 0U ?")
    if not (0 <= auth < tag < decrypt):
        raise RuntimeError("r59 must authenticate and compare the tag before decrypt dispatch")

    chacha_c.write_text(source[:start] + updated + source[end:])
    marker.write_text(
        ".passwall-r59-inline-owner-poly1305-patched\n"
        "libssh2 1.11.1 Passwall r59 inline Owner Poly1305 before one decrypt dispatch\n"
    )
    print(
        "PASS: r59 computes Poly1305 on the Owner, checks the tag, then broadcasts "
        "one decrypt task generation to all persistent workers"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: apply_libssh2_r59_inline_poly1305.py LIBSSH2_SOURCE_DIR"
        )
    patch(Path(sys.argv[1]))
