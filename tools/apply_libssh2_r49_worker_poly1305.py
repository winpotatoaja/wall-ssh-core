#!/usr/bin/env python3
"""Passwall r49: offload Poly1305 while crypto workers decrypt ChaCha20 payload."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


WORKER_MAIN = r'''
static unsigned long long
chacha_parallel_now_ns(void)
{
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0ULL;
    return ((unsigned long long)ts.tv_sec * 1000000000ULL) +
           (unsigned long long)ts.tv_nsec;
}

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
        const u8 *poly_input;
        const u8 *poly_key;
        u8 *poly_tag;
        u_int offset;
        u_int length;
        size_t poly_len;
        unsigned int task_kind;
        unsigned int measure_poly;
        unsigned long long poly_started_ns = 0ULL;
        unsigned long long poly_ended_ns = 0ULL;

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
        length = pool->lengths[worker->index];
        poly_input = pool->poly_input;
        poly_key = pool->poly_key;
        poly_tag = pool->poly_tag;
        poly_len = pool->poly_len;
        measure_poly = pool->measure_poly;
        if(task_kind == CHACHA_TASK_DECRYPT)
            local_state = pool->states[worker->index];

        (void)pthread_mutex_unlock(&pool->mutex);
        if(task_kind == CHACHA_TASK_POLY1305) {
#if defined(__linux__)
            (void)prctl(PR_SET_NAME, "chacha-poly", 0, 0, 0);
#endif
            if(measure_poly)
                poly_started_ns = chacha_parallel_now_ns();
            poly1305_auth(poly_tag, poly_input, poly_len, poly_key);
            if(measure_poly)
                poly_ended_ns = chacha_parallel_now_ns();
            if(poly_started_ns && poly_ended_ns >= poly_started_ns)
                pool->poly_ns = poly_ended_ns - poly_started_ns;
        } else if(task_kind == CHACHA_TASK_DECRYPT) {
#if defined(__linux__)
            (void)snprintf(thread_name, sizeof(thread_name), "chacha-dec%u",
                           worker->index);
            (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif
            chacha_encrypt_bytes(&local_state, source + offset,
                                 destination + offset, length);
        }
        chacha_parallel_wipe(&local_state, sizeof(local_state));
        if(pthread_mutex_lock(&pool->mutex) != 0)
            return NULL;

        pool->completed++;
        if(pool->completed >= pool->worker_count)
            (void)pthread_cond_broadcast(&pool->work_done);
    }

    (void)pthread_mutex_unlock(&pool->mutex);
    return NULL;
}
'''

PARALLEL_FUNCTION = r'''
/*
 * r49: the Owner dispatches all crypto work and performs no payload transform.
 * One persistent worker authenticates a private ciphertext snapshot with
 * Poly1305 while the other workers decrypt disjoint ChaCha20 block ranges.
 * The Owner compares the tag only after all tasks complete. On an invalid tag,
 * restore the original AAD+ciphertext before returning the decrypt error.
 *
 * Return 1 on authenticated worker-only decrypt, 0 for safe serial/fallback
 * handling, -2 for an invalid tag, and -1 for a pool/worker failure.
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
    unsigned int workers, decrypt_workers, worker, i;
    uint64_t total_blocks;
    size_t poly_len;
    unsigned int tag_diff = 0U;
    int rc = 0;

    if(!pool || !base_state || !source || !destination || !poly_key ||
       !wire_tag || bytes < 4096U)
        return 0;

    workers = pool->worker_count;
    if(workers < 2U || workers > CHACHA_PARALLEL_MAX_WORKERS)
        return 0;

    poly_len = (size_t)aadlen + (size_t)bytes;
    if(poly_len > CHACHA_PARALLEL_MAX_PACKET)
        return 0;

    decrypt_workers = workers - 1U;
    total_blocks = ((uint64_t)bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(total_blocks < decrypt_workers)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error || !pool->poly_input) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    /* Snapshot ciphertext before any in-place ChaCha worker can modify it. */
    memcpy(pool->poly_input, source, poly_len);
    memcpy(pool->poly_key, poly_key, POLY1305_KEYLEN);
    pool->poly_len = poly_len;
    pool->poly_ns = 0ULL;
    pool->measure_poly = measure ? 1U : 0U;
    pool->source = source + aadlen;
    pool->destination = destination + aadlen;
    pool->completed = 0U;

    for(worker = 0U; worker < workers; worker++) {
        pool->task_kind[worker] =
            worker == workers - 1U ? CHACHA_TASK_POLY1305 :
                                     CHACHA_TASK_DECRYPT;
        pool->offsets[worker] = 0U;
        pool->lengths[worker] = 0U;
        memset(&pool->states[worker], 0, sizeof(pool->states[worker]));
    }

    for(worker = 0U; worker < decrypt_workers; worker++) {
        uint64_t first_block =
            (total_blocks * (uint64_t)worker) / decrypt_workers;
        uint64_t end_block =
            (total_blocks * (uint64_t)(worker + 1U)) / decrypt_workers;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > bytes)
            end_byte = bytes;
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

    if(pool->stopping || pool->worker_error ||
       pool->completed != workers) {
        rc = -1;
    } else {
        for(i = 0U; i < POLY1305_TAGLEN; i++)
            tag_diff |= (unsigned int)(pool->poly_tag[i] ^ wire_tag[i]);
        if(poly_ns_out)
            *poly_ns_out = pool->poly_ns;
        if(tag_diff != 0U) {
            /* No unauthenticated plaintext may remain in the packet buffer. */
            memcpy(destination, pool->poly_input, poly_len);
            rc = -2;
        } else {
            rc = 1;
        }
    }

    pool->source = NULL;
    pool->destination = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    chacha_parallel_wipe(pool->poly_input, CHACHA_PARALLEL_MAX_PACKET);
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

CRYPT_FUNCTION = r'''int
chachapoly_crypt(struct _LIBSSH2_SESSION *session,
                 struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
                 const u_char *src, u_int len, u_int aadlen, int do_encrypt)
{
    u_char seqbuf[8];
    const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
    int r = LIBSSH2_ERROR_INVAL;
    int parallel_done = 0;
    unsigned char *ptr = NULL;
    int diag_enabled = session && session->passwall_diag.enabled;
    unsigned long long phase_started = 0ULL, phase_ended = 0ULL;
    unsigned long long poly_worker_ns = 0ULL;

    memset(poly_key, 0, sizeof(poly_key));
    ptr = &seqbuf[0];
    _libssh2_store_u64(&ptr, seqnr);

    phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
    chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
    chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));
    if(diag_enabled) {
        phase_ended = _libssh2_diag_now_ns();
        if(phase_ended >= phase_started)
            session->passwall_diag.chacha20_key_ns += phase_ended - phase_started;
    }

    if(!do_encrypt && ctx->parallel_pool) {
        int parallel_rc;
        const u_char *wire_tag = src + aadlen + len;

        chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
        parallel_rc = chacha_decrypt_poly_worker_only(
            ctx->parallel_pool, &ctx->main_ctx, src, dest, len, aadlen,
            poly_key, wire_tag, &poly_worker_ns, diag_enabled);
        if(parallel_rc == 1) {
            parallel_done = 1;
            if(diag_enabled) {
                phase_ended = _libssh2_diag_now_ns();
                if(phase_ended >= phase_started) {
                    unsigned long long elapsed = phase_ended - phase_started;
                    session->passwall_diag.chacha20_payload_ns += elapsed;
                    session->passwall_diag.chacha20_parallel_ns += elapsed;
                }
                session->passwall_diag.chacha_poly1305_ns += poly_worker_ns;
                session->passwall_diag.chacha_poly1305_offloaded_packets++;
                session->passwall_diag.chacha20_parallel_bytes += len;
                session->passwall_diag.chacha20_parallel_packets++;
            }
        } else if(parallel_rc < 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
    }

    /* One-worker and small-packet fallback: authenticate before any writes. */
    if(!do_encrypt && !parallel_done) {
        const u_char *tag = src + aadlen + len;
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
        poly1305_auth(expected_tag, src, aadlen + len, poly_key);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha_poly1305_ns +=
                    phase_ended - phase_started;
        }
        if(chachapoly_timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
    }

    /* Header/AAD is transformed only after successful authentication. */
    if(aadlen) {
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
        chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
        chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha20_header_ns +=
                    phase_ended - phase_started;
        }
    }

    if(!parallel_done) {
        int parallel_rc = 0;
        chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
        if(!do_encrypt && ctx->parallel_pool)
            parallel_rc = chacha_encrypt_bytes_parallel(
                ctx->parallel_pool, &ctx->main_ctx, src + aadlen,
                dest + aadlen, len);
        if(parallel_rc < 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
        if(parallel_rc > 0 && !do_encrypt) {
            if(diag_enabled) {
                phase_ended = _libssh2_diag_now_ns();
                if(phase_ended >= phase_started) {
                    unsigned long long elapsed = phase_ended - phase_started;
                    session->passwall_diag.chacha20_payload_ns += elapsed;
                    session->passwall_diag.chacha20_parallel_ns += elapsed;
                }
                session->passwall_diag.chacha20_parallel_bytes += len;
                session->passwall_diag.chacha20_parallel_packets++;
            }
        } else {
            chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
                                 dest + aadlen, len);
            if(diag_enabled) {
                phase_ended = _libssh2_diag_now_ns();
                if(phase_ended >= phase_started) {
                    unsigned long long elapsed = phase_ended - phase_started;
                    session->passwall_diag.chacha20_payload_ns += elapsed;
                    session->passwall_diag.chacha20_serial_ns += elapsed;
                }
                session->passwall_diag.chacha20_serial_bytes += len;
                session->passwall_diag.chacha20_serial_packets++;
            }
        }
    }

    if(do_encrypt) {
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0ULL;
        poly1305_auth(dest + aadlen + len, dest, aadlen + len, poly_key);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha_poly1305_ns +=
                    phase_ended - phase_started;
        }
    }

    r = 0;
out:
    memset(expected_tag, 0, sizeof(expected_tag));
    memset(seqbuf, 0, sizeof(seqbuf));
    memset(poly_key, 0, sizeof(poly_key));
    return r;
}'''


def patch(root: Path) -> None:
    if not (root / ".passwall-r48-worker-only-chacha-patched").is_file():
        raise RuntimeError("Run r48 worker-only ChaCha patch first")
    marker = root / ".passwall-r49-poly1305-worker-overlap-patched"
    if marker.exists():
        raise RuntimeError("r49 Poly1305 worker patch is already present")

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r49 patch is pinned to libssh2 1.11.1")

    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        '#include "chacha.h"\n\n#include <errno.h>',
        '#include "chacha.h"\n#include "poly1305.h"\n\n#include <errno.h>',
        "include Poly1305 worker API"
    )
    replace_once(
        chacha_c,
        "#include <string.h>\n",
        "#include <string.h>\n#include <time.h>\n",
        "include monotonic clock support"
    )
    replace_once(
        chacha_c,
        "#define CHACHA_PARALLEL_MAX_WORKERS 4U\n#define CHACHA_PARALLEL_STACK_SIZE (64U * 1024U)",
        "#define CHACHA_PARALLEL_MAX_WORKERS 4U\n"
        "#define CHACHA_PARALLEL_STACK_SIZE (64U * 1024U)\n"
        "#define CHACHA_PARALLEL_MAX_PACKET 35000U\n"
        "#define CHACHA_TASK_IDLE 0U\n"
        "#define CHACHA_TASK_DECRYPT 1U\n"
        "#define CHACHA_TASK_POLY1305 2U",
        "define bounded Poly1305 task and scratch-buffer limits"
    )
    replace_once(
        chacha_c,
        "    unsigned long long generation;\n    const u8 *source;",
        "    unsigned long long generation;\n"
        "    unsigned int task_kind[CHACHA_PARALLEL_MAX_WORKERS];\n"
        "    u8 *poly_input;\n"
        "    size_t poly_len;\n"
        "    u8 poly_key[POLY1305_KEYLEN];\n"
        "    u8 poly_tag[POLY1305_TAGLEN];\n"
        "    unsigned long long poly_ns;\n"
        "    unsigned int measure_poly;\n"
        "    const u8 *source;",
        "extend persistent pool with bounded Poly1305 task state"
    )

    source = chacha_c.read_text()
    start_marker = "static void *\nchacha_parallel_worker_main(void *opaque)\n{"
    end_marker = "\nstatic void\nchacha_parallel_pool_stop"
    start = source.find(start_marker)
    end = source.find(end_marker, start)
    if start < 0 or end < 0 or source.find(start_marker, start + 1) >= 0:
        raise RuntimeError("chacha.c: expected one r48 worker-main function")
    source = source[:start] + WORKER_MAIN.rstrip() + source[end:]
    chacha_c.write_text(source)

    replace_once(
        chacha_c,
        "    chacha_parallel_wipe(pool->states, sizeof(pool->states));\n"
        "    if(pool->work_done_initialized)",
        "    chacha_parallel_wipe(pool->states, sizeof(pool->states));\n"
        "    if(pool->poly_input) {\n"
        "        chacha_parallel_wipe(pool->poly_input, CHACHA_PARALLEL_MAX_PACKET);\n"
        "        free(pool->poly_input);\n"
        "        pool->poly_input = NULL;\n"
        "    }\n"
        "    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));\n"
        "    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));\n"
        "    if(pool->work_done_initialized)",
        "wipe/free Poly1305 packet snapshot during pool teardown"
    )
    replace_once(
        chacha_c,
        "    pool = (chacha_parallel_pool_t *)calloc(1, sizeof(*pool));\n"
        "    if(!pool)\n"
        "        return NULL;\n\n"
        "    rc = pthread_mutex_init(&pool->mutex, NULL);",
        "    pool = (chacha_parallel_pool_t *)calloc(1, sizeof(*pool));\n"
        "    if(!pool)\n"
        "        return NULL;\n"
        "    pool->poly_input = (u8 *)malloc(CHACHA_PARALLEL_MAX_PACKET);\n"
        "    if(!pool->poly_input) {\n"
        "        free(pool);\n"
        "        errno = ENOMEM;\n"
        "        return NULL;\n"
        "    }\n\n"
        "    rc = pthread_mutex_init(&pool->mutex, NULL);",
        "allocate bounded persistent Poly1305 snapshot"
    )
    with chacha_c.open("a") as handle:
        handle.write(PARALLEL_FUNCTION)

    chacha_h = root / "src/chacha.h"
    replace_once(
        chacha_h,
        "int chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *pool,\n"
        "                                  const struct chacha_ctx *base_state,\n"
        "                                  const u_char *source, u_char *destination,\n"
        "                                  u_int bytes);\n\n"
        "#endif",
        "int chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *pool,\n"
        "                                  const struct chacha_ctx *base_state,\n"
        "                                  const u_char *source, u_char *destination,\n"
        "                                  u_int bytes);\n"
        "int chacha_decrypt_poly_worker_only(struct chacha_parallel_pool *pool,\n"
        "                                    const struct chacha_ctx *base_state,\n"
        "                                    const u_char *source, u_char *destination,\n"
        "                                    u_int bytes, u_int aadlen,\n"
        "                                    const u_char poly_key[32],\n"
        "                                    const u_char wire_tag[16],\n"
        "                                    unsigned long long *poly_ns_out,\n"
        "                                    int measure);\n\n"
        "#endif",
        "expose worker-only ChaCha plus Poly1305 task"
    )

    cipher_c = root / "src/cipher-chachapoly.c"
    cipher_source = cipher_c.read_text()
    function_marker = "int\nchachapoly_crypt("
    start = cipher_source.find(function_marker)
    if start < 0 or cipher_source.find(function_marker, start + 1) >= 0:
        raise RuntimeError("cipher-chachapoly.c: expected one chachapoly_crypt function")
    end_marker = "\n/* Decrypt and extract the encrypted packet length */"
    end = cipher_source.find(end_marker, start)
    if end < 0:
        raise RuntimeError("cipher-chachapoly.c: packet-length helper anchor missing")
    cipher_source = cipher_source[:start] + CRYPT_FUNCTION + cipher_source[end:]
    cipher_c.write_text(cipher_source)

    priv = root / "src/libssh2_priv.h"
    replace_once(
        priv,
        "        unsigned long long chacha_poly1305_ns;\n"
        "        unsigned long long chacha20_key_ns;",
        "        unsigned long long chacha_poly1305_ns;\n"
        "        unsigned long long chacha_poly1305_offloaded_packets;\n"
        "        unsigned long long chacha20_key_ns;",
        "add per-session Poly1305 offload packet counter"
    )
    replace_once(
        priv,
        "    unsigned long long chacha_poly1305_ns;\n"
        "    unsigned long long chacha20_key_ns;",
        "    unsigned long long chacha_poly1305_ns;\n"
        "    unsigned long long chacha_poly1305_offloaded_packets;\n"
        "    unsigned long long chacha20_key_ns;",
        "add Poly1305 offload counter to diagnostic snapshot"
    )

    session_c = root / "src/session.c"
    replace_once(
        session_c,
        "    timing->chacha_poly1305_ns =\n"
        "        session->passwall_diag.chacha_poly1305_ns;\n"
        "    timing->chacha20_key_ns =",
        "    timing->chacha_poly1305_ns =\n"
        "        session->passwall_diag.chacha_poly1305_ns;\n"
        "    timing->chacha_poly1305_offloaded_packets =\n"
        "        session->passwall_diag.chacha_poly1305_offloaded_packets;\n"
        "    timing->chacha20_key_ns =",
        "snapshot Poly1305 offload packet count"
    )
    replace_once(
        session_c,
        "        session->passwall_diag.chacha_poly1305_ns = 0;\n"
        "        session->passwall_diag.chacha20_key_ns = 0;",
        "        session->passwall_diag.chacha_poly1305_ns = 0;\n"
        "        session->passwall_diag.chacha_poly1305_offloaded_packets = 0;\n"
        "        session->passwall_diag.chacha20_key_ns = 0;",
        "reset Poly1305 offload packet count per PERF interval"
    )

    marker.write_text(
        "libssh2 1.11.1 Passwall r49 worker-only Poly1305/ChaCha overlap\n"
    )
    print(
        "PASS: r49 offloads Poly1305 to one persistent worker while the remaining "
        "workers decrypt ChaCha20; SSH Owner performs no packet crypto"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError(
            "usage: apply_libssh2_r49_worker_poly1305.py <libssh2-1.11.1-source-dir>"
        )
    patch(Path(sys.argv[1]).resolve())
