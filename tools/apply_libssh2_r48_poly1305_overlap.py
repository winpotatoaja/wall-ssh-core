#!/usr/bin/env python3
"""Add r48 overlapped Poly1305 verification and ChaCha20 packet decryption."""
from pathlib import Path
import sys

def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))

PARALLEL_FUNCTION = r'''
/*
 * R48: overlap Poly1305 verification on the final worker with ChaCha20
 * decryption on the Owner and the other workers. Poly1305 reads a private
 * ciphertext snapshot while ChaCha transforms the original packet in place.
 * The original packet is restored on authentication failure.
 *
 * Return 1 on authenticated parallel decrypt, 0 when the caller should use
 * the serial path, -2 for an invalid tag, and -1 for a worker/pool failure.
 */
int
chacha_decrypt_poly_parallel(struct chacha_parallel_pool *opaque_pool,
                             const struct chacha_ctx *base_state,
                             const u_char *source, u_char *destination,
                             u_int bytes, u_int aadlen, size_t poly_len,
                             const u_char poly_key[POLY1305_KEYLEN],
                             const u_char wire_tag[POLY1305_TAGLEN],
                             unsigned long long *poly_ns_out, int measure)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int workers, decrypt_workers, lanes, lane, i;
    uint64_t total_blocks, owner_end_block;
    u_int owner_length;
    chacha_ctx owner_state;
    int rc = 0;
    unsigned int tag_diff = 0U;

    if(!pool || !base_state || !source || !destination || !poly_key ||
       !wire_tag || bytes < 4096U ||
       poly_len != (size_t)aadlen + (size_t)bytes ||
       poly_len > CHACHA_PARALLEL_MAX_PACKET)
        return 0;

    workers = pool->worker_count;
    if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS)
        return 0;

    /* Keep the last worker for Poly1305; other lanes transform ChaCha. */
    decrypt_workers = workers - 1U;
    lanes = decrypt_workers + 1U;
    total_blocks = ((uint64_t)bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(total_blocks < lanes)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error || !pool->poly_input) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    /* Preserve the ciphertext, AAD and tag source before in-place writes. */
    memcpy(pool->poly_input, source, poly_len);
    memcpy(pool->poly_key, poly_key, POLY1305_KEYLEN);
    pool->poly_len = poly_len;
    pool->poly_ns = 0ULL;
    pool->measure_poly = measure ? 1U : 0U;
    pool->source = source;
    pool->destination = destination;
    pool->completed = 0U;
    for(i = 0U; i < workers; i++)
        pool->task_kind[i] = CHACHA_TASK_IDLE;

    for(lane = 1U; lane < lanes; lane++) {
        unsigned int worker_index = lane - 1U;
        uint64_t first_block = (total_blocks * lane) / lanes;
        uint64_t end_block = (total_blocks * (lane + 1U)) / lanes;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > bytes)
            end_byte = bytes;
        pool->offsets[worker_index] =
            (u_int)(first_block * CHACHA_BLOCKLEN);
        pool->lengths[worker_index] =
            (u_int)(end_byte - pool->offsets[worker_index]);
        pool->states[worker_index] = *base_state;
        counter = (uint64_t)base_state->input[12] |
                  ((uint64_t)base_state->input[13] << 32);
        counter += first_block;
        pool->states[worker_index].input[12] = (u32)counter;
        pool->states[worker_index].input[13] = (u32)(counter >> 32);
        pool->task_kind[worker_index] = CHACHA_TASK_DECRYPT;
    }

    pool->task_kind[workers - 1U] = CHACHA_TASK_POLY1305;
    pool->generation++;
    (void)pthread_cond_broadcast(&pool->work_ready);
    (void)pthread_mutex_unlock(&pool->mutex);

    owner_end_block = total_blocks / lanes;
    owner_length = (u_int)(owner_end_block * CHACHA_BLOCKLEN);
    if(owner_length > bytes)
        owner_length = bytes;
    owner_state = *base_state;
    chacha_encrypt_bytes(&owner_state, source + aadlen,
                         destination + aadlen, owner_length);
    chacha_parallel_wipe(&owner_state, sizeof(owner_state));

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
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
            /* Do not leave unauthenticated plaintext in the packet buffer. */
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
    for(i = 0U; i < workers; i++)
        pool->task_kind[i] = CHACHA_TASK_IDLE;
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
    unsigned long long phase_started = 0, phase_ended = 0;
    unsigned long long poly_worker_ns = 0ULL;

    memset(poly_key, 0, sizeof(poly_key));
    ptr = &seqbuf[0];
    _libssh2_store_u64(&ptr, seqnr);

    phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
    chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
    chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));
    if(diag_enabled) {
        phase_ended = _libssh2_diag_now_ns();
        if(phase_ended >= phase_started)
            session->passwall_diag.chacha20_key_ns += phase_ended - phase_started;
    }

    if(!do_encrypt && ctx->parallel_pool) {
        const u_char *wire_tag = src + aadlen + len;
        int parallel_rc;

        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
        chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
        parallel_rc = chacha_decrypt_poly_parallel(
            ctx->parallel_pool, &ctx->main_ctx, src, dest, len, aadlen,
            (size_t)aadlen + (size_t)len, poly_key, wire_tag,
            &poly_worker_ns, diag_enabled);
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

    /* Small packets or unavailable pools retain the original serial path. */
    if(!do_encrypt && !parallel_done) {
        const u_char *tag = src + aadlen + len;
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
        poly1305_auth(expected_tag, src, aadlen + len, poly_key);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha_poly1305_ns += phase_ended - phase_started;
        }
        if(chachapoly_timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
    }

    /* The AAD/header is decrypted only after its tag has been authenticated. */
    if(aadlen) {
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
        chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
        chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha20_header_ns += phase_ended - phase_started;
        }
    }

    if(!parallel_done) {
        chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
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

    if(do_encrypt) {
        phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
        poly1305_auth(dest + aadlen + len, dest, aadlen + len, poly_key);
        if(diag_enabled) {
            phase_ended = _libssh2_diag_now_ns();
            if(phase_ended >= phase_started)
                session->passwall_diag.chacha_poly1305_ns += phase_ended - phase_started;
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
    if not (root / ".passwall-r47-parallel-chacha-patched").is_file():
        raise RuntimeError("Run apply_libssh2_r47_parallel_chacha.py first")
    marker = root / ".passwall-r48-poly1305-overlap-patched"
    if marker.exists():
        raise RuntimeError("r48 Poly1305 overlap patch is already present")
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r48 patch is pinned to libssh2 1.11.1")

    chacha_c = root / "src/chacha.c"
    replace_once(chacha_c,
"""#include "chacha.h"

#include <errno.h>""",
"""#include "chacha.h"
#include "poly1305.h"

#include <errno.h>""", "include Poly1305 in ChaCha worker source")
    replace_once(chacha_c,
"""#define CHACHA_PARALLEL_MAX_WORKERS 3U
#define CHACHA_PARALLEL_STACK_SIZE (64U * 1024U)""",
"""#define CHACHA_PARALLEL_MAX_WORKERS 3U
#define CHACHA_PARALLEL_STACK_SIZE (64U * 1024U)
#define CHACHA_PARALLEL_MAX_PACKET 35000U
#define CHACHA_TASK_IDLE 0U
#define CHACHA_TASK_DECRYPT 1U
#define CHACHA_TASK_POLY1305 2U""", "add task types and packet scratch limit")
    replace_once(chacha_c,
"""    unsigned int worker_error;
    unsigned long long generation;
    const u8 *source;""",
"""    unsigned int worker_error;
    unsigned long long generation;
    unsigned int task_kind[CHACHA_PARALLEL_MAX_WORKERS];
    u8 *poly_input;
    size_t poly_len;
    u8 poly_key[POLY1305_KEYLEN];
    u8 poly_tag[POLY1305_TAGLEN];
    unsigned long long poly_ns;
    unsigned int measure_poly;
    const u8 *source;""", "extend crypto pool with ciphertext snapshot and Poly1305 task")
    replace_once(chacha_c,
"""static void *
chacha_parallel_worker_main(void *opaque)
{
    chacha_parallel_worker_t *worker = (chacha_parallel_worker_t *)opaque;
    chacha_parallel_pool_t *pool = worker->pool;
    unsigned long long seen_generation = 0;
#if defined(__linux__)
    char thread_name[16];
    (void)snprintf(thread_name, sizeof(thread_name), "chacha-dec%u", worker->index);
    (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return NULL;

    while(!pool->stopping) {
        chacha_ctx local_state;
        const u8 *source;
        u8 *destination;
        u_int offset;
        u_int length;

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
        local_state = pool->states[worker->index];
        source = pool->source;
        destination = pool->destination;
        offset = pool->offsets[worker->index];
        length = pool->lengths[worker->index];

        (void)pthread_mutex_unlock(&pool->mutex);
        chacha_encrypt_bytes(&local_state, source + offset,
                             destination + offset, length);
        chacha_parallel_wipe(&local_state, sizeof(local_state));
        if(pthread_mutex_lock(&pool->mutex) != 0)
            return NULL;

        pool->completed++;
        if(pool->completed >= pool->worker_count)
            (void)pthread_cond_broadcast(&pool->work_done);
    }

    (void)pthread_mutex_unlock(&pool->mutex);
    return NULL;
}""",
"""static void *
chacha_parallel_worker_main(void *opaque)
{
    chacha_parallel_worker_t *worker = (chacha_parallel_worker_t *)opaque;
    chacha_parallel_pool_t *pool = worker->pool;
    unsigned long long seen_generation = 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return NULL;

    while(!pool->stopping) {
        chacha_ctx local_state;
        const u8 *source;
        u8 *destination;
        u_int offset;
        u_int length;
        unsigned int task_kind;
        unsigned long long poly_started_ns;
        unsigned long long poly_ended_ns;
#if defined(__linux__)
        char thread_name[16];
#endif

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
        local_state = pool->states[worker->index];
        source = pool->source;
        destination = pool->destination;
        offset = pool->offsets[worker->index];
        length = pool->lengths[worker->index];

        (void)pthread_mutex_unlock(&pool->mutex);
        if(task_kind == CHACHA_TASK_POLY1305) {
#if defined(__linux__)
            (void)snprintf(thread_name, sizeof(thread_name), "chacha-poly");
            (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif
            poly_started_ns = pool->measure_poly ? _libssh2_diag_now_ns() : 0ULL;
            poly1305_auth(pool->poly_tag, pool->poly_input,
                          pool->poly_len, pool->poly_key);
            poly_ended_ns = pool->measure_poly ? _libssh2_diag_now_ns() : 0ULL;
            if(poly_ended_ns >= poly_started_ns)
                pool->poly_ns = poly_ended_ns - poly_started_ns;
        } else if(task_kind == CHACHA_TASK_DECRYPT) {
#if defined(__linux__)
            (void)snprintf(thread_name, sizeof(thread_name),
                           "chacha-dec%u", worker->index);
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
}""", "dispatch either ChaCha or Poly1305 work on persistent workers")
    replace_once(chacha_c,
"""    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    if(pool->work_done_initialized)""",
"""    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    if(pool->poly_input) {
        chacha_parallel_wipe(pool->poly_input, CHACHA_PARALLEL_MAX_PACKET);
        free(pool->poly_input);
        pool->poly_input = NULL;
    }
    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));
    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));
    if(pool->work_done_initialized)""", "wipe and free Poly1305 ciphertext scratch")
    replace_once(chacha_c,
"""    pool = (chacha_parallel_pool_t *)calloc(1, sizeof(*pool));
    if(!pool)
        return NULL;

    rc = pthread_mutex_init(&pool->mutex, NULL);""",
"""    pool = (chacha_parallel_pool_t *)calloc(1, sizeof(*pool));
    if(!pool)
        return NULL;
    pool->poly_input = (u8 *)calloc(1, CHACHA_PARALLEL_MAX_PACKET);
    if(!pool->poly_input) {
        free(pool);
        errno = ENOMEM;
        return NULL;
    }

    rc = pthread_mutex_init(&pool->mutex, NULL);""", "allocate persistent Poly1305 snapshot")
    replace_once(chacha_c,
"""    pool->source = source;
    pool->destination = destination;
    pool->completed = 0U;

    for(lane = 1U; lane < lanes; lane++) {""",
"""    pool->source = source;
    pool->destination = destination;
    pool->completed = 0U;
    for(lane = 0U; lane < workers; lane++)
        pool->task_kind[lane] = CHACHA_TASK_DECRYPT;

    for(lane = 1U; lane < lanes; lane++) {""", "mark r47 decrypt work items explicitly")

    with chacha_c.open("a") as f:
        f.write(PARALLEL_FUNCTION)

    chacha_h = root / "src/chacha.h"
    replace_once(chacha_h,
"""int chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *pool,
                                  const struct chacha_ctx *base_state,
                                  const u_char *source, u_char *destination,
                                  u_int bytes);

#endif""",
"""int chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *pool,
                                  const struct chacha_ctx *base_state,
                                  const u_char *source, u_char *destination,
                                  u_int bytes);
int chacha_decrypt_poly_parallel(struct chacha_parallel_pool *pool,
                                 const struct chacha_ctx *base_state,
                                 const u_char *source, u_char *destination,
                                 u_int bytes, u_int aadlen, size_t poly_len,
                                 const u_char poly_key[POLY1305_KEYLEN],
                                 const u_char wire_tag[POLY1305_TAGLEN],
                                 unsigned long long *poly_ns_out, int measure);

#endif""", "expose overlapped Poly1305/ChaCha operation")

    cipher_c = root / "src/cipher-chachapoly.c"
    source = cipher_c.read_text()
    marker = "int\\nchachapoly_crypt("
    start = source.find(marker)
    if start < 0 or source.find(marker, start + 1) >= 0:
        raise RuntimeError("cipher-chachapoly.c: expected one chachapoly_crypt function")
    end_marker = "\\n/* Decrypt and extract the encrypted packet length */"
    end = source.find(end_marker, start)
    if end < 0:
        raise RuntimeError("cipher-chachapoly.c: get_length anchor missing")
    source = source[:start] + CRYPT_FUNCTION + source[end:]
    cipher_c.write_text(source)

    priv = root / "src/libssh2_priv.h"
    replace_once(priv,
"""        unsigned long long chacha_poly1305_ns;
        unsigned long long chacha20_key_ns;""",
"""        unsigned long long chacha_poly1305_ns;
        unsigned long long chacha_poly1305_offloaded_packets;
        unsigned long long chacha20_key_ns;""", "add offloaded Poly1305 diagnostic counter")
    replace_once(priv,
"""    unsigned long long chacha_poly1305_ns;
    unsigned long long chacha20_key_ns;""",
"""    unsigned long long chacha_poly1305_ns;
    unsigned long long chacha_poly1305_offloaded_packets;
    unsigned long long chacha20_key_ns;""", "add Poly1305 counter to public timing layout")
    session_c = root / "src/session.c"
    replace_once(session_c,
"""    timing->chacha_poly1305_ns =
        session->passwall_diag.chacha_poly1305_ns;
    timing->chacha20_key_ns =""",
"""    timing->chacha_poly1305_ns =
        session->passwall_diag.chacha_poly1305_ns;
    timing->chacha_poly1305_offloaded_packets =
        session->passwall_diag.chacha_poly1305_offloaded_packets;
    timing->chacha20_key_ns =""", "snapshot Poly1305 offload packets")
    replace_once(session_c,
"""        session->passwall_diag.chacha_poly1305_ns = 0;
        session->passwall_diag.chacha20_key_ns = 0;""",
"""        session->passwall_diag.chacha_poly1305_ns = 0;
        session->passwall_diag.chacha_poly1305_offloaded_packets = 0;
        session->passwall_diag.chacha20_key_ns = 0;""", "reset Poly1305 offload packets")

    marker.write_text("libssh2 1.11.1 Passwall r48 overlapped Poly1305 and ChaCha20\\n")
    print("PASS: r48 Poly1305 verification overlaps ChaCha20 using a private ciphertext snapshot")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("usage: apply_libssh2_r48_poly1305_overlap.py <libssh2-1.11.1-source-dir>")
    patch(Path(sys.argv[1]).resolve())
