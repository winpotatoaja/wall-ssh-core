#!/usr/bin/env python3
"""Add safe packet-local ChaCha20 parallelism to upstream libssh2 1.11.1."""
from pathlib import Path
import sys

def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))

POOL_SOURCE = r'''
/* Passwall r47: persistent packet-local ChaCha20 workers. */
#define CHACHA_PARALLEL_MAX_WORKERS 3U
#define CHACHA_PARALLEL_STACK_SIZE (64U * 1024U)

typedef struct chacha_parallel_pool chacha_parallel_pool_t;

typedef struct {
    chacha_parallel_pool_t *pool;
    pthread_t thread;
    unsigned int index;
    int started;
} chacha_parallel_worker_t;

struct chacha_parallel_pool {
    pthread_mutex_t mutex;
    pthread_cond_t work_ready;
    pthread_cond_t work_done;
    unsigned int worker_count;
    unsigned int completed;
    unsigned int stopping;
    unsigned int worker_error;
    unsigned long long generation;
    const u8 *source;
    u8 *destination;
    u_int offsets[CHACHA_PARALLEL_MAX_WORKERS];
    u_int lengths[CHACHA_PARALLEL_MAX_WORKERS];
    chacha_ctx states[CHACHA_PARALLEL_MAX_WORKERS];
    chacha_parallel_worker_t workers[CHACHA_PARALLEL_MAX_WORKERS];
    int mutex_ready;
    int work_ready_initialized;
    int work_done_initialized;
};

static void
chacha_parallel_wipe(void *memory, size_t length)
{
    volatile u8 *p = (volatile u8 *)memory;
    while(length--)
        *p++ = 0;
}

static void *
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
}

static void
chacha_parallel_pool_stop(chacha_parallel_pool_t *pool)
{
    unsigned int i;

    if(!pool)
        return;

    if(pool->mutex_ready) {
        (void)pthread_mutex_lock(&pool->mutex);
        pool->stopping = 1U;
        if(pool->work_ready_initialized)
            (void)pthread_cond_broadcast(&pool->work_ready);
        if(pool->work_done_initialized)
            (void)pthread_cond_broadcast(&pool->work_done);
        (void)pthread_mutex_unlock(&pool->mutex);
    }

    for(i = 0; i < pool->worker_count; i++) {
        if(pool->workers[i].started) {
            (void)pthread_join(pool->workers[i].thread, NULL);
            pool->workers[i].started = 0;
        }
    }

    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    if(pool->work_done_initialized)
        (void)pthread_cond_destroy(&pool->work_done);
    if(pool->work_ready_initialized)
        (void)pthread_cond_destroy(&pool->work_ready);
    if(pool->mutex_ready)
        (void)pthread_mutex_destroy(&pool->mutex);
}

struct chacha_parallel_pool *
chacha_parallel_pool_create(unsigned int workers)
{
    chacha_parallel_pool_t *pool;
    pthread_attr_t attr;
    unsigned int i;
    int rc;

    if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS) {
        errno = EINVAL;
        return NULL;
    }

    pool = (chacha_parallel_pool_t *)calloc(1, sizeof(*pool));
    if(!pool)
        return NULL;

    rc = pthread_mutex_init(&pool->mutex, NULL);
    if(rc != 0) {
        errno = rc;
        goto fail;
    }
    pool->mutex_ready = 1;

    rc = pthread_cond_init(&pool->work_ready, NULL);
    if(rc != 0) {
        errno = rc;
        goto fail;
    }
    pool->work_ready_initialized = 1;

    rc = pthread_cond_init(&pool->work_done, NULL);
    if(rc != 0) {
        errno = rc;
        goto fail;
    }
    pool->work_done_initialized = 1;
    pool->worker_count = workers;

    rc = pthread_attr_init(&attr);
    if(rc != 0) {
        errno = rc;
        goto fail;
    }
    rc = pthread_attr_setstacksize(&attr, CHACHA_PARALLEL_STACK_SIZE);
    if(rc != 0) {
        (void)pthread_attr_destroy(&attr);
        errno = rc;
        goto fail;
    }

    for(i = 0; i < workers; i++) {
        pool->workers[i].pool = pool;
        pool->workers[i].index = i;
        rc = pthread_create(&pool->workers[i].thread, &attr,
                            chacha_parallel_worker_main, &pool->workers[i]);
        if(rc != 0) {
            (void)pthread_attr_destroy(&attr);
            errno = rc;
            goto fail;
        }
        pool->workers[i].started = 1;
    }
    (void)pthread_attr_destroy(&attr);
    return pool;

fail:
    chacha_parallel_pool_stop(pool);
    free(pool);
    return NULL;
}

void
chacha_parallel_pool_destroy(struct chacha_parallel_pool *opaque_pool)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    if(!pool)
        return;
    chacha_parallel_pool_stop(pool);
    chacha_parallel_wipe(pool, sizeof(*pool));
    free(pool);
}

unsigned int
chacha_parallel_pool_workers(const struct chacha_parallel_pool *pool)
{
    return pool ? pool->worker_count : 0U;
}

/*
 * Run lane zero on the SSH Owner and the remaining lanes on persistent
 * workers. All offsets are ChaCha block-aligned; the final lane owns the
 * optional short tail. The caller authenticates the complete packet first.
 * Return 1 when parallel work ran, 0 when the caller should use serial code,
 * and -1 if the worker pool cannot complete the dispatched packet.
 */
int
chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *opaque_pool,
                              const struct chacha_ctx *base_state,
                              const u_char *source, u_char *destination,
                              u_int bytes)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int lanes, lane, workers;
    uint64_t total_blocks, owner_end_block;
    u_int owner_length;
    chacha_ctx owner_state;
    int rc = 0;

    if(!pool || !base_state || !source || !destination ||
       bytes < 4096U)
        return 0;

    workers = pool->worker_count;
    lanes = workers + 1U;
    total_blocks = ((uint64_t)bytes + CHACHA_BLOCKLEN - 1U) /
                   CHACHA_BLOCKLEN;
    if(total_blocks < lanes)
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

    for(lane = 1U; lane < lanes; lane++) {
        uint64_t first_block = (total_blocks * lane) / lanes;
        uint64_t end_block = (total_blocks * (lane + 1U)) / lanes;
        uint64_t end_byte = end_block * CHACHA_BLOCKLEN;
        uint64_t counter;

        if(end_byte > bytes)
            end_byte = bytes;
        pool->offsets[lane - 1U] = (u_int)(first_block * CHACHA_BLOCKLEN);
        pool->lengths[lane - 1U] =
            (u_int)(end_byte - pool->offsets[lane - 1U]);
        pool->states[lane - 1U] = *base_state;

        counter = (uint64_t)base_state->input[12] |
                  ((uint64_t)base_state->input[13] << 32);
        counter += first_block;
        pool->states[lane - 1U].input[12] = (u32)counter;
        pool->states[lane - 1U].input[13] = (u32)(counter >> 32);
    }

    pool->generation++;
    (void)pthread_cond_broadcast(&pool->work_ready);
    (void)pthread_mutex_unlock(&pool->mutex);

    owner_end_block = total_blocks / lanes;
    owner_length = (u_int)(owner_end_block * CHACHA_BLOCKLEN);
    if(owner_length > bytes)
        owner_length = bytes;
    owner_state = *base_state;
    chacha_encrypt_bytes(&owner_state, source, destination, owner_length);
    chacha_parallel_wipe(&owner_state, sizeof(owner_state));

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
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
    marker = root / ".passwall-r43-diag-patched"
    if not marker.is_file():
        raise RuntimeError("Run apply_libssh2_r43_diag.py first")
    if (root / ".passwall-r47-parallel-chacha-patched").exists():
        raise RuntimeError("r47 parallel ChaCha patch is already present")

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("The r47 patch is pinned to libssh2 1.11.1")

    priv = root / "src/libssh2_priv.h"
    replace_once(priv,
"""        unsigned int transport_depth;
        unsigned long long decrypt_path_ns;""",
"""        unsigned int transport_depth;
        unsigned int chacha_workers_requested;
        unsigned int chacha_workers_active;
        unsigned long long chacha_poly1305_ns;
        unsigned long long chacha20_key_ns;
        unsigned long long chacha20_header_ns;
        unsigned long long chacha20_payload_ns;
        unsigned long long chacha20_serial_ns;
        unsigned long long chacha20_serial_bytes;
        unsigned long long chacha20_serial_packets;
        unsigned long long chacha20_parallel_ns;
        unsigned long long chacha20_parallel_bytes;
        unsigned long long chacha20_parallel_packets;
        unsigned long long decrypt_path_ns;""", "private ChaCha diagnostics/config")
    replace_once(priv,
"""    unsigned long long packet_queue_enqueued_bytes;
} LIBSSH2_DIAG_TIMING;""",
"""    unsigned long long packet_queue_enqueued_bytes;
    unsigned int chacha_workers_requested;
    unsigned int chacha_workers_active;
    unsigned long long chacha_poly1305_ns;
    unsigned long long chacha20_key_ns;
    unsigned long long chacha20_header_ns;
    unsigned long long chacha20_payload_ns;
    unsigned long long chacha20_serial_ns;
    unsigned long long chacha20_serial_bytes;
    unsigned long long chacha20_serial_packets;
    unsigned long long chacha20_parallel_ns;
    unsigned long long chacha20_parallel_bytes;
    unsigned long long chacha20_parallel_packets;
} LIBSSH2_DIAG_TIMING;""", "public ChaCha timing snapshot layout")

    chacha_h = root / "src/chacha.h"
    replace_once(chacha_h,
"""void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m,
                          u_char *c, u_int bytes);

#endif""",
"""void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m,
                          u_char *c, u_int bytes);

struct chacha_parallel_pool;
struct chacha_parallel_pool *chacha_parallel_pool_create(unsigned int workers);
void chacha_parallel_pool_destroy(struct chacha_parallel_pool *pool);
unsigned int chacha_parallel_pool_workers(const struct chacha_parallel_pool *pool);
int chacha_encrypt_bytes_parallel(struct chacha_parallel_pool *pool,
                                  const struct chacha_ctx *base_state,
                                  const u_char *source, u_char *destination,
                                  u_int bytes);

#endif""", "ChaCha parallel API")

    chacha_c = root / "src/chacha.c"
    replace_once(chacha_c,
"""#include "chacha.h"

""",
"""#include "chacha.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

""", "ChaCha worker includes")
    with chacha_c.open("a") as f:
        f.write(POOL_SOURCE)

    cipher_h = root / "src/cipher-chachapoly.h"
    replace_once(cipher_h,
"""struct chachapoly_ctx {
    struct chacha_ctx main_ctx, header_ctx;
};

int chachapoly_init(struct chachapoly_ctx *cpctx,
                    const u_char *key, u_int keylen);
int chachapoly_crypt(struct chachapoly_ctx *cpctx, u_int seqnr,
                     u_char *dest, const u_char *src, u_int len, u_int aadlen,
                     int do_encrypt);""",
"""struct chacha_parallel_pool;
struct _LIBSSH2_SESSION;

struct chachapoly_ctx {
    struct chacha_ctx main_ctx, header_ctx;
    struct chacha_parallel_pool *parallel_pool;
};

int chachapoly_init(struct chachapoly_ctx *cpctx,
                    const u_char *key, u_int keylen,
                    unsigned int parallel_workers);
void chachapoly_cleanup(struct chachapoly_ctx *cpctx);
unsigned int chachapoly_parallel_workers(const struct chachapoly_ctx *cpctx);
int chachapoly_crypt(struct _LIBSSH2_SESSION *session,
                     struct chachapoly_ctx *cpctx, u_int seqnr,
                     u_char *dest, const u_char *src, u_int len, u_int aadlen,
                     int do_encrypt);""", "ChaCha-Poly API")

    cipher_c = root / "src/cipher-chachapoly.c"
    replace_once(cipher_c,
"""int
chachapoly_init(struct chachapoly_ctx *ctx, const u_char *key, u_int keylen)
{
    if(keylen != (32 + 32)) /* 2 x 256 bit keys */
        return LIBSSH2_ERROR_INVAL;
    chacha_keysetup(&ctx->main_ctx, key, 256);
    chacha_keysetup(&ctx->header_ctx, key + 32, 256);
    return 0;
}""",
"""int
chachapoly_init(struct chachapoly_ctx *ctx, const u_char *key, u_int keylen,
                unsigned int parallel_workers)
{
    if(!ctx)
        return LIBSSH2_ERROR_INVAL;
    memset(ctx, 0, sizeof(*ctx));
    if(!key || keylen != (32 + 32)) /* 2 x 256 bit keys */
        return LIBSSH2_ERROR_INVAL;
    chacha_keysetup(&ctx->main_ctx, key, 256);
    chacha_keysetup(&ctx->header_ctx, key + 32, 256);
    if(parallel_workers > 0U)
        ctx->parallel_pool = chacha_parallel_pool_create(parallel_workers);
    /* Pool creation is optional: retain the safe serial fallback. */
    return 0;
}

void
chachapoly_cleanup(struct chachapoly_ctx *ctx)
{
    if(!ctx)
        return;
    chacha_parallel_pool_destroy(ctx->parallel_pool);
    memset(ctx, 0, sizeof(*ctx));
}

unsigned int
chachapoly_parallel_workers(const struct chachapoly_ctx *ctx)
{
    return ctx ? chacha_parallel_pool_workers(ctx->parallel_pool) : 0U;
}""", "ChaCha-Poly initialization and cleanup")

    old_crypt = """int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
                 const u_char *src, u_int len, u_int aadlen, int do_encrypt)
{
    u_char seqbuf[8];
    const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
    u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
    int r = LIBSSH2_ERROR_INVAL;
    unsigned char *ptr = NULL;

    /*
     * Run ChaCha20 once to generate the Poly1305 key. The IV is the
     * packet sequence number.
     */
    memset(poly_key, 0, sizeof(poly_key));
    ptr = &seqbuf[0];
    _libssh2_store_u64(&ptr, seqnr);
    chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
    chacha_encrypt_bytes(&ctx->main_ctx,
                         poly_key, poly_key, sizeof(poly_key));

    /* If decrypting, check tag before anything else */
    if(!do_encrypt) {
        const u_char *tag = src + aadlen + len;

        poly1305_auth(expected_tag, src, aadlen + len, poly_key);
        if(chachapoly_timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN)
           != 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
    }

    /* Crypt additional data */
    if(aadlen) {
        chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
        chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
    }

    /* Set Chacha's block counter to 1 */
    chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
    chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
                         dest + aadlen, len);

    /* If encrypting, calculate and append tag */
    if(do_encrypt) {
        poly1305_auth(dest + aadlen + len, dest, aadlen + len,
                      poly_key);
    }
    r = 0;
out:
    memset(expected_tag, 0, sizeof(expected_tag));
    memset(seqbuf, 0, sizeof(seqbuf));
    memset(poly_key, 0, sizeof(poly_key));
    return r;
}"""
    new_crypt = """int
chachapoly_crypt(struct _LIBSSH2_SESSION *session,
                 struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
                 const u_char *src, u_int len, u_int aadlen, int do_encrypt)
{
    u_char seqbuf[8];
    const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
    int r = LIBSSH2_ERROR_INVAL;
    unsigned char *ptr = NULL;
    int diag_enabled = session && session->passwall_diag.enabled;
    unsigned long long phase_started = 0, phase_ended = 0;

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

    /* Authenticate the complete ciphertext before any in-place decryption. */
    if(!do_encrypt) {
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

    chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
    phase_started = diag_enabled ? _libssh2_diag_now_ns() : 0;
    if(!do_encrypt && ctx->parallel_pool) {
        int parallel_rc = chacha_encrypt_bytes_parallel(
            ctx->parallel_pool, &ctx->main_ctx, src + aadlen,
            dest + aadlen, len);
        if(parallel_rc < 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
        if(parallel_rc > 0) {
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
}"""
    replace_once(cipher_c, old_crypt, new_crypt, "instrument and parallelize ChaCha payload")

    crypt_c = root / "src/crypt.c"
    replace_once(crypt_c,
"""    if(chachapoly_init(&ctx->chachapoly_ctx, secret, method->secret_len)) {
        LIBSSH2_FREE(session, ctx);
        return -1;
    }

    *abstract = ctx;""",
"""    if(chachapoly_init(&ctx->chachapoly_ctx, secret, method->secret_len,
                       encrypt ? 0U : session->passwall_diag.chacha_workers_requested)) {
        chachapoly_cleanup(&ctx->chachapoly_ctx);
        LIBSSH2_FREE(session, ctx);
        return -1;
    }
    if(!encrypt)
        session->passwall_diag.chacha_workers_active =
            chachapoly_parallel_workers(&ctx->chachapoly_ctx);

    *abstract = ctx;""", "configure inbound ChaCha worker count")
    replace_once(crypt_c,
"""            ret = chachapoly_crypt(&ctx->chachapoly_ctx, seqno, buf, buf,
                                   ((u_int)buf_len), 4, ctx->encrypt);""",
"""            ret = chachapoly_crypt(session, &ctx->chachapoly_ctx,
                                   seqno, buf, buf, ((u_int)buf_len),
                                   4, ctx->encrypt);""", "pass session to ChaCha decrypt")
    replace_once(crypt_c,
"""            ret = chachapoly_crypt(&ctx->chachapoly_ctx, seqno, buf, buf,
                                   ((u_int)buf_len) - 4, 4, ctx->encrypt);""",
"""            ret = chachapoly_crypt(session, &ctx->chachapoly_ctx,
                                   seqno, buf, buf,
                                   ((u_int)buf_len) - 4, 4, ctx->encrypt);""", "pass session to ChaCha encrypt")
    replace_once(crypt_c,
"""    if(cctx && *cctx) {
        LIBSSH2_FREE(session, *cctx);
        *abstract = NULL;
    }
    return 0;
}""",
"""    if(cctx && *cctx) {
        chachapoly_cleanup(&(*cctx)->chachapoly_ctx);
        LIBSSH2_FREE(session, *cctx);
        *abstract = NULL;
    }
    return 0;
}""", "destroy ChaCha worker pool with cipher context")

    session_c = root / "src/session.c"
    replace_once(session_c,
"""    memset(&session->passwall_diag, 0, sizeof(session->passwall_diag));
    if(!enabled)
        return;

    packet = _libssh2_list_first(&session->packets);""",
"""    unsigned int requested_workers;
    unsigned int active_workers;
    requested_workers = session->passwall_diag.chacha_workers_requested;
    active_workers = session->passwall_diag.chacha_workers_active;
    memset(&session->passwall_diag, 0, sizeof(session->passwall_diag));
    session->passwall_diag.chacha_workers_requested = requested_workers;
    session->passwall_diag.chacha_workers_active = active_workers;
    if(!enabled)
        return;

    packet = _libssh2_list_first(&session->packets);""", "preserve ChaCha worker configuration when enabling diagnostics")

    replace_once(session_c,
"""    timing->packet_queue_enqueued_bytes =
        session->passwall_diag.packet_queue_enqueued_bytes;

    if(reset) {""",
"""    timing->packet_queue_enqueued_bytes =
        session->passwall_diag.packet_queue_enqueued_bytes;
    timing->chacha_workers_requested =
        session->passwall_diag.chacha_workers_requested;
    timing->chacha_workers_active =
        session->passwall_diag.chacha_workers_active;
    timing->chacha_poly1305_ns =
        session->passwall_diag.chacha_poly1305_ns;
    timing->chacha20_key_ns =
        session->passwall_diag.chacha20_key_ns;
    timing->chacha20_header_ns =
        session->passwall_diag.chacha20_header_ns;
    timing->chacha20_payload_ns =
        session->passwall_diag.chacha20_payload_ns;
    timing->chacha20_serial_ns =
        session->passwall_diag.chacha20_serial_ns;
    timing->chacha20_serial_bytes =
        session->passwall_diag.chacha20_serial_bytes;
    timing->chacha20_serial_packets =
        session->passwall_diag.chacha20_serial_packets;
    timing->chacha20_parallel_ns =
        session->passwall_diag.chacha20_parallel_ns;
    timing->chacha20_parallel_bytes =
        session->passwall_diag.chacha20_parallel_bytes;
    timing->chacha20_parallel_packets =
        session->passwall_diag.chacha20_parallel_packets;

    if(reset) {""", "snapshot ChaCha metrics")
    replace_once(session_c,
"""        session->passwall_diag.packet_drain_removed = 0;
        session->passwall_diag.packet_queue_enqueued_packets = 0;""",
"""        session->passwall_diag.packet_drain_removed = 0;
        session->passwall_diag.chacha_poly1305_ns = 0;
        session->passwall_diag.chacha20_key_ns = 0;
        session->passwall_diag.chacha20_header_ns = 0;
        session->passwall_diag.chacha20_payload_ns = 0;
        session->passwall_diag.chacha20_serial_ns = 0;
        session->passwall_diag.chacha20_serial_bytes = 0;
        session->passwall_diag.chacha20_serial_packets = 0;
        session->passwall_diag.chacha20_parallel_ns = 0;
        session->passwall_diag.chacha20_parallel_bytes = 0;
        session->passwall_diag.chacha20_parallel_packets = 0;
        session->passwall_diag.packet_queue_enqueued_packets = 0;""", "reset ChaCha counters with each perf interval")

    with session_c.open("a") as f:
        f.write("""
/* Configure the number of background ChaCha20 lanes before key exchange. */
LIBSSH2_API void
libssh2_session_set_chacha_workers(LIBSSH2_SESSION *session,
                                   unsigned int workers)
{
    if(!session)
        return;
    if(workers > 3U)
        workers = 3U;
    session->passwall_diag.chacha_workers_requested = workers;
}
""")

    marker47 = root / ".passwall-r47-parallel-chacha-patched"
    marker47.write_text("libssh2 1.11.1 Passwall r47 packet-local parallel ChaCha20\\n")
    print("PASS: patched libssh2 1.11.1 with authenticated packet-local ChaCha20 worker lanes and phase timing")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("usage: apply_libssh2_r47_parallel_chacha.py <libssh2-1.11.1-source-dir>")
    patch(Path(sys.argv[1]).resolve())
