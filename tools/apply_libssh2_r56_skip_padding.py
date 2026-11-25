#!/usr/bin/env python3
"""Passwall r56: omit the authenticated padding-length byte from the output buffer."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


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


def replace_function(path: Path, signature: str, replacement: str) -> None:
    source = path.read_text()
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"{path.name}: expected exactly one function {signature!r}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"{path.name}: function body missing for {signature!r}")
    end = find_matching_brace(source, brace)
    path.write_text(source[:start] + replacement.rstrip() + source[end:])


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
        const u8 *poly_input;
        const u8 *poly_key;
        u8 *poly_tag;
        u8 *padding_length_out;
        u_int offset;
        u_int destination_offset;
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
        destination_offset = pool->destination_offsets[worker->index];
        length = pool->lengths[worker->index];
        poly_input = pool->poly_input;
        poly_key = pool->poly_key;
        poly_tag = pool->poly_tag;
        padding_length_out = pool->padding_length_out;
        poly_len = pool->poly_len;
        measure_poly = pool->measure_poly;
        if(task_kind == CHACHA_TASK_DECRYPT ||
           task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST)
            local_state = pool->states[worker->index];
        pool->active_workers++;

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
        }
        else if(task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST) {
            u8 zero_block[CHACHA_BLOCKLEN] = { 0 };
            u8 first_keystream[CHACHA_BLOCKLEN];
            u_int i;

#if defined(__linux__)
            (void)snprintf(thread_name, sizeof(thread_name), "chacha-dec%u",
                           worker->index);
            (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif
            /* Worker zero consumes block one, exports padding length, and
             * writes the remaining 63 bytes directly in normalized layout. */
            chacha_encrypt_bytes(&local_state, zero_block, first_keystream,
                                 64U);
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
#if defined(__linux__)
            (void)snprintf(thread_name, sizeof(thread_name), "chacha-dec%u",
                           worker->index);
            (void)prctl(PR_SET_NAME, thread_name, 0, 0, 0);
#endif
            chacha_encrypt_bytes(&local_state, source + offset,
                                 destination + destination_offset, length);
        }
        chacha_parallel_wipe(&local_state, sizeof(local_state));
        if(pthread_mutex_lock(&pool->mutex) != 0)
            return NULL;

        if(pool->active_workers > 0U)
            pool->active_workers--;
        pool->completed++;
        if(pool->completed >= pool->worker_count || pool->active_workers == 0U)
            (void)pthread_cond_broadcast(&pool->work_done);
    }

    (void)pthread_mutex_unlock(&pool->mutex);
    return NULL;
}
'''


WORKER_ONLY = r'''
/*
 * r56: authenticate the complete wire packet first, then dispatch the
 * normalized body. With skip_first set, worker zero decrypts ChaCha block one,
 * exports the padding length, and writes bytes 1..63 at output offsets 0..62.
 * All workers then decrypt the remaining block-aligned ranges. No unauthenticated
 * plaintext is written and the SSH Owner performs no payload transform.
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
                                unsigned long long *poly_ns_out, int measure)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    unsigned int workers, worker;
    uint64_t total_blocks, decrypt_bytes;
    size_t poly_len;
    unsigned int tag_diff = 0U;
    int rc = -1;

    if(!pool || !base_state || !source || !destination || !poly_key ||
       !wire_tag || bytes < 4096U)
        return 0;
    if(skip_first && (dest_aadlen != 0U || !padding_length_out || bytes < 64U))
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
    total_blocks = (decrypt_bytes + CHACHA_BLOCKLEN - 1U) / CHACHA_BLOCKLEN;
    if(total_blocks < workers)
        return 0;

    if(pthread_mutex_lock(&pool->mutex) != 0)
        return -1;
    if(pool->stopping || pool->worker_error) {
        (void)pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    /* Phase one: Poly1305 only. The complete original AAD+ciphertext is read
     * before any output byte or padding-length result is written. */
    pool->poly_input = source;
    memcpy(pool->poly_key, poly_key, POLY1305_KEYLEN);
    pool->poly_len = poly_len;
    pool->poly_ns = 0ULL;
    pool->measure_poly = measure ? 1U : 0U;
    pool->source = NULL;
    pool->destination = NULL;
    pool->padding_length_out = NULL;
    pool->completed = 0U;

    for(worker = 0U; worker < workers; worker++) {
        pool->task_kind[worker] =
            worker == workers - 1U ? CHACHA_TASK_POLY1305 : CHACHA_TASK_IDLE;
        pool->offsets[worker] = 0U;
        pool->destination_offsets[worker] = 0U;
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
        (void)pthread_mutex_unlock(&pool->mutex);
        (void)chacha_parallel_pool_stop(pool);
        return -1;
    }

    for(worker = 0U; worker < POLY1305_TAGLEN; worker++)
        tag_diff |= (unsigned int)(pool->poly_tag[worker] ^ wire_tag[worker]);
    if(poly_ns_out)
        *poly_ns_out = pool->poly_ns;

    if(tag_diff != 0U) {
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

    rc = 1;

cleanup:
    pool->source = NULL;
    pool->destination = NULL;
    pool->padding_length_out = NULL;
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
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


CHACHAPOLY_FUNCTION = r'''
int
chachapoly_crypt(struct _LIBSSH2_SESSION *session,
                 struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
                 const u_char *src, u_int len, u_int aadlen,
                 u_int dest_aadlen, unsigned int drop_first,
                 u_char *padding_length_out, int do_encrypt)
{
    u_char seqbuf[8];
    const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    u_char zero_block[64] = { 0 };
    u_char first_keystream[64];
    u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
    int r = LIBSSH2_ERROR_INVAL;
    int parallel_done = 0;
    unsigned char *ptr = NULL;
    int diag_enabled = session && session->passwall_diag.enabled;
    unsigned long long phase_started = 0ULL, phase_ended = 0ULL;
    unsigned long long poly_worker_ns = 0ULL;

    if(dest_aadlen != 0U && dest_aadlen != aadlen)
        return LIBSSH2_ERROR_INVAL;
    if(do_encrypt && dest_aadlen != aadlen)
        return LIBSSH2_ERROR_INVAL;
    if(drop_first && (do_encrypt || dest_aadlen != 0U ||
                      !padding_length_out || len == 0U))
        return LIBSSH2_ERROR_INVAL;
    if(!drop_first && padding_length_out)
        return LIBSSH2_ERROR_INVAL;

    memset(poly_key, 0, sizeof(poly_key));
    memset(first_keystream, 0, sizeof(first_keystream));
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
            dest_aadlen, drop_first, padding_length_out, poly_key, wire_tag,
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
                session->passwall_diag.chacha20_parallel_bytes +=
                    (unsigned long long)len - (drop_first ? 1ULL : 0ULL);
                session->passwall_diag.chacha20_parallel_packets++;
            }
        }
        else if(parallel_rc < 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }
    }

    /* Serial fallback also authenticates the original packet before any write. */
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

    if(dest_aadlen) {
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
        if(!do_encrypt && ctx->parallel_pool && !drop_first)
            parallel_rc = chacha_encrypt_bytes_parallel(
                ctx->parallel_pool, &ctx->main_ctx, src + aadlen,
                dest + dest_aadlen, len);

        if(parallel_rc < 0) {
            r = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }

        if(drop_first) {
            u_int prefix_len = len < 64U ? len : 64U;
            u_int i;

            chacha_encrypt_bytes(&ctx->main_ctx, zero_block, first_keystream,
                                 CHACHA_BLOCKLEN);
            *padding_length_out = (u_char)(src[aadlen] ^ first_keystream[0]);
            for(i = 1U; i < prefix_len; i++)
                dest[i - 1U] = (u_char)(src[aadlen + i] ^ first_keystream[i]);
            if(len > 64U)
                chacha_encrypt_bytes(&ctx->main_ctx,
                                     src + aadlen + 64U,
                                     dest + 63U,
                                     len - 64U);
            if(diag_enabled) {
                phase_ended = _libssh2_diag_now_ns();
                if(phase_ended >= phase_started) {
                    unsigned long long elapsed = phase_ended - phase_started;
                    session->passwall_diag.chacha20_payload_ns += elapsed;
                    session->passwall_diag.chacha20_serial_ns += elapsed;
                }
                session->passwall_diag.chacha20_serial_bytes +=
                    (unsigned long long)len - 1ULL;
                session->passwall_diag.chacha20_serial_packets++;
            }
        }
        else if(parallel_rc > 0 && !do_encrypt) {
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
        }
        else {
            chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
                                 dest + dest_aadlen, len);
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
        poly1305_auth(dest + dest_aadlen + len, dest,
                      dest_aadlen + len, poly_key);
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
    memset(first_keystream, 0, sizeof(first_keystream));
    memset(zero_block, 0, sizeof(zero_block));
    return r;
}
'''


def patch(root: Path) -> None:
    for marker_name in (
        ".passwall-r51-auth-before-decrypt-patched",
        ".passwall-r52-worker-lifecycle-patched",
        ".passwall-r53-mips32r2-chacha-asm-patched",
        ".passwall-r54-mips32r2-poly1305-asm-patched",
        ".passwall-r55-out-of-place-chachapoly-patched",
    ):
        if not (root / marker_name).is_file():
            raise RuntimeError("r56 requires prior patch: " + marker_name)

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r56 patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r56-skip-padding-memmove-patched"
    if marker.exists():
        raise RuntimeError("r56 skip-padding memmove patch is already present")

    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        "#define CHACHA_TASK_POLY1305 2U",
        "#define CHACHA_TASK_POLY1305 2U\n#define CHACHA_TASK_DECRYPT_SKIP_FIRST 3U",
        "add a worker task for consuming block one and omitting padding length",
    )
    replace_once(
        chacha_c,
        "    u_int offsets[CHACHA_PARALLEL_MAX_WORKERS];\n"
        "    u_int lengths[CHACHA_PARALLEL_MAX_WORKERS];\n",
        "    u_int offsets[CHACHA_PARALLEL_MAX_WORKERS];\n"
        "    u_int destination_offsets[CHACHA_PARALLEL_MAX_WORKERS];\n"
        "    u_int lengths[CHACHA_PARALLEL_MAX_WORKERS];\n",
        "give worker tasks independent source and destination offsets",
    )
    replace_once(
        chacha_c,
        "    unsigned int measure_poly;\n"
        "    const u8 *source;\n"
        "    u8 *destination;\n",
        "    unsigned int measure_poly;\n"
        "    const u8 *source;\n"
        "    u8 *destination;\n"
        "    u8 *padding_length_out;\n",
        "add a synchronized output for the separately recovered padding length",
    )

    replace_function(
        chacha_c, "static void *\nchacha_parallel_worker_main(void *opaque)", WORKER_MAIN
    )
    replace_once(
        chacha_c,
        "        pool->offsets[lane] = (u_int)(first_block * CHACHA_BLOCKLEN);\n"
        "        pool->lengths[lane] =\n",
        "        pool->offsets[lane] = (u_int)(first_block * CHACHA_BLOCKLEN);\n"
        "        pool->destination_offsets[lane] = pool->offsets[lane];\n"
        "        pool->lengths[lane] =\n",
        "preserve identical offsets for existing parallel decrypt tasks",
    )
    replace_once(
        chacha_c,
        "    pool->source = NULL;\n"
        "    pool->destination = NULL;\n"
        "    pool->poly_input = NULL;\n"
        "    pool->poly_len = 0U;\n"
        "    pool->measure_poly = 0U;\n"
        "    pool->active_workers = 0U;",
        "    pool->source = NULL;\n"
        "    pool->destination = NULL;\n"
        "    pool->padding_length_out = NULL;\n"
        "    pool->poly_input = NULL;\n"
        "    pool->poly_len = 0U;\n"
        "    pool->measure_poly = 0U;\n"
        "    pool->active_workers = 0U;",
        "clear padding output pointer when worker pool stops",
    )
    replace_once(
        chacha_c,
        "    pool->completed = pool->worker_count;\n"
        "    chacha_parallel_wipe(pool->states, sizeof(pool->states));\n"
        "    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));\n"
        "    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));\n"
        "    memset(pool->offsets, 0, sizeof(pool->offsets));\n"
        "    memset(pool->lengths, 0, sizeof(pool->lengths));",
        "    pool->completed = pool->worker_count;\n"
        "    chacha_parallel_wipe(pool->states, sizeof(pool->states));\n"
        "    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));\n"
        "    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));\n"
        "    memset(pool->offsets, 0, sizeof(pool->offsets));\n"
        "    memset(pool->destination_offsets, 0, sizeof(pool->destination_offsets));\n"
        "    memset(pool->lengths, 0, sizeof(pool->lengths));",
        "clear independent worker destination offsets on pool stop",
    )

    replace_function(
        chacha_c, "int\nchacha_decrypt_poly_worker_only(", WORKER_ONLY
    )

    chacha_h = root / "src/chacha.h"
    replace_once(
        chacha_h,
        "                                    u_int bytes, u_int aadlen,\n"
        "                                    u_int dest_aadlen,\n"
        "                                    const u_char poly_key[32],",
        "                                    u_int bytes, u_int aadlen,\n"
        "                                    u_int dest_aadlen,\n"
        "                                    unsigned int skip_first,\n"
        "                                    u_char *padding_length_out,\n"
        "                                    const u_char poly_key[32],",
        "extend worker-only decrypt API with normalized-output mode",
    )

    cipher_h = root / "src/cipher-chachapoly.h"
    replace_once(
        cipher_h,
        "                     u_int aadlen, u_int dest_aadlen, int do_encrypt);",
        "                     u_int aadlen, u_int dest_aadlen,\n"
        "                     unsigned int drop_first, u_char *padding_length_out,\n"
        "                     int do_encrypt);",
        "extend ChaCha-Poly API for padding-byte omission",
    )

    cipher_c = root / "src/cipher-chachapoly.c"
    replace_function(
        cipher_c, "int\nchachapoly_crypt(", CHACHAPOLY_FUNCTION
    )

    crypt_c = root / "src/crypt.c"
    replace_once(
        crypt_c,
        "                                   ((u_int)buf_len) - 4, 4, 4,\n"
        "                                   ctx->encrypt);",
        "                                   ((u_int)buf_len) - 4, 4, 4,\n"
        "                                   0U, NULL, ctx->encrypt);",
        "keep legacy encryption in four-byte-AAD mode",
    )
    replace_once(
        crypt_c,
        "                       4, 4, ctx->encrypt);",
        "                       4, 4, 0U, NULL, ctx->encrypt);",
        "keep legacy in-place decryption in four-byte-AAD mode",
    )

    helper_old = (
        "                                 unsigned int payload_len,\n"
        "                                 unsigned int tag_len,\n"
        "                                 void **abstract)"
    )
    helper_new = (
        "                                 unsigned int payload_len,\n"
        "                                 unsigned int tag_len,\n"
        "                                 unsigned char *padding_length,\n"
        "                                 void **abstract)"
    )
    replace_once(crypt_c, helper_old, helper_new, "expose separately decoded padding length")
    replace_once(
        crypt_c,
        "    rc = chachapoly_crypt(session, &ctx->chachapoly_ctx, seqno,\n"
        "                          destination, source, payload_len, 4U, 0U, 0);\n"
        "    if(rc == 0)\n"
        "        memset(destination + payload_len, 0, tag_len);\n"
        "    return rc;",
        "    rc = chachapoly_crypt(session, &ctx->chachapoly_ctx, seqno,\n"
        "                          destination, source, payload_len, 4U, 0U,\n"
        "                          1U, padding_length, 0);\n"
        "    return rc;",
        "decrypt normalized body and do not reserve or clear an output tag",
    )

    priv_h = root / "src/libssh2_priv.h"
    replace_once(
        priv_h,
        "                                     unsigned int payload_len,\n"
        "                                     unsigned int tag_len,\n"
        "                                     void **abstract);",
        "                                     unsigned int payload_len,\n"
        "                                     unsigned int tag_len,\n"
        "                                     unsigned char *padding_length,\n"
        "                                     void **abstract);",
        "update transport helper prototype",
    )

    transport_c = root / "src/transport.c"
    replace_once(
        transport_c,
        "            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {\n"
        "                int out_of_place_chachapoly =\n",
        "            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {\n"
        "                int out_of_place_chachapoly =\n",
        "retain the r55 cipher gate while extending its helper call",
    )
    replace_once(
        transport_c,
        "                        (unsigned int)numdecrypt, auth_len,\n"
        "                        &session->remote.crypt_abstract);",
        "                        (unsigned int)numdecrypt, auth_len,\n"
        "                        &p->padding_length,\n"
        "                        &session->remote.crypt_abstract);",
        "receive padding length separately from normalized output",
    )
    replace_once(
        transport_c,
        "                p->padding_length = p->wptr[0];\n\n"
        "                if(p->padding_length > p->packet_length - 1) {",
        "                if(!out_of_place_chachapoly)\n"
        "                    p->padding_length = p->wptr[0];\n\n"
        "                if(p->padding_length > p->packet_length - 1) {",
        "preserve padding validation without reading packet type as padding length",
    )
    replace_once(
        transport_c,
        "                numdecrypt += auth_len;\n",
        "                numdecrypt += auth_len;\n"
        "                if(out_of_place_chachapoly) {\n"
        "                    if(p->total_num < (size_t)auth_len + 1U)\n"
        "                        return LIBSSH2_ERROR_DECRYPT;\n"
        "                    p->total_num -= (size_t)auth_len + 1U;\n"
        "                    numwrite = numdecrypt - (ssize_t)auth_len - 1;\n"
        "                }\n"
        "                else\n"
        "                    numwrite = numdecrypt;\n",
        "account for the omitted padding byte and discarded authentication tag",
    )
    replace_once(
        transport_c,
        "        if(numdecrypt > 0) {\n            /* now decrypt the lot */",
        "        if(numdecrypt > 0) {\n"
        "            ssize_t numwrite = numdecrypt;\n"
        "            /* now decrypt the lot */",
        "track stored plaintext bytes separately from consumed wire bytes",
    )
    replace_once(
        transport_c,
        "            p->wptr += numdecrypt;\n"
        "            /* increase data_num */\n"
        "            p->data_num += numdecrypt;",
        "            p->wptr += numwrite;\n"
        "            /* increase data_num */\n"
        "            p->data_num += numwrite;",
        "advance output pointers by normalized plaintext length",
    )
    replace_once(
        transport_c,
        "        else if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {\n"
        "            /* etm trim off padding byte from payload */\n"
        "            memmove(p->payload, &p->payload[1], p->packet_length - 1);\n"
        "        }",
        "        else if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET) &&\n"
        "                strcmp(session->remote.crypt->name,\n"
        "                       \"chacha20-poly1305@openssh.com\") != 0) {\n"
        "            /* Other full-packet ciphers still need padding-byte removal. */\n"
        "            memmove(p->payload, &p->payload[1], p->packet_length - 1);\n"
        "        }",
        "skip the padding memmove only for the already-normalized ChaCha body",
    )

    marker.write_text(
        ".passwall-r56-skip-padding-memmove-patched\n"
        "libssh2 1.11.1 Passwall r56 authenticated normalized ChaCha body output\n"
    )
    print(
        "PASS: r56 authenticates the original packet, exports padding length, "
        "writes normalized packet bytes directly, and skips the ChaCha padding memmove"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r56_skip_padding.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
