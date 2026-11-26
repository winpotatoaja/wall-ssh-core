/*
 * Passwall r56: authenticated normalized ChaCha20-Poly1305 output.
 * Verifies in-place compatibility, body-only output, padding-byte omission,
 * unchanged ciphertext input, worker-count equivalence, tails and tag rejection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2_priv.h"
#include "cipher-chachapoly.h"

#define PACKET_HEADER_LEN 4U
#define POLY_TAG_LEN 16U
#define MAX_PAYLOAD 32768U
#define OUTPUT_SENTINEL 0xa5U

static unsigned int
pattern_byte(unsigned int seed, size_t offset)
{
    unsigned int x = seed ^ (unsigned int)(offset * 0x9e3779b1U);
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x & 0xffU;
}

static int
all_bytes_are(const unsigned char *data, size_t length, unsigned char value)
{
    size_t i;
    for(i = 0; i < length; i++) {
        if(data[i] != value)
            return 0;
    }
    return 1;
}

static int
test_case(struct chachapoly_ctx *encrypt_ctx,
          struct chachapoly_ctx *decrypt_ctx,
          unsigned int seed, u_int payload_len, unsigned int workers,
          unsigned int threshold_bytes)
{
    size_t packet_len = PACKET_HEADER_LEN + (size_t)payload_len;
    size_t wire_len = packet_len + POLY_TAG_LEN;
    unsigned char *plain = (unsigned char *)malloc(packet_len ? packet_len : 1U);
    unsigned char *wire = (unsigned char *)malloc(wire_len);
    unsigned char *cipher_copy = (unsigned char *)malloc(wire_len);
    unsigned char *cipher_guard = (unsigned char *)malloc(wire_len);
    unsigned char *bad = (unsigned char *)malloc(wire_len);
    unsigned char *bad_guard = (unsigned char *)malloc(wire_len);
    unsigned char *body = (unsigned char *)malloc(payload_len ? payload_len : 1U);
    unsigned char *body_without_pad = (unsigned char *)malloc(payload_len ? payload_len : 1U);
    unsigned char padding_length = OUTPUT_SENTINEL;
    u_int seqnr = seed * 17U + payload_len;
    LIBSSH2_SESSION diag_session;
    LIBSSH2_SESSION bad_diag_session;
    unsigned int successful_decrypt_calls = payload_len == 0U ? 2U : 3U;
    unsigned int expected_offload =
        workers > 0U && payload_len >= threshold_bytes ? 3U : 0U;
    int rc = -1;

    memset(&diag_session, 0, sizeof(diag_session));
    memset(&bad_diag_session, 0, sizeof(bad_diag_session));
    diag_session.passwall_diag.enabled = 1;
    bad_diag_session.passwall_diag.enabled = 1;

    if(!plain || !wire || !cipher_copy || !cipher_guard ||
       !bad || !bad_guard || !body || !body_without_pad) {
        fprintf(stderr, "allocation failed for payload %u\n", payload_len);
        goto out;
    }

    for(size_t i = 0; i < packet_len; i++)
        plain[i] = (unsigned char)pattern_byte(seed, i);
    memcpy(wire, plain, packet_len);

    if(chachapoly_crypt(NULL, encrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 0U, NULL, 1) != 0) {
        fprintf(stderr, "serial encryption failed for payload %u\n", payload_len);
        goto out;
    }
    memcpy(cipher_copy, wire, wire_len);
    memcpy(cipher_guard, wire, wire_len);

    /* Existing in-place API remains byte-for-byte compatible. */
    if(chachapoly_crypt(&diag_session, decrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 0U, NULL, 0) != 0) {
        fprintf(stderr, "in-place decryption failed for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }
    if(memcmp(wire, plain, packet_len) != 0) {
        fprintf(stderr, "in-place plaintext mismatch for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }

    /* r55 body-only output has no four-byte AAD prefix; source stays intact. */
    memset(body, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    if(chachapoly_crypt(&diag_session, decrypt_ctx, seqnr, body, cipher_copy,
                        payload_len, PACKET_HEADER_LEN, 0U, 0U, NULL, 0) != 0) {
        fprintf(stderr, "out-of-place body decrypt failed for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }
    if(payload_len && memcmp(body, plain + PACKET_HEADER_LEN, payload_len) != 0) {
        fprintf(stderr, "out-of-place body mismatch for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }
    if(memcmp(cipher_copy, cipher_guard, wire_len) != 0) {
        fprintf(stderr, "ciphertext source changed on successful out-of-place decrypt (%u)\n",
                payload_len);
        goto out;
    }

    /* r56 emits packet bytes after padding_length directly at output offset 0. */
    memset(body_without_pad, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    padding_length = OUTPUT_SENTINEL;
    if(chachapoly_crypt(&diag_session, decrypt_ctx, seqnr, body_without_pad, cipher_copy,
                        payload_len, PACKET_HEADER_LEN, 0U, 1U,
                        &padding_length, 0) == 0) {
        if(payload_len == 0U) {
            fprintf(stderr, "padding-byte omission accepted an empty packet body\n");
            goto out;
        }
    }
    else if(payload_len == 0U) {
        /* A zero-byte packet has no padding-length byte to omit. */
        if(padding_length != OUTPUT_SENTINEL ||
           !all_bytes_are(body_without_pad, 1U, OUTPUT_SENTINEL)) {
            fprintf(stderr, "empty padding-byte omission changed its outputs\n");
            goto out;
        }
    }
    if(payload_len > 0U) {
        if(padding_length != plain[PACKET_HEADER_LEN] ||
           (payload_len > 1U &&
            memcmp(body_without_pad, plain + PACKET_HEADER_LEN + 1U,
                   payload_len - 1U) != 0)) {
            fprintf(stderr, "r56 normalized output mismatch for payload %u with %u workers\n",
                    payload_len, workers);
            goto out;
        }
    }
    if(payload_len > 0U && body_without_pad[payload_len - 1U] != OUTPUT_SENTINEL) {
        fprintf(stderr, "r56 normalized output wrote past payload_len - 1 for payload %u\n",
                payload_len);
        goto out;
    }
    if(memcmp(cipher_copy, cipher_guard, wire_len) != 0) {
        fprintf(stderr, "r56 normalized decrypt modified its ciphertext source (%u)\n",
                payload_len);
        goto out;
    }

    /* A corrupt tag must leave both ciphertext and destination untouched. */
    memcpy(bad, cipher_guard, wire_len);
    bad[wire_len - 1U] ^= 0x80U;
    memcpy(bad_guard, bad, wire_len);
    memset(body, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    if(chachapoly_crypt(&bad_diag_session, decrypt_ctx, seqnr, body, bad,
                        payload_len, PACKET_HEADER_LEN, 0U, 0U, NULL, 0) == 0) {
        fprintf(stderr, "out-of-place tampered tag accepted for payload %u\n",
                payload_len);
        goto out;
    }
    if(payload_len && !all_bytes_are(body, payload_len, OUTPUT_SENTINEL)) {
        fprintf(stderr, "destination changed before tag rejection for payload %u\n",
                payload_len);
        goto out;
    }
    if(memcmp(bad, bad_guard, wire_len) != 0) {
        fprintf(stderr, "ciphertext changed on rejected out-of-place decrypt (%u)\n",
                payload_len);
        goto out;
    }

    /* Failed authentication must not expose either normalized bytes or pad length. */
    memset(body_without_pad, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    padding_length = OUTPUT_SENTINEL;
    if(chachapoly_crypt(&bad_diag_session, decrypt_ctx, seqnr, body_without_pad, bad,
                        payload_len, PACKET_HEADER_LEN, 0U, 1U,
                        &padding_length, 0) == 0) {
        fprintf(stderr, "r56 normalized output accepted a bad tag for payload %u\n",
                payload_len);
        goto out;
    }
    if(padding_length != OUTPUT_SENTINEL ||
       !all_bytes_are(body_without_pad, payload_len ? payload_len : 1U,
                      OUTPUT_SENTINEL)) {
        fprintf(stderr, "r56 wrote normalized output before authentication for payload %u\n",
                payload_len);
        goto out;
    }
    if(memcmp(bad, bad_guard, wire_len) != 0) {
        fprintf(stderr, "r56 failed-auth path modified ciphertext for payload %u\n",
                payload_len);
        goto out;
    }

    /* Retain the in-place tamper regression as an independent compatibility gate. */
    memcpy(bad, cipher_guard, wire_len);
    bad[wire_len - 1U] ^= 0x80U;
    memcpy(bad_guard, bad, wire_len);
    if(chachapoly_crypt(&bad_diag_session, decrypt_ctx, seqnr, bad, bad,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 0U, NULL, 0) == 0) {
        fprintf(stderr, "in-place tampered tag accepted for payload %u\n", payload_len);
        goto out;
    }
    if(memcmp(bad, bad_guard, wire_len) != 0) {
        fprintf(stderr, "in-place packet changed before tag rejection for payload %u\n",
                payload_len);
        goto out;
    }

    if(diag_session.passwall_diag.chacha_poly1305_offloaded_packets !=
       (unsigned long long)expected_offload) {
        fprintf(stderr, "dispatch mismatch workers=%u threshold=%u payload=%u "
                "offloaded=%llu expected=%u\n", workers, threshold_bytes,
                payload_len,
                diag_session.passwall_diag.chacha_poly1305_offloaded_packets,
                expected_offload);
        goto out;
    }
    if(expected_offload &&
       (diag_session.passwall_diag.chacha20_worker_cpu_ns == 0ULL ||
        diag_session.passwall_diag.chacha20_worker_critical_ns == 0ULL)) {
        fprintf(stderr, "worker execution counters missing workers=%u "
                "threshold=%u payload=%u\n",
                workers, threshold_bytes, payload_len);
        goto out;
    }

    /* R63: every successful packet must be either worker-dispatched or serial.
     * This catches the old fixed-4-KiB helper bypassing the configured threshold. */
    if(bad_diag_session.passwall_diag.chacha_poly1305_offloaded_packets != 0ULL ||
       bad_diag_session.passwall_diag.chacha20_parallel_packets != 0ULL ||
       bad_diag_session.passwall_diag.chacha20_serial_packets != 0ULL) {
        fprintf(stderr, "R63 bad-tag path dispatched or counted crypto work "
                "workers=%u threshold=%u payload=%u serial=%llu parallel=%llu offloaded=%llu\n",
                workers, threshold_bytes, payload_len,
                bad_diag_session.passwall_diag.chacha20_serial_packets,
                bad_diag_session.passwall_diag.chacha20_parallel_packets,
                bad_diag_session.passwall_diag.chacha_poly1305_offloaded_packets);
        goto out;
    }

    if(diag_session.passwall_diag.chacha20_parallel_packets !=
           (unsigned long long)expected_offload ||
       diag_session.passwall_diag.chacha20_serial_packets !=
           (unsigned long long)(successful_decrypt_calls - expected_offload)) {
        fprintf(stderr, "R63 threshold bypass: workers=%u threshold=%u payload=%u "
                "serial_packets=%llu parallel_packets=%llu expected_serial=%u "
                "expected_parallel=%u successful_calls=%u\n",
                workers, threshold_bytes, payload_len,
                diag_session.passwall_diag.chacha20_serial_packets,
                diag_session.passwall_diag.chacha20_parallel_packets,
                successful_decrypt_calls - expected_offload, expected_offload,
                successful_decrypt_calls);
        goto out;
    }
    if(threshold_bytes != 4096U)
        printf("R63_AB workers=%u threshold_kib=%u payload=%u offloaded=%u\n",
               workers, threshold_bytes / 1024U, payload_len,
               expected_offload != 0U);
    rc = 0;
out:
    free(plain);
    free(wire);
    free(cipher_copy);
    free(cipher_guard);
    free(bad);
    free(bad_guard);
    free(body);
    free(body_without_pad);
    return rc;
}


static int
test_r59_profile(struct chachapoly_ctx *encrypt_ctx,
                 struct chachapoly_ctx *decrypt_ctx,
                 unsigned int workers, u_int payload_len, unsigned int seed)
{
    size_t packet_len = PACKET_HEADER_LEN + (size_t)payload_len;
    size_t wire_len = packet_len + POLY_TAG_LEN;
    unsigned char *plain = (unsigned char *)malloc(packet_len);
    unsigned char *wire = (unsigned char *)malloc(wire_len);
    unsigned char *body = (unsigned char *)malloc(payload_len);
    unsigned char padding_length = OUTPUT_SENTINEL;
    unsigned int i;
    int rc = -1;
    LIBSSH2_SESSION diag_session;

    if(!plain || !wire || !body) {
        fprintf(stderr, "r57 profile allocation failed\n");
        goto out;
    }

    memset(&diag_session, 0, sizeof(diag_session));
    diag_session.passwall_diag.enabled = 1;
    for(i = 0U; i < packet_len; i++)
        plain[i] = (unsigned char)pattern_byte(seed, i);
    plain[PACKET_HEADER_LEN] = 16U;
    memcpy(wire, plain, packet_len);

    if(chachapoly_crypt(NULL, encrypt_ctx, seed + payload_len,
                        wire, wire, payload_len,
                        PACKET_HEADER_LEN, PACKET_HEADER_LEN,
                        0U, NULL, 1) != 0) {
        fprintf(stderr, "r57 profile encryption failed\n");
        goto out;
    }

    if(chachapoly_crypt(&diag_session, decrypt_ctx, seed + payload_len,
                        body, wire, payload_len,
                        PACKET_HEADER_LEN, 0U, 1U,
                        &padding_length, 0) != 0) {
        fprintf(stderr, "r57 profiled normalized decrypt failed (workers=%u)\n",
                workers);
        goto out;
    }

    if(padding_length != plain[PACKET_HEADER_LEN] ||
       memcmp(body, plain + PACKET_HEADER_LEN + 1U, payload_len - 1U) != 0) {
        fprintf(stderr, "r57 profiled normalized plaintext mismatch\n");
        goto out;
    }

    if(diag_session.passwall_diag.chacha_poly1305_ns == 0ULL ||
       diag_session.passwall_diag.chacha_poly1305_wall_ns == 0ULL ||
       diag_session.passwall_diag.chacha_poly1305_wall_ns !=
           diag_session.passwall_diag.chacha_poly1305_ns ||
       diag_session.passwall_diag.chacha20_decrypt_wall_ns == 0ULL ||
       diag_session.passwall_diag.chacha20_worker_cpu_ns == 0ULL ||
       diag_session.passwall_diag.chacha20_worker_critical_ns == 0ULL ||
       diag_session.passwall_diag.chacha20_profile_packets != 1ULL ||
       diag_session.passwall_diag.chacha_poly1305_offloaded_packets != 1ULL ||
       diag_session.passwall_diag.chacha20_worker_cpu_ns <
           diag_session.passwall_diag.chacha20_worker_critical_ns) {
        fprintf(stderr, "r59 inline Poly1305 and r57 phase timing counters missing or inconsistent "
                "(workers=%u)\n", workers);
        goto out;
    }

    printf("R59_PROFILE payload=%u workers=%u poly_worker_ns=%llu "
           "poly_wall_ns=%llu chacha_wall_ns=%llu worker_cpu_ns=%llu "
           "worker_critical_ns=%llu coordinator_other_ns=%llu\n",
           payload_len, workers,
           diag_session.passwall_diag.chacha_poly1305_ns,
           diag_session.passwall_diag.chacha_poly1305_wall_ns,
           diag_session.passwall_diag.chacha20_decrypt_wall_ns,
           diag_session.passwall_diag.chacha20_worker_cpu_ns,
           diag_session.passwall_diag.chacha20_worker_critical_ns,
           diag_session.passwall_diag.chacha20_parallel_other_ns);
    rc = 0;

out:
    free(plain);
    free(wire);
    free(body);
    return rc;
}

static int
test_r63_threshold_matrix(const unsigned char key[64],
                          struct chachapoly_ctx *encrypt_ctx)
{
    static const unsigned int worker_counts[] = { 0U, 1U, 2U, 3U };
    static const unsigned int thresholds[] = {
        4096U, 8192U, 16384U, 24576U, 32768U
    };
    unsigned int seed = 0x620000U;
    size_t i, j, k;

    for(i = 0U; i < sizeof(thresholds) / sizeof(thresholds[0]); i++) {
        struct chachapoly_ctx decrypt_ctx[4];
        memset(decrypt_ctx, 0, sizeof(decrypt_ctx));
        for(j = 0U; j < sizeof(worker_counts) / sizeof(worker_counts[0]); j++) {
            if(chachapoly_init(&decrypt_ctx[j], key, 64U,
                               worker_counts[j], thresholds[i]) != 0) {
                fprintf(stderr, "R63 context init failed workers=%u threshold=%u\n",
                        worker_counts[j], thresholds[i]);
                for(k = 0U; k < 4U; k++)
                    chachapoly_cleanup(&decrypt_ctx[k]);
                return -1;
            }
            if(chachapoly_parallel_workers(&decrypt_ctx[j]) != worker_counts[j]) {
                fprintf(stderr, "R63 pool worker mismatch requested=%u actual=%u\n",
                        worker_counts[j],
                        chachapoly_parallel_workers(&decrypt_ctx[j]));
                for(k = 0U; k < 4U; k++)
                    chachapoly_cleanup(&decrypt_ctx[k]);
                return -1;
            }
        }

        for(j = 0U; j < sizeof(worker_counts) / sizeof(worker_counts[0]); j++) {
            const u_int lengths[3] = {
                thresholds[i] - 1U, thresholds[i], thresholds[i] + 1U
            };
            for(k = 0U; k < 3U; k++) {
                if(test_case(encrypt_ctx, &decrypt_ctx[j], seed++,
                             lengths[k], worker_counts[j], thresholds[i]) != 0) {
                    for(size_t n = 0U; n < 4U; n++)
                        chachapoly_cleanup(&decrypt_ctx[n]);
                    return -1;
                }
            }
        }
        for(j = 0U; j < 4U; j++)
            chachapoly_cleanup(&decrypt_ctx[j]);
    }
    return 0;
}

int
main(void)
{
    static const u_int lengths[] = {
        0U, 1U, 63U, 64U, 65U, 4095U, 4096U, 4097U,
        8191U, 8192U, 16384U, MAX_PAYLOAD
    };
    static const unsigned int worker_counts[] = { 0U, 1U, 2U, 3U, 4U };
    unsigned char key[64];
    struct chachapoly_ctx encrypt_ctx;
    struct chachapoly_ctx decrypt_ctx[5];
    size_t i, j;

    memset(&encrypt_ctx, 0, sizeof(encrypt_ctx));
    memset(decrypt_ctx, 0, sizeof(decrypt_ctx));
    for(i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)pattern_byte(0x48U, i);

    if(chachapoly_init(&encrypt_ctx, key, sizeof(key), 0U, 4096U) != 0) {
        fprintf(stderr, "serial encrypt context initialization failed\n");
        return 1;
    }
    for(i = 0; i < sizeof(worker_counts) / sizeof(worker_counts[0]); i++) {
        if(chachapoly_init(&decrypt_ctx[i], key, sizeof(key),
                           worker_counts[i], 4096U) != 0) {
            fprintf(stderr, "ChaCha worker pool initialization failed (%u)\n",
                    worker_counts[i]);
            for(j = 0; j < 5U; j++)
                chachapoly_cleanup(&decrypt_ctx[j]);
            chachapoly_cleanup(&encrypt_ctx);
            return 1;
        }
        if(chachapoly_parallel_workers(&decrypt_ctx[i]) != worker_counts[i]) {
            fprintf(stderr, "requested %u ChaCha workers were not created\n",
                    worker_counts[i]);
            for(j = 0; j < 5U; j++)
                chachapoly_cleanup(&decrypt_ctx[j]);
            chachapoly_cleanup(&encrypt_ctx);
            return 1;
        }
    }

    for(i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(j = 0; j < sizeof(worker_counts) / sizeof(worker_counts[0]); j++) {
            if(test_case(&encrypt_ctx, &decrypt_ctx[j],
                         0x4800U + (unsigned int)(i * 16U + j),
                         lengths[i], worker_counts[j], 4096U) != 0) {
                for(j = 0; j < 5U; j++)
                    chachapoly_cleanup(&decrypt_ctx[j]);
                chachapoly_cleanup(&encrypt_ctx);
                return 1;
            }
        }
    }

    for(i = 1U; i < 5U; i++) {
        static const u_int profile_lengths[] = { 4096U, 16384U, MAX_PAYLOAD };
        for(j = 0U; j < sizeof(profile_lengths) / sizeof(profile_lengths[0]); j++) {
            if(test_r59_profile(&encrypt_ctx, &decrypt_ctx[i],
                                worker_counts[i], profile_lengths[j],
                                0x570000U + (unsigned int)(i * 32U + j)) != 0) {
                for(j = 0; j < 5U; j++)
                    chachapoly_cleanup(&decrypt_ctx[j]);
                chachapoly_cleanup(&encrypt_ctx);
                return 1;
            }
        }
    }

    for(i = 0; i < 5U; i++)
        chachapoly_cleanup(&decrypt_ctx[i]);
    if(test_r63_threshold_matrix(key, &encrypt_ctx) != 0) {
        chachapoly_cleanup(&encrypt_ctx);
        return 1;
    }
    chachapoly_cleanup(&encrypt_ctx);
    puts("PASS: R63 threshold gate 0/1/2/3 workers and 4/8/16/24/32 KiB; serial/parallel counters enforced");
    return 0;
}
