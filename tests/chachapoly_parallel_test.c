/*
 * Passwall r55: ChaCha20-Poly1305 authentication and out-of-place decrypt.
 * Verifies serial/in-place compatibility, body-only output, unchanged
 * ciphertext input, worker-count equivalence, block tails and tag rejection.
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
          unsigned int seed, u_int payload_len, unsigned int workers)
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
    u_int seqnr = seed * 17U + payload_len;
    int rc = -1;

    if(!plain || !wire || !cipher_copy || !cipher_guard ||
       !bad || !bad_guard || !body) {
        fprintf(stderr, "allocation failed for payload %u\n", payload_len);
        goto out;
    }

    for(size_t i = 0; i < packet_len; i++)
        plain[i] = (unsigned char)pattern_byte(seed, i);
    memcpy(wire, plain, packet_len);

    if(chachapoly_crypt(NULL, encrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 1) != 0) {
        fprintf(stderr, "serial encryption failed for payload %u\n", payload_len);
        goto out;
    }
    memcpy(cipher_copy, wire, wire_len);
    memcpy(cipher_guard, wire, wire_len);

    /* Existing in-place API remains byte-for-byte compatible. */
    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 0) != 0) {
        fprintf(stderr, "in-place decryption failed for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }
    if(memcmp(wire, plain, packet_len) != 0) {
        fprintf(stderr, "in-place plaintext mismatch for payload %u with %u workers\n",
                payload_len, workers);
        goto out;
    }

    /* r55 output has no four-byte AAD prefix; the authenticated source stays intact. */
    memset(body, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, body, cipher_copy,
                        payload_len, PACKET_HEADER_LEN, 0U, 0) != 0) {
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

    /* A corrupt tag must leave both ciphertext and destination untouched. */
    memcpy(bad, cipher_guard, wire_len);
    bad[wire_len - 1U] ^= 0x80U;
    memcpy(bad_guard, bad, wire_len);
    memset(body, OUTPUT_SENTINEL, payload_len ? payload_len : 1U);
    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, body, bad,
                        payload_len, PACKET_HEADER_LEN, 0U, 0) == 0) {
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

    /* Retain the in-place tamper regression as an independent compatibility gate. */
    memcpy(bad, cipher_guard, wire_len);
    bad[wire_len - 1U] ^= 0x80U;
    memcpy(bad_guard, bad, wire_len);
    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, bad, bad,
                        payload_len, PACKET_HEADER_LEN, PACKET_HEADER_LEN, 0) == 0) {
        fprintf(stderr, "in-place tampered tag accepted for payload %u\n", payload_len);
        goto out;
    }
    if(memcmp(bad, bad_guard, wire_len) != 0) {
        fprintf(stderr, "in-place packet changed before tag rejection for payload %u\n",
                payload_len);
        goto out;
    }

    rc = 0;
out:
    free(plain);
    free(wire);
    free(cipher_copy);
    free(cipher_guard);
    free(bad);
    free(bad_guard);
    free(body);
    return rc;
}

int
main(void)
{
    static const u_int lengths[] = {
        0U, 1U, 63U, 64U, 65U, 4095U, 4096U, 4097U,
        8191U, 8192U, 16384U, MAX_PAYLOAD
    };
    static const unsigned int worker_counts[] = { 1U, 2U, 3U, 4U };
    unsigned char key[64];
    struct chachapoly_ctx encrypt_ctx;
    struct chachapoly_ctx decrypt_ctx[4];
    size_t i, j;

    memset(&encrypt_ctx, 0, sizeof(encrypt_ctx));
    memset(decrypt_ctx, 0, sizeof(decrypt_ctx));
    for(i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)pattern_byte(0x48U, i);

    if(chachapoly_init(&encrypt_ctx, key, sizeof(key), 0U) != 0) {
        fprintf(stderr, "serial encrypt context initialization failed\n");
        return 1;
    }
    for(i = 0; i < sizeof(worker_counts) / sizeof(worker_counts[0]); i++) {
        if(chachapoly_init(&decrypt_ctx[i], key, sizeof(key),
                           worker_counts[i]) != 0) {
            fprintf(stderr, "ChaCha worker pool initialization failed (%u)\n",
                    worker_counts[i]);
            for(j = 0; j < 4U; j++)
                chachapoly_cleanup(&decrypt_ctx[j]);
            chachapoly_cleanup(&encrypt_ctx);
            return 1;
        }
        if(chachapoly_parallel_workers(&decrypt_ctx[i]) != worker_counts[i]) {
            fprintf(stderr, "requested %u ChaCha workers were not created\n",
                    worker_counts[i]);
            for(j = 0; j < 4U; j++)
                chachapoly_cleanup(&decrypt_ctx[j]);
            chachapoly_cleanup(&encrypt_ctx);
            return 1;
        }
    }

    for(i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(j = 0; j < sizeof(worker_counts) / sizeof(worker_counts[0]); j++) {
            if(test_case(&encrypt_ctx, &decrypt_ctx[j],
                         0x4800U + (unsigned int)(i * 16U + j),
                         lengths[i], worker_counts[j]) != 0) {
                for(j = 0; j < 4U; j++)
                    chachapoly_cleanup(&decrypt_ctx[j]);
                chachapoly_cleanup(&encrypt_ctx);
                return 1;
            }
        }
    }

    for(i = 0; i < 4U; i++)
        chachapoly_cleanup(&decrypt_ctx[i]);
    chachapoly_cleanup(&encrypt_ctx);
    puts("PASS: ChaCha20-Poly1305 auth-first in-place/out-of-place decrypt, source integrity, tails and tag rejection");
    return 0;
}
