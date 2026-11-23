/*
 * Passwall r47: ChaCha20-Poly1305 packet parallelism regression.
 * Verifies serial encryption against one- and three-worker decryption,
 * including block tails and authentication failure before in-place writes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh2_priv.h"
#include "cipher-chachapoly.h"

#define PACKET_HEADER_LEN 4U
#define POLY_TAG_LEN 16U
#define MAX_PAYLOAD 32768U

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
test_case(struct chachapoly_ctx *encrypt_ctx,
          struct chachapoly_ctx *decrypt_ctx,
          unsigned int seed, u_int payload_len)
{
    size_t packet_len = PACKET_HEADER_LEN + (size_t)payload_len;
    size_t wire_len = packet_len + POLY_TAG_LEN;
    unsigned char *plain = (unsigned char *)malloc(packet_len ? packet_len : 1U);
    unsigned char *wire = (unsigned char *)malloc(wire_len ? wire_len : 1U);
    unsigned char *bad = (unsigned char *)malloc(wire_len ? wire_len : 1U);
    unsigned char *before = (unsigned char *)malloc(wire_len ? wire_len : 1U);
    u_int seqnr = seed * 17U + payload_len;
    int rc = -1;

    if(!plain || !wire || !bad || !before) {
        fprintf(stderr, "allocation failed for payload %u\n", payload_len);
        goto out;
    }

    for(size_t i = 0; i < packet_len; i++)
        plain[i] = (unsigned char)pattern_byte(seed, i);
    memcpy(wire, plain, packet_len);

    if(chachapoly_crypt(NULL, encrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, 1) != 0) {
        fprintf(stderr, "serial encryption failed for payload %u\n", payload_len);
        goto out;
    }

    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, wire, wire,
                        payload_len, PACKET_HEADER_LEN, 0) != 0) {
        fprintf(stderr, "parallel decryption failed for payload %u\n", payload_len);
        goto out;
    }
    if(memcmp(wire, plain, packet_len) != 0) {
        fprintf(stderr, "plaintext mismatch for payload %u\n", payload_len);
        goto out;
    }

    memcpy(bad, wire, packet_len);
    /* Re-encrypt so the failure test starts with authenticated ciphertext. */
    if(chachapoly_crypt(NULL, encrypt_ctx, seqnr, bad, bad,
                        payload_len, PACKET_HEADER_LEN, 1) != 0) {
        fprintf(stderr, "second serial encryption failed for payload %u\n", payload_len);
        goto out;
    }
    bad[packet_len + POLY_TAG_LEN - 1U] ^= 0x80U;
    memcpy(before, bad, wire_len);
    if(chachapoly_crypt(NULL, decrypt_ctx, seqnr, bad, bad,
                        payload_len, PACKET_HEADER_LEN, 0) == 0) {
        fprintf(stderr, "tampered tag accepted for payload %u\n", payload_len);
        goto out;
    }
    if(memcmp(bad, before, wire_len) != 0) {
        fprintf(stderr, "packet changed before tag rejection for payload %u\n", payload_len);
        goto out;
    }

    rc = 0;
out:
    free(plain);
    free(wire);
    free(bad);
    free(before);
    return rc;
}

int
main(void)
{
    static const u_int lengths[] = {
        0U, 1U, 63U, 64U, 65U, 4095U, 4096U, 4097U,
        8191U, 8192U, 16384U, MAX_PAYLOAD
    };
    unsigned char key[64];
    struct chachapoly_ctx encrypt_ctx;
    struct chachapoly_ctx decrypt_ctx_1;
    struct chachapoly_ctx decrypt_ctx_3;

    for(size_t i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)pattern_byte(0x47U, i);

    if(chachapoly_init(&encrypt_ctx, key, sizeof(key), 0U) != 0 ||
       chachapoly_init(&decrypt_ctx_1, key, sizeof(key), 1U) != 0 ||
       chachapoly_init(&decrypt_ctx_3, key, sizeof(key), 3U) != 0) {
        fprintf(stderr, "ChaCha-Poly context initialization failed\n");
        return 1;
    }

    if(chachapoly_parallel_workers(&decrypt_ctx_1) != 1U ||
       chachapoly_parallel_workers(&decrypt_ctx_3) != 3U) {
        fprintf(stderr, "requested ChaCha worker pools were not created\n");
        chachapoly_cleanup(&decrypt_ctx_3);
        chachapoly_cleanup(&decrypt_ctx_1);
        chachapoly_cleanup(&encrypt_ctx);
        return 1;
    }

    for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        if(test_case(&encrypt_ctx, &decrypt_ctx_1, 0x1100U + (unsigned int)i,
                     lengths[i]) != 0 ||
           test_case(&encrypt_ctx, &decrypt_ctx_3, 0x2200U + (unsigned int)i,
                     lengths[i]) != 0) {
            chachapoly_cleanup(&decrypt_ctx_3);
            chachapoly_cleanup(&decrypt_ctx_1);
            chachapoly_cleanup(&encrypt_ctx);
            return 1;
        }
    }

    chachapoly_cleanup(&decrypt_ctx_3);
    chachapoly_cleanup(&decrypt_ctx_1);
    chachapoly_cleanup(&encrypt_ctx);
    puts("PASS: ChaCha20-Poly1305 serial/parallel equivalence, tails and tag rejection");
    return 0;
}
