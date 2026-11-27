#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUARD 8U

static const size_t valid_lengths[] = {
    16U, 32U, 64U, 1024U, 4096U, 16384U, 32768U, 34992U, 35008U
};
static const size_t split_pattern[] = {16U, 256U, 1024U, 4096U, 64U};

static void
fill_bytes(unsigned char *buffer, size_t length, unsigned int seed)
{
    uint32_t state = seed ? seed : 0x9e3779b9U;
    size_t i;

    for(i = 0U; i < length; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        buffer[i] = (unsigned char)(state >> 9);
    }
}

static int
ranges_disjoint_or_identical(uintptr_t dest, uintptr_t source, size_t len)
{
    if(dest == source)
        return 1;
    if(len > (size_t)(UINTPTR_MAX - dest) ||
       len > (size_t)(UINTPTR_MAX - source))
        return 0;
    return dest >= source + (uintptr_t)len ||
           source >= dest + (uintptr_t)len;
}

static int
checked_outofplace_update(EVP_CIPHER_CTX *ctx, unsigned char *dest,
                          const unsigned char *source, size_t len)
{
    int outl = 0;
    int ret;

    if(len == 0U)
        return 0;
    if(!ctx || !dest || !source || len > (size_t)INT_MAX ||
       (len % 16U) != 0U)
        return 1;
    if(EVP_CIPHER_CTX_mode(ctx) != EVP_CIPH_CTR_MODE ||
       EVP_CIPHER_CTX_nid(ctx) != NID_aes_128_ctr)
        return 1;
    if(!ranges_disjoint_or_identical((uintptr_t)dest,
                                     (uintptr_t)source, len))
        return 1;

    ret = EVP_CipherUpdate(ctx, dest, &outl, source, (int)len);
    return (ret == 1 && outl == (int)len) ? 0 : 1;
}

static EVP_CIPHER_CTX *
new_context(const EVP_CIPHER *cipher, int encrypt,
            const unsigned char key[16], const unsigned char iv[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!ctx)
        return NULL;
    if(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, encrypt) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int
outside_range_is(const unsigned char *buffer, size_t allocation,
                 size_t offset, size_t length, unsigned char sentinel)
{
    size_t i;

    for(i = 0U; i < allocation; i++) {
        if(i < offset || i >= offset + length) {
            if(buffer[i] != sentinel)
                return 0;
        }
    }
    return 1;
}

static int
run_case(size_t length, size_t input_offset, size_t output_offset,
         int wrap_counter, unsigned int seed)
{
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *plain = NULL;
    unsigned char *cipher = NULL;
    unsigned char *cipher_snapshot = NULL;
    unsigned char *out = NULL;
    unsigned char *split_out = NULL;
    unsigned char *inplace = NULL;
    unsigned char *block_loop = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t allocation = length + 2U * GUARD + 8U;
    size_t input_pos = GUARD + input_offset;
    size_t output_pos = GUARD + output_offset;
    size_t pos;
    size_t part = 0U;
    int outl = 0;
    int ok = 0;

    fill_bytes(key, sizeof(key), seed ^ 0x5a17U);
    fill_bytes(iv, sizeof(iv), seed ^ 0x7182U);
    if(wrap_counter)
        memset(iv + 12U, 0xff, 4U);

    plain = (unsigned char *)malloc(allocation);
    cipher = (unsigned char *)malloc(allocation);
    cipher_snapshot = (unsigned char *)malloc(allocation);
    out = (unsigned char *)malloc(allocation);
    split_out = (unsigned char *)malloc(allocation);
    inplace = (unsigned char *)malloc(allocation);
    block_loop = (unsigned char *)malloc(allocation);
    if(!plain || !cipher || !cipher_snapshot || !out || !split_out ||
       !inplace || !block_loop)
        goto cleanup;

    memset(plain, 0xa5, allocation);
    memset(cipher, 0xc3, allocation);
    memset(out, 0x5a, allocation);
    memset(split_out, 0x6b, allocation);
    fill_bytes(plain + input_pos, length, seed ^ (unsigned int)length);

    ctx = new_context(EVP_aes_128_ctr(), 1, key, iv);
    if(!ctx)
        goto cleanup;
    if(EVP_CipherUpdate(ctx, cipher + input_pos, &outl,
                        plain + input_pos, (int)length) != 1 ||
       outl != (int)length)
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    memcpy(cipher_snapshot, cipher, allocation);
    ctx = new_context(EVP_aes_128_ctr(), 0, key, iv);
    if(!ctx)
        goto cleanup;
    if(checked_outofplace_update(ctx, out + output_pos,
                                 cipher + input_pos, length) != 0)
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(out + output_pos, plain + input_pos, length) != 0 ||
       memcmp(cipher, cipher_snapshot, allocation) != 0 ||
       !outside_range_is(out, allocation, output_pos, length, 0x5a))
        goto cleanup;

    /* Several aligned fragments use one persistent counter state. */
    ctx = new_context(EVP_aes_128_ctr(), 0, key, iv);
    if(!ctx)
        goto cleanup;
    for(pos = 0U; pos < length; ) {
        size_t n = split_pattern[part %
            (sizeof(split_pattern) / sizeof(split_pattern[0]))];
        if(n > length - pos)
            n = length - pos;
        if(checked_outofplace_update(ctx, split_out + output_pos + pos,
                                     cipher + input_pos + pos, n) != 0)
            goto cleanup;
        pos += n;
        part++;
        /* A transport EAGAIN can occur between calls; EVP state is retained. */
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(split_out + output_pos, plain + input_pos, length) != 0 ||
       memcmp(cipher, cipher_snapshot, allocation) != 0 ||
       !outside_range_is(split_out, allocation, output_pos, length, 0x6b))
        goto cleanup;

    memcpy(inplace, cipher, allocation);
    ctx = new_context(EVP_aes_128_ctr(), 0, key, iv);
    if(!ctx)
        goto cleanup;
    if(checked_outofplace_update(ctx, inplace + input_pos,
                                 inplace + input_pos, length) != 0)
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(inplace + input_pos, plain + input_pos, length) != 0)
        goto cleanup;

    memcpy(block_loop, cipher, allocation);
    ctx = new_context(EVP_aes_128_ctr(), 0, key, iv);
    if(!ctx)
        goto cleanup;
    for(pos = 0U; pos < length; pos += 16U) {
        if(checked_outofplace_update(ctx, block_loop + input_pos + pos,
                                     block_loop + input_pos + pos, 16U) != 0)
            goto cleanup;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(block_loop + input_pos, plain + input_pos, length) != 0)
        goto cleanup;

    ok = 1;

cleanup:
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(cipher);
    free(cipher_snapshot);
    free(out);
    free(split_out);
    free(inplace);
    free(block_loop);
    return ok;
}

static int
test_rejections(void)
{
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char plain[16];
    unsigned char cipher[16];
    unsigned char output[16];
    unsigned char overlap[128];
    unsigned char snapshot[sizeof(overlap)];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *cbc = NULL;
    int outl = 0;
    int ok = 0;

    fill_bytes(key, sizeof(key), 0x12345678U);
    fill_bytes(iv, sizeof(iv), 0x87654321U);
    fill_bytes(plain, sizeof(plain), 0xdeadbeefU);
    ctx = new_context(EVP_aes_128_ctr(), 1, key, iv);
    if(!ctx)
        goto cleanup;
    if(EVP_CipherUpdate(ctx, cipher, &outl, plain, 16) != 1 || outl != 16)
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = new_context(EVP_aes_128_ctr(), 0, key, iv);
    if(!ctx)
        goto cleanup;

    memset(overlap, 0x7c, sizeof(overlap));
    memcpy(snapshot, overlap, sizeof(overlap));
    if(checked_outofplace_update(ctx, overlap + 1U, overlap + 16U, 32U) == 0 ||
       memcmp(overlap, snapshot, sizeof(overlap)) != 0)
        goto cleanup;
    if(checked_outofplace_update(ctx, overlap + 16U, overlap + 1U, 32U) == 0 ||
       memcmp(overlap, snapshot, sizeof(overlap)) != 0)
        goto cleanup;
    if(checked_outofplace_update(ctx, overlap + 1U, overlap + 64U, 17U) == 0 ||
       memcmp(overlap, snapshot, sizeof(overlap)) != 0)
        goto cleanup;
    /* SSH framing rejects a 35,000-byte fragment: it is not 16-byte aligned. */
    if(checked_outofplace_update(ctx, overlap + 1U, overlap + 64U, 35000U) == 0 ||
       memcmp(overlap, snapshot, sizeof(overlap)) != 0)
        goto cleanup;
    if(checked_outofplace_update(ctx, (unsigned char *)(uintptr_t)1U,
                                 (const unsigned char *)(uintptr_t)2U,
                                 (size_t)INT_MAX + 1U) == 0)
        goto cleanup;
    if(ranges_disjoint_or_identical(UINTPTR_MAX - 7U, 0x1000U, 16U) ||
       ranges_disjoint_or_identical(0x1000U, UINTPTR_MAX - 7U, 16U))
        goto cleanup;

    memset(output, 0, sizeof(output));
    if(checked_outofplace_update(ctx, output, cipher, 16U) != 0 ||
       memcmp(output, plain, sizeof(plain)) != 0)
        goto cleanup; /* Rejected calls must not advance the EVP counter. */

    cbc = new_context(EVP_aes_128_cbc(), 0, key, iv);
    if(!cbc)
        goto cleanup;
    memset(output, 0x44, sizeof(output));
    if(checked_outofplace_update(cbc, output, cipher, 16U) == 0)
        goto cleanup;

    ok = 1;
cleanup:
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);
    if(cbc)
        EVP_CIPHER_CTX_free(cbc);
    return ok;
}

int
main(void)
{
    size_t i;
    size_t in_offset;
    size_t out_offset;
    unsigned int cases = 0U;
    int wrap;

    if(EVP_CIPHER_get_block_size(EVP_aes_128_ctr()) != 1) {
        fprintf(stderr, "FAIL: OpenSSL AES-128-CTR must expose a 1-byte EVP block size\n");
        return 1;
    }
    if(checked_outofplace_update(NULL, NULL, NULL, 0U) != 0) {
        fprintf(stderr, "FAIL: zero-length no-op handling\n");
        return 1;
    }

    for(i = 0U; i < sizeof(valid_lengths) / sizeof(valid_lengths[0]); i++) {
        for(in_offset = 0U; in_offset < 4U; in_offset++) {
            for(out_offset = 0U; out_offset < 4U; out_offset++) {
                for(wrap = 0; wrap <= 1; wrap++) {
                    unsigned int seed = 0x31a5U + (unsigned int)i * 37U +
                        (unsigned int)in_offset * 7U +
                        (unsigned int)out_offset * 3U + (unsigned int)wrap;
                    if(!run_case(valid_lengths[i], in_offset, out_offset,
                                 wrap, seed)) {
                        fprintf(stderr,
                                "FAIL: len=%lu in_offset=%lu out_offset=%lu wrap=%d\n",
                                (unsigned long)valid_lengths[i],
                                (unsigned long)in_offset,
                                (unsigned long)out_offset, wrap);
                        return 1;
                    }
                    cases++;
                }
            }
        }
    }

    if(!test_rejections()) {
        fprintf(stderr, "FAIL: partial-overlap/length/context rejection regression\n");
        return 1;
    }

    printf("PASS: R65-C AES-128-CTR out-of-place differential: %u cases; "
           "in/out offsets 0..3, counter wrap, split-state, in-place and 16-byte reference\n",
           cases);
    printf("PASS: partial overlap, non-aligned length, INT_MAX, uintptr overflow, "
           "wrong cipher, zero-length and rejected-call state preservation\n");
    return 0;
}
