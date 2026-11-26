#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t lengths[] = {
    0U, 16U, 32U, 64U, 1024U, 4096U, 16384U, 32768U, 35000U
};

static const size_t chunk_pattern[] = {16U, 7U, 4089U, 32768U, 13U, 511U, 3U};

static void
fill_bytes(unsigned char *buffer, size_t length, unsigned int seed)
{
    size_t i;
    uint32_t state = seed;
    for(i = 0; i < length; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        buffer[i] = (unsigned char)(state >> 9);
    }
}

static int
cipher_update(EVP_CIPHER_CTX *ctx, unsigned char *out,
              const unsigned char *in, size_t length)
{
    int out_length = 0;
    if(length == 0U)
        return 1;
    if(length > (size_t)INT32_MAX)
        return 0;
    if(EVP_CipherUpdate(ctx, out, &out_length, in, (int)length) != 1)
        return 0;
    return out_length == (int)length;
}

static int
cipher_init(EVP_CIPHER_CTX **ctx, int encrypt,
            const unsigned char key[16], const unsigned char iv[16])
{
    *ctx = EVP_CIPHER_CTX_new();
    if(!*ctx)
        return 0;
    if(EVP_CipherInit_ex(*ctx, EVP_aes_128_ctr(), NULL,
                         key, iv, encrypt) != 1) {
        EVP_CIPHER_CTX_free(*ctx);
        *ctx = NULL;
        return 0;
    }
    return 1;
}

static int
run_case(size_t length, size_t offset, int wrap_counter, unsigned int seed)
{
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *plain = NULL;
    unsigned char *reference = NULL;
    unsigned char *inplace = NULL;
    unsigned char *looped = NULL;
    unsigned char *split = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t allocation = length + offset + 8U;
    size_t pos;
    size_t part_index = 0U;
    int ok = 0;

    fill_bytes(key, sizeof(key), seed ^ 0x5a17U);
    memset(iv, 0, sizeof(iv));
    if(wrap_counter) {
        memset(iv + 12, 0xff, 4U);
    }
    else {
        fill_bytes(iv, sizeof(iv), seed ^ 0x7182U);
    }

    plain = (unsigned char *)malloc(allocation);
    reference = (unsigned char *)malloc(allocation);
    inplace = (unsigned char *)malloc(allocation);
    looped = (unsigned char *)malloc(allocation);
    split = (unsigned char *)malloc(allocation);
    if(!plain || !reference || !inplace || !looped || !split)
        goto cleanup;

    fill_bytes(plain, allocation, seed ^ (unsigned int)(length + offset));
    memcpy(inplace, plain, allocation);
    memcpy(looped, plain, allocation);
    memcpy(split, plain, allocation);

    if(!cipher_init(&ctx, 1, key, iv))
        goto cleanup;
    if(!cipher_update(ctx, reference + offset, plain + offset, length))
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* In-place one-shot bulk EVP update. */
    if(!cipher_init(&ctx, 1, key, iv))
        goto cleanup;
    if(!cipher_update(ctx, inplace + offset, inplace + offset, length))
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(reference + offset, inplace + offset, length) != 0)
        goto cleanup;

    /* Legacy-equivalent sequence: one EVP update per SSH 16-byte block. */
    if(!cipher_init(&ctx, 1, key, iv))
        goto cleanup;
    for(pos = 0U; pos < length; ) {
        size_t n = length - pos;
        if(n > 16U)
            n = 16U;
        if(!cipher_update(ctx, looped + offset + pos,
                          plain + offset + pos, n))
            goto cleanup;
        pos += n;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(reference + offset, looped + offset, length) != 0)
        goto cleanup;

    /* Irregular call boundaries prove that EVP retains partial CTR state. */
    if(!cipher_init(&ctx, 1, key, iv))
        goto cleanup;
    for(pos = 0U; pos < length; ) {
        size_t n = chunk_pattern[part_index %
                                 (sizeof(chunk_pattern) / sizeof(chunk_pattern[0]))];
        if(n > length - pos)
            n = length - pos;
        if(!cipher_update(ctx, split + offset + pos,
                          split + offset + pos, n))
            goto cleanup;
        pos += n;
        part_index++;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(reference + offset, split + offset, length) != 0)
        goto cleanup;

    /* Decrypt the bulk ciphertext in place and compare with the source. */
    if(!cipher_init(&ctx, 0, key, iv))
        goto cleanup;
    if(!cipher_update(ctx, inplace + offset, inplace + offset, length))
        goto cleanup;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if(memcmp(plain + offset, inplace + offset, length) != 0)
        goto cleanup;

    ok = 1;

cleanup:
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(reference);
    free(inplace);
    free(looped);
    free(split);
    return ok;
}

int
main(void)
{
    size_t i;
    size_t offset;
    unsigned int cases = 0U;

    if(EVP_CIPHER_get_block_size(EVP_aes_128_ctr()) != 1) {
        fprintf(stderr, "FAIL: AES-128-CTR EVP block size is not one byte\n");
        return 1;
    }

    for(i = 0U; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(offset = 0U; offset < 4U; offset++) {
            int wrap;
            for(wrap = 0; wrap <= 1; wrap++) {
                if(!run_case(lengths[i], offset, wrap,
                             0x31a5U + (unsigned int)i * 17U +
                             (unsigned int)offset * 3U + (unsigned int)wrap)) {
                    fprintf(stderr,
                            "FAIL: length=%lu offset=%lu counter_wrap=%d\n",
                            (unsigned long)lengths[i],
                            (unsigned long)offset, wrap);
                    return 1;
                }
                cases++;
            }
        }
    }

    printf("PASS: OpenSSL AES-128-CTR EVP bulk differential; %u cases, "
           "one-shot/in-place/16-byte-loop/irregular-split/decrypt, "
           "offsets 0..3 and counter-wrap boundary\n", cases);
    return 0;
}
