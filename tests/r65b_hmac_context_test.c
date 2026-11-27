#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "R65-B HMAC differential requires OpenSSL 3"
#endif

#define ROUNDS 2048U
#define PACKET_MAX 8192U
#define ADDTL_MAX 64U
static EVP_MAC *g_hmac;

static void seq_bytes(uint32_t n, unsigned char b[4])
{
    b[0] = (unsigned char)(n >> 24);
    b[1] = (unsigned char)(n >> 16);
    b[2] = (unsigned char)(n >> 8);
    b[3] = (unsigned char)n;
}

static EVP_MAC_CTX *ctx_new_keyed(const unsigned char key[32])
{
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(g_hmac);
    OSSL_PARAM params[3];
    if(!ctx)
        return NULL;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                  (void *)key, 32);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)OSSL_DIGEST_NAME_SHA2_256, 0);
    params[2] = OSSL_PARAM_construct_end();
    if(EVP_MAC_init(ctx, NULL, 0, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int digest_fresh(const unsigned char key[32], uint32_t seq,
                        const unsigned char *packet, size_t plen,
                        const unsigned char *addtl, size_t alen,
                        unsigned char out[32])
{
    EVP_MAC_CTX *ctx = ctx_new_keyed(key);
    unsigned char sb[4];
    size_t outlen = 0;
    int ok;
    if(!ctx)
        return 0;
    seq_bytes(seq, sb);
    ok = EVP_MAC_update(ctx, sb, sizeof(sb)) == 1 &&
         EVP_MAC_update(ctx, packet, plen) == 1;
    if(ok && addtl && alen)
        ok = EVP_MAC_update(ctx, addtl, alen) == 1;
    if(ok)
        ok = EVP_MAC_final(ctx, out, &outlen, 32) == 1 && outlen == 32;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

static int digest_reused(EVP_MAC_CTX *template, uint32_t seq,
                         const unsigned char *packet, size_t plen,
                         const unsigned char *addtl, size_t alen,
                         unsigned char out[32])
{
    EVP_MAC_CTX *ctx = template;
    unsigned char sb[4];
    size_t outlen = 0;
    int own = 0, ok;
#if OPENSSL_VERSION_NUMBER >= 0x30000030L
    if(EVP_MAC_init(ctx, NULL, 0, NULL) != 1)
        return 0;
#else
    ctx = EVP_MAC_CTX_dup(template);
    if(!ctx)
        return 0;
    own = 1;
#endif
    seq_bytes(seq, sb);
    ok = EVP_MAC_update(ctx, sb, sizeof(sb)) == 1 &&
         EVP_MAC_update(ctx, packet, plen) == 1;
    if(ok && addtl && alen)
        ok = EVP_MAC_update(ctx, addtl, alen) == 1;
    if(ok)
        ok = EVP_MAC_final(ctx, out, &outlen, 32) == 1 && outlen == 32;
    if(own)
        EVP_MAC_CTX_free(ctx);
    return ok;
}

static int test_rekey_and_reuse(void)
{
    unsigned char key1[32], key2[32];
    unsigned char packet[1024], addtl[32];
    unsigned char fresh1[32], reused1[32], fresh2[32], reused2[32];
    EVP_MAC_CTX *ctx;
    unsigned int i;

    for(i = 0; i < sizeof(key1); i++) {
        key1[i] = (unsigned char)(0x21U + i * 3U);
        key2[i] = (unsigned char)(0xA7U - i * 5U);
        packet[i % sizeof(packet)] = (unsigned char)(i * 29U);
        addtl[i % sizeof(addtl)] = (unsigned char)(i * 11U);
    }

    ctx = ctx_new_keyed(key1);
    if(!ctx)
        return 0;
    if(!digest_fresh(key1, 100, packet, sizeof(packet), addtl, sizeof(addtl), fresh1) ||
       !digest_reused(ctx, 100, packet, sizeof(packet), addtl, sizeof(addtl), reused1) ||
       CRYPTO_memcmp(fresh1, reused1, 32) != 0)
        goto fail;

    EVP_MAC_CTX_free(ctx);
    ctx = ctx_new_keyed(key2);
    if(!ctx)
        return 0;
    if(!digest_fresh(key2, 101, packet, sizeof(packet), addtl, sizeof(addtl), fresh2) ||
       !digest_reused(ctx, 101, packet, sizeof(packet), addtl, sizeof(addtl), reused2) ||
       CRYPTO_memcmp(fresh2, reused2, 32) != 0)
        goto fail;
    if(CRYPTO_memcmp(reused1, reused2, 32) == 0)
        goto fail;

    EVP_MAC_CTX_free(ctx);
    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(addtl, sizeof(addtl));
    OPENSSL_cleanse(fresh1, sizeof(fresh1));
    OPENSSL_cleanse(reused1, sizeof(reused1));
    OPENSSL_cleanse(fresh2, sizeof(fresh2));
    OPENSSL_cleanse(reused2, sizeof(reused2));
    return 1;

fail:
    EVP_MAC_CTX_free(ctx);
    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(addtl, sizeof(addtl));
    OPENSSL_cleanse(fresh1, sizeof(fresh1));
    OPENSSL_cleanse(reused1, sizeof(reused1));
    OPENSSL_cleanse(fresh2, sizeof(fresh2));
    OPENSSL_cleanse(reused2, sizeof(reused2));
    return 0;
}

static int test_init_update_final_failures(void)
{
    unsigned char key[32];
    unsigned char sb[4] = {0, 0, 0, 1};
    unsigned char packet[64], out[32];
    unsigned char expected[32];
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM missing_key[3];
    size_t outlen = 0;
    unsigned int i;
    int ok;

    for(i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x53U + i);
    for(i = 0; i < sizeof(packet); i++)
        packet[i] = (unsigned char)(i * 17U);

    ctx = EVP_MAC_CTX_new(g_hmac);
    if(!ctx)
        goto fail;
    missing_key[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)OSSL_DIGEST_NAME_SHA2_256, 0);
    missing_key[1] = OSSL_PARAM_construct_end();
    missing_key[2] = OSSL_PARAM_construct_end();
    if(EVP_MAC_init(ctx, NULL, 0, missing_key) == 1)
        goto fail;
    EVP_MAC_CTX_free(ctx);

    ctx = ctx_new_keyed(key);
    if(!ctx)
        goto fail;
    ok = EVP_MAC_update(ctx, NULL, 1);
    if(ok == 1)
        goto fail;
    EVP_MAC_CTX_free(ctx);

    ctx = ctx_new_keyed(key);
    if(!ctx)
        goto fail;
    if(EVP_MAC_update(ctx, sb, sizeof(sb)) != 1 ||
       EVP_MAC_update(ctx, packet, sizeof(packet)) != 1)
        goto fail;
    if(EVP_MAC_final(ctx, out, &outlen, 31) == 1)
        goto fail;
    EVP_MAC_CTX_free(ctx);

    ctx = ctx_new_keyed(key);
    if(!ctx)
        goto fail;
    if(EVP_MAC_update(ctx, sb, sizeof(sb)) != 1 ||
       EVP_MAC_update(ctx, packet, sizeof(packet)) != 1 ||
       EVP_MAC_final(ctx, expected, &outlen, 32) != 1 || outlen != 32)
        goto fail;
    EVP_MAC_CTX_free(ctx);

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(out, sizeof(out));
    OPENSSL_cleanse(expected, sizeof(expected));
    return 1;

fail:
    if(ctx)
        EVP_MAC_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(out, sizeof(out));
    OPENSSL_cleanse(expected, sizeof(expected));
    return 0;
}

static int run_direction(unsigned int dir, const unsigned char key[32])
{
    EVP_MAC_CTX *template = ctx_new_keyed(key);
    unsigned char packet[PACKET_MAX], addtl[ADDTL_MAX];
    unsigned char expected[32], actual[32];
    unsigned int i;
    int ok = 1;
    if(!template)
        return 0;
    for(i = 0; i < ROUNDS; i++) {
        size_t plen = (size_t)((i * 7919U + dir * 97U) % (PACKET_MAX + 1U));
        size_t alen = (i % 5U == 0U) ? 0U :
                      (size_t)((i * 17U + dir) % ADDTL_MAX) + 1U;
        size_t j;
        uint32_t seq = 0x10203040U + i + (dir << 24);
        for(j = 0; j < plen; j++)
            packet[j] = (unsigned char)(i * 29U + j * 13U + dir * 71U);
        for(j = 0; j < alen; j++)
            addtl[j] = (unsigned char)(i * 11U + j * 7U + dir * 43U);
        if(!digest_fresh(key, seq, packet, plen, alen ? addtl : NULL, alen, expected) ||
           !digest_reused(template, seq, packet, plen, alen ? addtl : NULL, alen, actual) ||
           CRYPTO_memcmp(expected, actual, sizeof(expected)) != 0) {
            fprintf(stderr, "FAIL: direction=%u round=%u plen=%zu alen=%zu\n",
                    dir, i, plen, alen);
            ok = 0;
            break;
        }
    }
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(addtl, sizeof(addtl));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    EVP_MAC_CTX_free(template);
    return ok;
}

int main(void)
{
    unsigned char txkey[32], rxkey[32];
    unsigned int i;

    for(i = 0; i < 32; i++) {
        txkey[i] = (unsigned char)(0x21U + i * 3U);
        rxkey[i] = (unsigned char)(0xA7U - i * 5U);
    }

    g_hmac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if(!g_hmac) {
        fprintf(stderr, "FAIL: EVP_MAC_fetch(HMAC)\n");
        return 1;
    }

    if(!run_direction(0, txkey) || !run_direction(1, rxkey) ||
       !test_rekey_and_reuse() || !test_init_update_final_failures()) {
        EVP_MAC_free(g_hmac);
        OPENSSL_cleanse(txkey, sizeof(txkey));
        OPENSSL_cleanse(rxkey, sizeof(rxkey));
        fprintf(stderr, "FAIL: HMAC callback-equivalent regression\n");
        return 1;
    }

    EVP_MAC_free(g_hmac);
    OPENSSL_cleanse(txkey, sizeof(txkey));
    OPENSSL_cleanse(rxkey, sizeof(rxkey));
#if OPENSSL_VERSION_NUMBER >= 0x30000030L
    puts("PASS: HMAC-SHA256 standard/ETM TX/RX reuse, rekey and EVP error cases; 2 directions x 2048 messages");
#else
    puts("PASS: HMAC-SHA256 EVP_MAC_CTX_dup fallback, reuse, rekey and EVP error cases; 2 directions x 2048 messages");
#endif
    return 0;
}
