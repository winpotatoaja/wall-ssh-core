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
    if(!ctx) return NULL;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)key, 32);
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
    if(!ctx) return 0;
    seq_bytes(seq, sb);
    ok = EVP_MAC_update(ctx, sb, sizeof(sb)) == 1 &&
         EVP_MAC_update(ctx, packet, plen) == 1;
    if(ok && addtl && alen) ok = EVP_MAC_update(ctx, addtl, alen) == 1;
    if(ok) ok = EVP_MAC_final(ctx, out, &outlen, 32) == 1 && outlen == 32;
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
    if(EVP_MAC_init(ctx, NULL, 0, NULL) != 1) return 0;
#else
    ctx = EVP_MAC_CTX_dup(template);
    if(!ctx) return 0;
    own = 1;
#endif
    seq_bytes(seq, sb);
    ok = EVP_MAC_update(ctx, sb, sizeof(sb)) == 1 &&
         EVP_MAC_update(ctx, packet, plen) == 1;
    if(ok && addtl && alen) ok = EVP_MAC_update(ctx, addtl, alen) == 1;
    if(ok) ok = EVP_MAC_final(ctx, out, &outlen, 32) == 1 && outlen == 32;
    if(own) EVP_MAC_CTX_free(ctx);
    return ok;
}

static int run_direction(unsigned int dir, const unsigned char key[32])
{
    EVP_MAC_CTX *template = ctx_new_keyed(key);
    unsigned char packet[PACKET_MAX], addtl[ADDTL_MAX];
    unsigned char expected[32], actual[32];
    unsigned int i;
    int ok = 1;
    if(!template) return 0;
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
    if(!run_direction(0, txkey) || !run_direction(1, rxkey)) {
        EVP_MAC_free(g_hmac);
        OPENSSL_cleanse(txkey, sizeof(txkey));
        OPENSSL_cleanse(rxkey, sizeof(rxkey));
        return 1;
    }
    EVP_MAC_free(g_hmac);
    OPENSSL_cleanse(txkey, sizeof(txkey));
    OPENSSL_cleanse(rxkey, sizeof(rxkey));
#if OPENSSL_VERSION_NUMBER >= 0x30000030L
    puts("PASS: OpenSSL 3.0.3+ HMAC-SHA256 context reset; 2 directions x 2048 messages");
#else
    puts("PASS: OpenSSL 3.0.0-3.0.2 HMAC-SHA256 context duplication; 2 directions x 2048 messages");
#endif
    return 0;
}
