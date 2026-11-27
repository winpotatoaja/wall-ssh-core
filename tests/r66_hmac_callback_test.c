#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libssh2_priv.h"

int libssh2_test_hmac256_init(LIBSSH2_SESSION *, unsigned char *, int *, void **);
int libssh2_test_hmac256_hash(LIBSSH2_SESSION *, unsigned char *, uint32_t,
                              const unsigned char *, size_t,
                              const unsigned char *, size_t, void **);
int libssh2_test_hmac256_dtor(LIBSSH2_SESSION *, void **);
int libssh2_test_hmac256_invalidate(void **);

#define ROUNDS 2048U
#define PACKET_MAX 8192U
#define ADDTL_MAX 64U

static int reference_mac(const unsigned char key[32], uint32_t seqno,
                         const unsigned char *packet, size_t packet_len,
                         const unsigned char *addtl, size_t addtl_len,
                         unsigned char out[32])
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned char seq[4];
    size_t out_len = 0;
    int ok = 0;
    if(!mac)
        return 0;
    ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if(!ctx)
        return 0;
    seq[0] = (unsigned char)(seqno >> 24);
    seq[1] = (unsigned char)(seqno >> 16);
    seq[2] = (unsigned char)(seqno >> 8);
    seq[3] = (unsigned char)seqno;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                   (void *)key, 32);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, (char *)OSSL_DIGEST_NAME_SHA2_256, 0);
    params[2] = OSSL_PARAM_construct_end();
    ok = EVP_MAC_init(ctx, NULL, 0, params) == 1 &&
         EVP_MAC_update(ctx, seq, sizeof(seq)) == 1 &&
         EVP_MAC_update(ctx, packet, packet_len) == 1;
    if(ok && addtl && addtl_len)
        ok = EVP_MAC_update(ctx, addtl, addtl_len) == 1;
    if(ok)
        ok = EVP_MAC_final(ctx, out, &out_len, 32) == 1 && out_len == 32;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

static int test_direction(LIBSSH2_SESSION *session, const unsigned char key[32],
                          unsigned int direction, int etm)
{
    unsigned char *packet = malloc(PACKET_MAX);
    unsigned char *addtl = malloc(ADDTL_MAX);
    unsigned char expected[32], actual[32];
    void *state = NULL;
    int free_key = 0;
    unsigned int i;
    int ok = 0;
    if(!packet || !addtl)
        goto done;
    if(libssh2_test_hmac256_init(session, (unsigned char *)key,
                                 &free_key, &state) != 0 || !state)
        goto done;
    /* Both standard and ETM method tables route to the same hash callback;
     * this test executes it once for each framing mode and direction. */
    (void)etm;
    for(i = 0; i < ROUNDS; i++) {
        size_t packet_len = (i * 7919U + direction * 97U) % (PACKET_MAX + 1U);
        size_t addtl_len = (i % 5U == 0U) ? 0U :
                           ((i * 17U + direction) % ADDTL_MAX) + 1U;
        size_t j;
        uint32_t seq = 0x10203040U + i + ((uint32_t)direction << 24);
        for(j = 0; j < packet_len; j++)
            packet[j] = (unsigned char)(i * 29U + j * 13U + direction * 71U);
        for(j = 0; j < addtl_len; j++)
            addtl[j] = (unsigned char)(i * 11U + j * 7U + direction * 43U);
        if(!reference_mac(key, seq, packet, packet_len,
                          addtl_len ? addtl : NULL, addtl_len, expected) ||
           libssh2_test_hmac256_hash(session, actual, seq, packet, packet_len,
                                     addtl_len ? addtl : NULL, addtl_len,
                                     &state) != 0 ||
           CRYPTO_memcmp(expected, actual, 32) != 0)
            goto done;
    }
    ok = 1;
done:
    libssh2_test_hmac256_dtor(session, &state);
    if(packet) { OPENSSL_cleanse(packet, PACKET_MAX); free(packet); }
    if(addtl) { OPENSSL_cleanse(addtl, ADDTL_MAX); free(addtl); }
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    return ok;
}

static int test_rekey(LIBSSH2_SESSION *session)
{
    unsigned char key1[32], key2[32], packet[128];
    unsigned char expected[32], actual1[32], actual2[32];
    void *state = NULL;
    int free_key = 0;
    unsigned int i;
    for(i = 0; i < 32; i++) {
        key1[i] = (unsigned char)(i + 1U);
        key2[i] = (unsigned char)(0xA0U + i);
    }
    memset(packet, 0x5a, sizeof(packet));
    if(libssh2_test_hmac256_init(session, key1, &free_key, &state) != 0 ||
       libssh2_test_hmac256_hash(session, actual1, 1, packet, sizeof(packet),
                                 NULL, 0, &state) != 0 ||
       !reference_mac(key1, 1, packet, sizeof(packet), NULL, 0, expected) ||
       CRYPTO_memcmp(actual1, expected, 32) != 0)
        goto fail;
    libssh2_test_hmac256_dtor(session, &state);
    if(libssh2_test_hmac256_init(session, key2, &free_key, &state) != 0 ||
       libssh2_test_hmac256_hash(session, actual2, 1, packet, sizeof(packet),
                                 NULL, 0, &state) != 0 ||
       !reference_mac(key2, 1, packet, sizeof(packet), NULL, 0, expected) ||
       CRYPTO_memcmp(actual2, expected, 32) != 0 ||
       CRYPTO_memcmp(actual1, actual2, 32) == 0)
        goto fail;
    libssh2_test_hmac256_dtor(session, &state);
    OPENSSL_cleanse(key1, sizeof(key1)); OPENSSL_cleanse(key2, sizeof(key2));
    OPENSSL_cleanse(packet, sizeof(packet)); OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual1, sizeof(actual1)); OPENSSL_cleanse(actual2, sizeof(actual2));
    return 1;
fail:
    libssh2_test_hmac256_dtor(session, &state);
    OPENSSL_cleanse(key1, sizeof(key1)); OPENSSL_cleanse(key2, sizeof(key2));
    OPENSSL_cleanse(packet, sizeof(packet)); OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual1, sizeof(actual1)); OPENSSL_cleanse(actual2, sizeof(actual2));
    return 0;
}

static int test_fail_closed(LIBSSH2_SESSION *session)
{
    unsigned char key[32], packet[16], out[32];
    void *state = NULL;
    int free_key = 0;
    unsigned int i;
    memset(key, 0x3c, sizeof(key)); memset(packet, 0x7d, sizeof(packet));
    if(libssh2_test_hmac256_init(session, NULL, &free_key, &state) == 0 ||
       state != NULL || free_key != 0)
        return 0;
    if(libssh2_test_hmac256_init(session, key, &free_key, &state) != 0 || !state)
        return 0;
    if(libssh2_test_hmac256_invalidate(&state) != 0 ||
       libssh2_test_hmac256_hash(session, out, 9, packet, sizeof(packet),
                                 NULL, 0, &state) == 0) {
        libssh2_test_hmac256_dtor(session, &state);
        return 0;
    }
    libssh2_test_hmac256_dtor(session, &state);
    for(i = 0; i < sizeof(key); i++) key[i] = 0;
    OPENSSL_cleanse(packet, sizeof(packet)); OPENSSL_cleanse(out, sizeof(out));
    return 1;
}

int main(void)
{
    LIBSSH2_SESSION *session = libssh2_session_init();
    unsigned char tx_key[32], rx_key[32];
    unsigned int i;
    if(!session)
        return 1;
    memset(session, 0, sizeof(*session));
    session->passwall_diag.enabled = 1;
    for(i = 0; i < 32; i++) {
        tx_key[i] = (unsigned char)(0x21U + i * 3U);
        rx_key[i] = (unsigned char)(0xA7U - i * 5U);
    }
    if(!test_direction(session, tx_key, 0, 0) ||
       !test_direction(session, rx_key, 1, 0) ||
       !test_direction(session, tx_key, 0, 1) ||
       !test_direction(session, rx_key, 1, 1) ||
       !test_rekey(session) || !test_fail_closed(session)) {
        fprintf(stderr, "FAIL: direct libssh2 HMAC callback tests\n");
        return 1;
    }
    OPENSSL_cleanse(tx_key, sizeof(tx_key)); OPENSSL_cleanse(rx_key, sizeof(rx_key));
    puts("PASS: direct libssh2 HMAC callback standard/ETM TX/RX, reuse, rekey and fail-closed state");
    return 0;
}
