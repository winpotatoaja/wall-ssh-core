#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#define ADDTL_MAX 8192U

static int reference_mac(const unsigned char key[32], uint32_t seqno,
                         const unsigned char *packet, size_t packet_len,
                         const unsigned char *addtl, size_t addtl_len,
                         unsigned char out[32])
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned char seq[4];
    size_t out_len = 0;
    int ok = 0;

    if(!key || (!packet && packet_len) || (!addtl && addtl_len))
        return 0;
    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if(!mac)
        goto done;
    ctx = EVP_MAC_CTX_new(mac);
    if(!ctx)
        goto done;

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
         EVP_MAC_update(ctx, seq, sizeof(seq)) == 1;
    if(ok && packet_len)
        ok = EVP_MAC_update(ctx, packet, packet_len) == 1;
    if(ok && addtl_len)
        ok = EVP_MAC_update(ctx, addtl, addtl_len) == 1;
    if(ok)
        ok = EVP_MAC_final(ctx, out, &out_len, 32) == 1 && out_len == 32;

done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(seq, sizeof(seq));
    return ok;
}

static int test_direction(LIBSSH2_SESSION *session, const unsigned char key[32],
                          unsigned int direction, int etm)
{
    unsigned char *packet = malloc(PACKET_MAX);
    unsigned char *addtl = malloc(ADDTL_MAX);
    unsigned char expected[32], actual[32];
    unsigned char mutable_key[32];
    void *state = NULL;
    int free_key = 0;
    unsigned int i;
    int ok = 0;

    if(!packet || !addtl)
        goto done;
    memcpy(mutable_key, key, sizeof(mutable_key));
    if(libssh2_test_hmac256_init(session, mutable_key, &free_key, &state) != 0 ||
       !state || free_key != 1)
        goto done;

    /* Mirror the callback's real argument shapes:
     * ETM: one complete authenticated packet span;
     * standard MAC: 5-byte packet header followed by payload as addtl. */
    for(i = 0; i < ROUNDS; i++) {
        size_t packet_len = etm
            ? (i * 7919U + direction * 97U) % (PACKET_MAX + 1U) : 5U;
        size_t addtl_len = etm ? 0U :
            ((i % 5U == 0U) ? 0U : ((i * 17U + direction) % ADDTL_MAX) + 1U);
        size_t j;
        uint32_t seq = 0x10203040U + i + ((uint32_t)direction << 24);
        const unsigned char *packet_data = packet;
        const unsigned char *addtl_data = (addtl_len != 0U) ? addtl : NULL;

        for(j = 0; j < packet_len; j++)
            packet[j] = (unsigned char)(i * 29U + j * 13U + direction * 71U);
        for(j = 0; j < addtl_len; j++)
            addtl[j] = (unsigned char)(i * 11U + j * 7U + direction * 43U);

        if(!reference_mac(key, seq, packet_data, packet_len,
                          addtl_data, addtl_len, expected) ||
           libssh2_test_hmac256_hash(session, actual, seq, packet_data, packet_len,
                                     addtl_data, addtl_len, &state) != 0 ||
           CRYPTO_memcmp(expected, actual, 32) != 0)
            goto done;
    }
    ok = 1;

done:
    libssh2_test_hmac256_dtor(session, &state);
    OPENSSL_cleanse(mutable_key, sizeof(mutable_key));
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
    int ok = 0;

    for(i = 0; i < 32; i++) {
        key1[i] = (unsigned char)(i + 1U);
        key2[i] = (unsigned char)(0xA0U + i);
    }
    memset(packet, 0x5a, sizeof(packet));

    if(libssh2_test_hmac256_init(session, key1, &free_key, &state) != 0 ||
       !state ||
       libssh2_test_hmac256_hash(session, actual1, 1, packet, sizeof(packet),
                                 NULL, 0, &state) != 0 ||
       !reference_mac(key1, 1, packet, sizeof(packet), NULL, 0, expected) ||
       CRYPTO_memcmp(actual1, expected, 32) != 0)
        goto done;
    if(libssh2_test_hmac256_dtor(session, &state) != 0)
        goto done;
    if(libssh2_test_hmac256_init(session, key2, &free_key, &state) != 0 ||
       !state ||
       libssh2_test_hmac256_hash(session, actual2, 1, packet, sizeof(packet),
                                 NULL, 0, &state) != 0 ||
       !reference_mac(key2, 1, packet, sizeof(packet), NULL, 0, expected) ||
       CRYPTO_memcmp(actual2, expected, 32) != 0 ||
       CRYPTO_memcmp(actual1, actual2, 32) == 0)
        goto done;
    ok = 1;

done:
    libssh2_test_hmac256_dtor(session, &state);
    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual1, sizeof(actual1));
    OPENSSL_cleanse(actual2, sizeof(actual2));
    return ok;
}

static int test_fail_closed(LIBSSH2_SESSION *session)
{
    unsigned char key[32], packet[16], out[32];
    void *state = NULL;
    int free_key = 0;
    int ok = 0;

    memset(key, 0x3c, sizeof(key));
    memset(packet, 0x7d, sizeof(packet));

    if(libssh2_test_hmac256_init(session, key, &free_key, NULL) == 0)
        goto done;
    if(libssh2_test_hmac256_init(session, NULL, &free_key, &state) == 0 ||
       state != NULL || free_key != 0)
        goto done;
    if(libssh2_test_hmac256_init(NULL, key, &free_key, &state) == 0 ||
       state != NULL || free_key != 0)
        goto done;
    if(libssh2_test_hmac256_init(session, key, &free_key, &state) != 0 || !state)
        goto done;
    if(libssh2_test_hmac256_invalidate(&state) != 0 ||
       libssh2_test_hmac256_hash(session, out, 9, packet, sizeof(packet),
                                 NULL, 0, &state) == 0)
        goto done;
    ok = 1;

done:
    libssh2_test_hmac256_dtor(session, &state);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(out, sizeof(out));
    return ok;
}

static int test_session_isolation(LIBSSH2_SESSION *session_a,
                                  LIBSSH2_SESSION *session_b)
{
    unsigned char key_a[32], key_b[32], packet[256], addtl[32];
    unsigned char expected_a[32], expected_b[32], actual_a[32], actual_b[32];
    void *state_a = NULL, *state_b = NULL;
    int free_key_a = 0, free_key_b = 0;
    unsigned int i;
    int ok = 0;

    for(i = 0; i < 32; i++) {
        key_a[i] = (unsigned char)(0x10U + i);
        key_b[i] = (unsigned char)(0xE0U - i);
    }
    if(libssh2_test_hmac256_init(session_a, key_a, &free_key_a, &state_a) != 0 ||
       libssh2_test_hmac256_init(session_b, key_b, &free_key_b, &state_b) != 0 ||
       !state_a || !state_b)
        goto done;

    for(i = 0; i < 512; i++) {
        size_t len = (i * 37U) % sizeof(packet);
        size_t extra = (i * 11U) % sizeof(addtl);
        size_t j;
        uint32_t seq_a = 0x11220000U + i;
        uint32_t seq_b = 0x88770000U + i;

        for(j = 0; j < len; j++)
            packet[j] = (unsigned char)(i + j * 3U);
        for(j = 0; j < extra; j++)
            addtl[j] = (unsigned char)(i * 5U + j * 7U);

        if(!reference_mac(key_a, seq_a, packet, len, NULL, 0, expected_a) ||
           libssh2_test_hmac256_hash(session_a, actual_a, seq_a,
                                     packet, len, NULL, 0, &state_a) != 0 ||
           CRYPTO_memcmp(expected_a, actual_a, 32) != 0)
            goto done;
        if(!reference_mac(key_b, seq_b, packet, len,
                          extra ? addtl : NULL, extra, expected_b) ||
           libssh2_test_hmac256_hash(session_b, actual_b, seq_b,
                                     packet, len, extra ? addtl : NULL,
                                     extra, &state_b) != 0 ||
           CRYPTO_memcmp(expected_b, actual_b, 32) != 0)
            goto done;
    }
    ok = 1;

done:
    libssh2_test_hmac256_dtor(session_a, &state_a);
    libssh2_test_hmac256_dtor(session_b, &state_b);
    OPENSSL_cleanse(key_a, sizeof(key_a));
    OPENSSL_cleanse(key_b, sizeof(key_b));
    OPENSSL_cleanse(packet, sizeof(packet));
    OPENSSL_cleanse(addtl, sizeof(addtl));
    OPENSSL_cleanse(expected_a, sizeof(expected_a));
    OPENSSL_cleanse(expected_b, sizeof(expected_b));
    OPENSSL_cleanse(actual_a, sizeof(actual_a));
    OPENSSL_cleanse(actual_b, sizeof(actual_b));
    return ok;
}

int main(void)
{
    LIBSSH2_SESSION *session = libssh2_session_init();
    LIBSSH2_SESSION *session2 = libssh2_session_init();
    unsigned char tx_key[32], rx_key[32];
    unsigned int i;
    int ok = 0;

    if(!session || !session2)
        goto done;
    /* libssh2_session_init() initializes the session and allocator callbacks.
     * Do not memset the opaque session: that would erase those callbacks. */
    session->passwall_diag.enabled = 1;
    session2->passwall_diag.enabled = 1;
    for(i = 0; i < 32; i++) {
        tx_key[i] = (unsigned char)(0x21U + i * 3U);
        rx_key[i] = (unsigned char)(0xA7U - i * 5U);
    }

    if(!test_direction(session, tx_key, 0, 0) ||
       !test_direction(session, rx_key, 1, 0) ||
       !test_direction(session, tx_key, 0, 1) ||
       !test_direction(session, rx_key, 1, 1) ||
       !test_rekey(session) ||
       !test_fail_closed(session) ||
       !test_session_isolation(session, session2))
        goto done;

    ok = 1;

done:
    OPENSSL_cleanse(tx_key, sizeof(tx_key));
    OPENSSL_cleanse(rx_key, sizeof(rx_key));
    if(session)
        libssh2_session_free(session);
    if(session2)
        libssh2_session_free(session2);
    if(!ok) {
        fprintf(stderr, "FAIL: direct libssh2 HMAC callback tests\n");
        return 1;
    }
    puts("PASS: direct HMAC callbacks TX/RX standard/ETM, reuse, rekey, fail-closed and session isolation");
    return 0;
}
