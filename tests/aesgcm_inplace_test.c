#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_LEN 24576U
#define AAD_LEN 4U
#define TAG_LEN 16U

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    const unsigned char key[16] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
    };
    const unsigned char iv[12] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x10, 0x32, 0x54, 0x76
    };
    unsigned char aad[AAD_LEN] = {0x00, 0x00, 0x60, 0x00};
    unsigned char tag[TAG_LEN];
    unsigned char *plain = malloc(PAYLOAD_LEN);
    unsigned char *frame = malloc(AAD_LEN + PAYLOAD_LEN + TAG_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len = 0;
    int final_len = 0;
    int ok = 0;

    if (!plain || !frame || !ctx) {
        free(plain);
        free(frame);
        EVP_CIPHER_CTX_free(ctx);
        return fail("allocation");
    }

    for (size_t i = 0; i < PAYLOAD_LEN; ++i)
        plain[i] = (unsigned char)((i * 37U + (i >> 3) + 11U) & 0xffU);
    memcpy(frame, aad, AAD_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &out_len, frame, (int)AAD_LEN) != 1 ||
        EVP_EncryptUpdate(ctx, frame + AAD_LEN, &out_len, plain,
                          (int)PAYLOAD_LEN) != 1 ||
        (size_t)out_len != PAYLOAD_LEN ||
        EVP_EncryptFinal_ex(ctx, frame + AAD_LEN + out_len, &final_len) != 1 ||
        final_len != 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(frame);
        return fail("AES-GCM encryption setup/vector generation");
    }
    memcpy(frame + AAD_LEN + PAYLOAD_LEN, tag, TAG_LEN);

    /* Reset the context and decrypt the large ciphertext in-place. */
    EVP_CIPHER_CTX_reset(ctx);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &out_len, frame, (int)AAD_LEN) != 1 ||
        EVP_DecryptUpdate(ctx, frame + AAD_LEN, &out_len,
                          frame + AAD_LEN, (int)PAYLOAD_LEN) != 1 ||
        (size_t)out_len != PAYLOAD_LEN ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            frame + AAD_LEN + PAYLOAD_LEN) != 1 ||
        EVP_DecryptFinal_ex(ctx, frame + AAD_LEN + out_len, &final_len) != 1 ||
        final_len != 0 || memcmp(frame + AAD_LEN, plain, PAYLOAD_LEN) != 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(frame);
        return fail("large in-place AES-GCM decrypt or plaintext comparison");
    }

    /* Re-encrypt to restore ciphertext, then prove a damaged tag is rejected. */
    EVP_CIPHER_CTX_reset(ctx);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &out_len, frame, (int)AAD_LEN) != 1 ||
        EVP_EncryptUpdate(ctx, frame + AAD_LEN, &out_len, plain,
                          (int)PAYLOAD_LEN) != 1 ||
        (size_t)out_len != PAYLOAD_LEN ||
        EVP_EncryptFinal_ex(ctx, frame + AAD_LEN + out_len, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(frame);
        return fail("AES-GCM ciphertext regeneration");
    }
    memcpy(frame + AAD_LEN + PAYLOAD_LEN, tag, TAG_LEN);
    frame[AAD_LEN + PAYLOAD_LEN + 7U] ^= 0x80U;

    EVP_CIPHER_CTX_reset(ctx);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &out_len, frame, (int)AAD_LEN) != 1 ||
        EVP_DecryptUpdate(ctx, frame + AAD_LEN, &out_len,
                          frame + AAD_LEN, (int)PAYLOAD_LEN) != 1 ||
        (size_t)out_len != PAYLOAD_LEN ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            frame + AAD_LEN + PAYLOAD_LEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plain);
        free(frame);
        return fail("invalid-tag setup");
    }
    ok = EVP_DecryptFinal_ex(ctx, frame + AAD_LEN + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(frame);

    if (ok == 1)
        return fail("tampered authentication tag was accepted");

    puts("PASS: AES-128-GCM large in-place decrypt, 4-byte AAD, and tag rejection");
    return 0;
}
