/*
 * Passwall r54 MIPS32r2/o32 Poly1305 assembly regression.
 * Compares the generated MIPS assembly path with libssh2's retained C oracle.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16

extern void poly1305_auth(unsigned char out[POLY1305_TAGLEN],
                          const unsigned char *message, size_t length,
                          const unsigned char key[POLY1305_KEYLEN]);
extern void poly1305_auth_portable(unsigned char out[POLY1305_TAGLEN],
                                   const unsigned char *message, size_t length,
                                   const unsigned char key[POLY1305_KEYLEN]);

static const unsigned char rfc_key[32] = {
    0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
    0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
    0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
    0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
};

static const unsigned char rfc_tag[16] = {
    0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
    0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
};

static const unsigned char rfc_message[] =
    "Cryptographic Forum Research Group";

static int test_rfc_vector(void)
{
    unsigned char actual[16];
    unsigned char reference[16];

    poly1305_auth(actual, rfc_message, sizeof(rfc_message) - 1U, rfc_key);
    poly1305_auth_portable(reference, rfc_message,
                           sizeof(rfc_message) - 1U, rfc_key);
    if(memcmp(actual, rfc_tag, sizeof(actual)) != 0) {
        fprintf(stderr, "FAIL: RFC Poly1305 known-answer tag mismatch\n");
        return -1;
    }
    if(memcmp(actual, reference, sizeof(actual)) != 0) {
        fprintf(stderr, "FAIL: RFC Poly1305 assembly/C oracle mismatch\n");
        return -1;
    }
    return 0;
}

static int test_reference_lengths(void)
{
    static const size_t lengths[] = {
        0U, 1U, 15U, 16U, 17U, 31U, 32U, 33U, 63U, 64U, 65U,
        255U, 256U, 257U, 4095U, 4096U, 4097U, 32768U, 34996U, 35000U
    };
    unsigned char message_storage[35008];
    unsigned char original[35008];
    unsigned char key_storage[36];
    unsigned char fast_tag[20];
    unsigned char ref_tag[20];
    size_t i;
    unsigned int msg_align, key_align, tag_align;

    for(i = 0; i < sizeof(message_storage); i++)
        message_storage[i] = (unsigned char)((i * 29U + (i >> 3) + 0x5bU) & 0xffU);
    for(i = 0; i < sizeof(key_storage); i++)
        key_storage[i] = (unsigned char)((i * 17U + 0xa3U) & 0xffU);
    memcpy(original, message_storage, sizeof(original));

    for(i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(msg_align = 0U; msg_align < 4U; msg_align++) {
            for(key_align = 0U; key_align < 4U; key_align++) {
                for(tag_align = 0U; tag_align < 4U; tag_align++) {
                    unsigned char *message = message_storage + msg_align;
                    unsigned char *key = key_storage + key_align;
                    unsigned char *fast = fast_tag + tag_align;
                    unsigned char *reference = ref_tag + tag_align;

                    poly1305_auth(fast, message, lengths[i], key);
                    poly1305_auth_portable(reference, message, lengths[i], key);
                    if(memcmp(fast, reference, POLY1305_TAGLEN) != 0) {
                        fprintf(stderr,
                                "FAIL: Poly1305 mismatch length=%lu msg_align=%u key_align=%u tag_align=%u\n",
                                (unsigned long)lengths[i], msg_align,
                                key_align, tag_align);
                        return -1;
                    }
                    if(memcmp(message_storage, original, sizeof(original)) != 0) {
                        fprintf(stderr,
                                "FAIL: Poly1305 modified input length=%lu\n",
                                (unsigned long)lengths[i]);
                        return -1;
                    }
                }
            }
        }
    }
    return 0;
}

int main(void)
{
    if(test_rfc_vector() != 0)
        return 1;
    if(test_reference_lengths() != 0)
        return 1;
    puts("PASS: MIPS32r2/o32 Poly1305 RFC vector, C-reference lengths, tails and alignment");
    return 0;
}
