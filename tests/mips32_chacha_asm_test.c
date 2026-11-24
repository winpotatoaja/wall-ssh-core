/*
 * Passwall r53 MIPS32r2 ChaCha assembly known-answer test.
 * RFC 8439 section 2.3.2; assembly implementation is dual-licensed GPL-2.0 OR MIT.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef unsigned char u8;

extern void chacha_crypt_mips(u32 state[16], u8 *out,
                              const u8 *in, u32 bytes, int rounds);

static const u8 expected[64] = {
    0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
    0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
    0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
    0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
    0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
    0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
    0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
    0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
};

static void make_state(u32 state[16])
{
    static const u32 initial[16] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        0x03020100U, 0x07060504U, 0x0b0a0908U, 0x0f0e0d0cU,
        0x13121110U, 0x17161514U, 0x1b1a1918U, 0x1f1e1d1cU,
        0x00000001U, 0x09000000U, 0x4a000000U, 0x00000000U
    };
    memcpy(state, initial, sizeof(initial));
}

static int test_out_of_place(size_t length, unsigned int in_align,
                             unsigned int out_align)
{
    u32 state[16];
    u8 source[72], output[72];
    size_t i;

    make_state(state);
    memset(source, 0, sizeof(source));
    memset(output, 0xa5, sizeof(output));
    chacha_crypt_mips(state, output + out_align, source + in_align,
                      (u32)length, 20);

    if(memcmp(output + out_align, expected, length) != 0) {
        fprintf(stderr, "FAIL: out-of-place vector length=%lu in_align=%u out_align=%u\n",
                (unsigned long)length, in_align, out_align);
        return -1;
    }
    for(i = 0; i < sizeof(source); i++) {
        if(source[i] != 0U) {
            fprintf(stderr, "FAIL: source modified at offset %lu\n",
                    (unsigned long)i);
            return -1;
        }
    }
    if(state[12] != (length ? 2U : 1U) || state[13] != 0x09000000U) {
        fprintf(stderr, "FAIL: counter state mismatch length=%lu low=%08x high=%08x\n",
                (unsigned long)length, state[12], state[13]);
        return -1;
    }
    return 0;
}

static int test_in_place(size_t length)
{
    u32 state[16];
    u8 buffer[72];

    make_state(state);
    memset(buffer, 0, sizeof(buffer));
    chacha_crypt_mips(state, buffer + 1, buffer + 1, (u32)length, 20);
    if(memcmp(buffer + 1, expected, length) != 0) {
        fprintf(stderr, "FAIL: in-place vector length=%lu\n",
                (unsigned long)length);
        return -1;
    }
    if(state[12] != (length ? 2U : 1U) || state[13] != 0x09000000U) {
        fprintf(stderr, "FAIL: in-place counter state mismatch length=%lu\n",
                (unsigned long)length);
        return -1;
    }
    return 0;
}

int main(void)
{
    static const size_t lengths[] = { 0U, 1U, 3U, 4U, 15U, 16U, 31U, 32U, 63U, 64U };
    size_t i;
    unsigned int in_align, out_align;

    for(i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        for(in_align = 0; in_align < 4U; in_align++) {
            for(out_align = 0; out_align < 4U; out_align++) {
                if(test_out_of_place(lengths[i], in_align, out_align) != 0)
                    return 1;
            }
        }
        if(test_in_place(lengths[i]) != 0)
            return 1;
    }
    puts("PASS: MIPS32r2 ChaCha assembly RFC 8439 vector, tails, alignment, in-place and counter update");
    return 0;
}
