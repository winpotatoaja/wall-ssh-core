/*
 * Passwall r53 MIPS32r2 ChaCha assembly known-answer test.
 * Assembly core source is dual-licensed GPL-2.0 OR MIT.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef unsigned char u8;

extern void chacha_crypt_mips(u32 state[16], u8 *out,
                              const u8 *in, u32 bytes, int rounds);

static const u8 expected_first_block[64] = {
    0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
    0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
    0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
    0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
    0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
    0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
    0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
    0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
};

static u32 rotl32(u32 value, unsigned int shift)
{
    return (value << shift) | (value >> (32U - shift));
}

static void quarter_round(u32 *a, u32 *b, u32 *c, u32 *d)
{
    *a += *b; *d ^= *a; *d = rotl32(*d, 16U);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12U);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8U);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7U);
}

static void put32_le(u8 *out, u32 value)
{
    out[0] = (u8)value;
    out[1] = (u8)(value >> 8);
    out[2] = (u8)(value >> 16);
    out[3] = (u8)(value >> 24);
}

static void reference_block(const u32 initial[16], u8 out[64])
{
    u32 x[16];
    unsigned int i;

    memcpy(x, initial, sizeof(x));
    for(i = 0; i < 10U; i++) {
        quarter_round(&x[0], &x[4], &x[8], &x[12]);
        quarter_round(&x[1], &x[5], &x[9], &x[13]);
        quarter_round(&x[2], &x[6], &x[10], &x[14]);
        quarter_round(&x[3], &x[7], &x[11], &x[15]);
        quarter_round(&x[0], &x[5], &x[10], &x[15]);
        quarter_round(&x[1], &x[6], &x[11], &x[12]);
        quarter_round(&x[2], &x[7], &x[8], &x[13]);
        quarter_round(&x[3], &x[4], &x[9], &x[14]);
    }
    for(i = 0; i < 16U; i++) {
        x[i] += initial[i];
        put32_le(out + (i * 4U), x[i]);
    }
}

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
    u32 state[16], block_state[16];
    u8 source[208], output[208], expected[192], block[64];
    size_t offset, i;

    make_state(state);
    memset(source, 0, sizeof(source));
    memset(output, 0xa5, sizeof(output));
    for(offset = 0; offset < length; offset += 64U) {
        memcpy(block_state, state, sizeof(block_state));
        block_state[12] += (u32)(offset / 64U);
        reference_block(block_state, block);
        memcpy(expected + offset, block, sizeof(block));
    }

    chacha_crypt_mips(state, output + out_align, source + in_align,
                      (u32)length, 20);
    if(memcmp(output + out_align, expected, length) != 0) {
        fprintf(stderr, "FAIL: out-of-place length=%lu in_align=%u out_align=%u\n",
                (unsigned long)length, in_align, out_align);
        return -1;
    }
    if(length >= 64U && memcmp(output + out_align, expected_first_block, 64U) != 0) {
        fprintf(stderr, "FAIL: RFC 8439 first block mismatch\n");
        return -1;
    }
    for(i = 0; i < sizeof(source); i++) {
        if(source[i] != 0U) {
            fprintf(stderr, "FAIL: source modified at offset %lu\n",
                    (unsigned long)i);
            return -1;
        }
    }
    if(state[12] != 1U + (u32)(length / 64U) || state[13] != 0x09000000U) {
        fprintf(stderr, "FAIL: counter update mismatch length=%lu low=%08x high=%08x\n",
                (unsigned long)length, state[12], state[13]);
        return -1;
    }
    return 0;
}

static int test_in_place(size_t length)
{
    u32 state[16], block_state[16];
    u8 buffer[208], expected[192], block[64];
    size_t offset;

    make_state(state);
    memset(buffer, 0, sizeof(buffer));
    for(offset = 0; offset < length; offset += 64U) {
        memcpy(block_state, state, sizeof(block_state));
        block_state[12] += (u32)(offset / 64U);
        reference_block(block_state, block);
        memcpy(expected + offset, block, sizeof(block));
    }
    chacha_crypt_mips(state, buffer + 1, buffer + 1, (u32)length, 20);
    if(memcmp(buffer + 1, expected, length) != 0) {
        fprintf(stderr, "FAIL: in-place length=%lu\n", (unsigned long)length);
        return -1;
    }
    if(length >= 64U && memcmp(buffer + 1, expected_first_block, 64U) != 0) {
        fprintf(stderr, "FAIL: RFC 8439 in-place first block mismatch\n");
        return -1;
    }
    if(state[12] != 1U + (u32)(length / 64U) || state[13] != 0x09000000U) {
        fprintf(stderr, "FAIL: in-place counter mismatch length=%lu\n",
                (unsigned long)length);
        return -1;
    }
    return 0;
}

int main(void)
{
    static const size_t lengths[] = { 0U, 64U, 128U, 192U };
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
    puts("PASS: MIPS32r2 ChaCha assembly RFC 8439 vector, multi-block, alignment, in-place and counter checks");
    return 0;
}
