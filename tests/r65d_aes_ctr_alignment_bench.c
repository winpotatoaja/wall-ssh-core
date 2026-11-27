#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALIGN_COUNT 16U
#define CHUNK_BYTES (16U * 1024U)
#define TOTAL_BYTES (256U * 1024U)
#define TRIALS 5U
#define PAIR_COUNT (ALIGN_COUNT * ALIGN_COUNT)
#define MIB_BYTES 1048576.0

typedef struct {
    uint64_t inplace_evp_ns;
    uint64_t copy_ns;
    uint64_t outofplace_evp_ns;
} sample_t;

static void fill_bytes(unsigned char *p, size_t n, uint32_t seed) {
    size_t i;
    uint32_t s = seed ? seed : 0x9e3779b9U;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        p[i] = (unsigned char)(s >> 9);
    }
}

static unsigned char *aligned_offset(unsigned char *p, unsigned int offset) {
    uintptr_t v = (uintptr_t)p;
    size_t adjust = (size_t)((16U - (v & 15U)) & 15U);
    return p + adjust + offset;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static EVP_CIPHER_CTX *new_ctx(const unsigned char key[16],
                               const unsigned char iv[16], int enc) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int encrypt_ref(const unsigned char key[16], const unsigned char iv[16],
                       const unsigned char *plain, unsigned char *cipher) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 1);
    int outl = 0, ok = 0;
    if (!ctx) return 0;
    if (EVP_CipherUpdate(ctx, cipher, &outl, plain, (int)TOTAL_BYTES) == 1 &&
        outl == (int)TOTAL_BYTES) ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int inplace_evp(const unsigned char key[16], const unsigned char iv[16],
                       unsigned char *buffer, uint64_t *elapsed) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 0);
    size_t pos;
    uint64_t start, end;
    if (!ctx) return 0;
    start = now_ns();
    if (!start) { EVP_CIPHER_CTX_free(ctx); return 0; }
    for (pos = 0; pos < TOTAL_BYTES; pos += CHUNK_BYTES) {
        int outl = 0;
        if (EVP_CipherUpdate(ctx, buffer + pos, &outl, buffer + pos,
                             (int)CHUNK_BYTES) != 1 || outl != (int)CHUNK_BYTES) {
            EVP_CIPHER_CTX_free(ctx); return 0;
        }
    }
    end = now_ns();
    EVP_CIPHER_CTX_free(ctx);
    if (end < start) return 0;
    *elapsed = end - start;
    return 1;
}

static int copy_packets(const unsigned char *src, unsigned char *dst,
                        uint64_t *elapsed) {
    size_t pos;
    uint64_t start = now_ns(), end;
    if (!start) return 0;
    for (pos = 0; pos < TOTAL_BYTES; pos += CHUNK_BYTES)
        memcpy(dst + pos, src + pos, CHUNK_BYTES);
    end = now_ns();
    if (end < start) return 0;
    *elapsed = end - start;
    return 1;
}

static int outofplace_evp(const unsigned char key[16], const unsigned char iv[16],
                          const unsigned char *src, unsigned char *dst,
                          uint64_t *elapsed) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 0);
    size_t pos;
    uint64_t start, end;
    if (!ctx) return 0;
    start = now_ns();
    if (!start) { EVP_CIPHER_CTX_free(ctx); return 0; }
    for (pos = 0; pos < TOTAL_BYTES; pos += CHUNK_BYTES) {
        int outl = 0;
        if (EVP_CipherUpdate(ctx, dst + pos, &outl, src + pos,
                             (int)CHUNK_BYTES) != 1 || outl != (int)CHUNK_BYTES) {
            EVP_CIPHER_CTX_free(ctx); return 0;
        }
    }
    end = now_ns();
    EVP_CIPHER_CTX_free(ctx);
    if (end < start) return 0;
    *elapsed = end - start;
    return 1;
}

static uint64_t median5(uint64_t v[TRIALS]) {
    unsigned int i, j;
    for (i = 0; i < TRIALS; i++)
        for (j = i + 1; j < TRIALS; j++)
            if (v[j] < v[i]) { uint64_t t = v[i]; v[i] = v[j]; v[j] = t; }
    return v[TRIALS / 2U];
}

static uint64_t ns_per_mib(uint64_t elapsed) {
    return (uint64_t)((double)elapsed * (MIB_BYTES / (double)TOTAL_BYTES));
}

static int run_pair(unsigned int sa, unsigned int da,
                    const unsigned char key[16], const unsigned char iv[16],
                    unsigned char *plain_mem, unsigned char *cipher_mem,
                    unsigned char *snap_mem, unsigned char *mut_mem,
                    unsigned char *out_mem, sample_t *result) {
    unsigned char *plain = aligned_offset(plain_mem, sa);
    unsigned char *cipher = aligned_offset(cipher_mem, sa);
    unsigned char *snap = aligned_offset(snap_mem, sa);
    unsigned char *mut = aligned_offset(mut_mem, sa);
    unsigned char *out = aligned_offset(out_mem, da);
    uint64_t evp[TRIALS], copy[TRIALS], oop[TRIALS];
    unsigned int t;

    fill_bytes(plain, TOTAL_BYTES, 0x741dU + sa * 17U + da);
    if (!encrypt_ref(key, iv, plain, cipher)) return 0;
    memcpy(snap, cipher, TOTAL_BYTES);

    for (t = 0; t < TRIALS; t++) {
        memcpy(mut, cipher, TOTAL_BYTES); /* Outside the measured EVP interval. */
        memset(out, 0x5a, TOTAL_BYTES);
        if (!inplace_evp(key, iv, mut, &evp[t]) ||
            memcmp(mut, plain, TOTAL_BYTES) != 0) return 0;
        if (!copy_packets(mut, out, &copy[t]) ||
            memcmp(out, plain, TOTAL_BYTES) != 0) return 0;

        memset(out, 0xa5, TOTAL_BYTES);
        if (!outofplace_evp(key, iv, cipher, out, &oop[t]) ||
            memcmp(out, plain, TOTAL_BYTES) != 0 ||
            memcmp(cipher, snap, TOTAL_BYTES) != 0) return 0;
    }
    result->inplace_evp_ns = median5(evp);
    result->copy_ns = median5(copy);
    result->outofplace_evp_ns = median5(oop);
    return 1;
}

static uint64_t median256(uint64_t v[PAIR_COUNT]) {
    unsigned int i, j;
    for (i = 0; i < PAIR_COUNT; i++)
        for (j = i + 1; j < PAIR_COUNT; j++)
            if (v[j] < v[i]) { uint64_t t = v[i]; v[i] = v[j]; v[j] = t; }
    return (v[PAIR_COUNT / 2U - 1U] + v[PAIR_COUNT / 2U]) / 2U;
}

int main(void) {
    unsigned char key[16], iv[16];
    unsigned char *plain = NULL, *cipher = NULL, *snap = NULL, *mut = NULL, *out = NULL;
    uint64_t baseline[PAIR_COUNT], oop[PAIR_COUNT];
    unsigned int sa, da, pair = 0;

    if (EVP_CIPHER_get_block_size(EVP_aes_128_ctr()) != 1) {
        fprintf(stderr, "FAIL: AES-128-CTR EVP block size is not 1\n");
        return 1;
    }
    fill_bytes(key, sizeof(key), 0x65d001U);
    fill_bytes(iv, sizeof(iv), 0x65d002U);
    plain = malloc(TOTAL_BYTES + 64U); cipher = malloc(TOTAL_BYTES + 64U);
    snap = malloc(TOTAL_BYTES + 64U); mut = malloc(TOTAL_BYTES + 64U);
    out = malloc(TOTAL_BYTES + 64U);
    if (!plain || !cipher || !snap || !mut || !out) {
        fprintf(stderr, "FAIL: allocation\n"); goto fail;
    }

    printf("R65-D AES-128-CTR alignment benchmark: OpenSSL=%s packet=%u stream=%u trials=%u residues=0..15\n",
           OpenSSL_version(OPENSSL_VERSION), CHUNK_BYTES, TOTAL_BYTES, TRIALS);

    for (sa = 0; sa < ALIGN_COUNT; sa++) {
        for (da = 0; da < ALIGN_COUNT; da++) {
            sample_t s;
            uint64_t base, candidate;
            double delta;
            if (!run_pair(sa, da, key, iv, plain, cipher, snap, mut, out, &s)) {
                fprintf(stderr, "FAIL: src=%u dst=%u\n", sa, da); goto fail;
            }
            base = ns_per_mib(s.inplace_evp_ns) + ns_per_mib(s.copy_ns);
            candidate = ns_per_mib(s.outofplace_evp_ns);
            delta = base ? ((double)candidate - (double)base) * 100.0 / (double)base : 0.0;
            baseline[pair] = base; oop[pair] = candidate;
            printf("PAIR src=%02u dst=%02u inplace_evp_ns_per_mib=%" PRIu64
                   " copy_ns_per_mib=%" PRIu64 " baseline_total_ns_per_mib=%" PRIu64
                   " outofplace_evp_ns_per_mib=%" PRIu64 " delta_pct=%+.2f\n",
                   sa, da, ns_per_mib(s.inplace_evp_ns), ns_per_mib(s.copy_ns),
                   base, candidate, delta);
            pair++;
        }
    }

    {
        uint64_t bm = median256(baseline), om = median256(oop);
        double delta = bm ? ((double)om - (double)bm) * 100.0 / (double)bm : 0.0;
        printf("SUMMARY pairs=%u baseline_median_ns_per_mib=%" PRIu64
               " outofplace_median_ns_per_mib=%" PRIu64 " median_delta_pct=%+.2f\n",
               pair, bm, om, delta);
    }
    printf("PASS: R65-D alignment matrix complete; all %u pairs passed plaintext/source checks\n",
           pair);
    free(plain); free(cipher); free(snap); free(mut); free(out);
    return 0;

fail:
    free(plain); free(cipher); free(snap); free(mut); free(out);
    return 1;
}
