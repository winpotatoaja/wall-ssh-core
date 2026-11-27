#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALIGN_CASES 3U
#define WORKSET_CASES 3U
#define CHUNK_CASES 3U
#define TRIALS 5U
#define MIB_BYTES 1048576.0

typedef struct { unsigned int src; unsigned int dst; } align_case_t;
typedef struct {
    uint64_t baseline_evp_ns;
    uint64_t baseline_copy_ns;
    uint64_t outofplace_ns;
} result_t;

static const align_case_t align_cases[ALIGN_CASES] = {
    {12U, 11U}, {4U, 11U}, {4U, 15U}
};
static const size_t worksets[WORKSET_CASES] = {
    256U * 1024U, 4U * 1024U * 1024U, 32U * 1024U * 1024U
};
static const size_t chunks[CHUNK_CASES] = {
    16U * 1024U, 29U * 1024U, 32U * 1024U
};

static void fill_bytes(unsigned char *p, size_t n, uint32_t seed) {
    size_t i;
    uint32_t s = seed ? seed : 0x9e3779b9U;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        p[i] = (unsigned char)(s >> 9);
    }
}
static unsigned char *aligned_offset(unsigned char *p, unsigned int residue) {
    uintptr_t v = (uintptr_t)p;
    size_t adjust = (size_t)((16U - (v & 15U)) & 15U);
    return p + adjust + residue;
}
static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}
static uint64_t checksum64(const unsigned char *p, size_t n) {
    size_t i;
    uint64_t h = UINT64_C(1469598103934665603);
    for (i = 0; i < n; i++) { h ^= (uint64_t)p[i]; h *= UINT64_C(1099511628211); }
    return h;
}
static EVP_CIPHER_CTX *new_ctx(const unsigned char key[16],
                               const unsigned char iv[16], int enc) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    return ctx;
}
static int encrypt_reference(const unsigned char key[16], const unsigned char iv[16],
                             const unsigned char *plain, unsigned char *cipher,
                             size_t total) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 1);
    size_t pos = 0;
    if (!ctx) return 0;
    while (pos < total) {
        size_t amount = total - pos;
        int outl = 0;
        if (amount > 1024U * 1024U) amount = 1024U * 1024U;
        if (EVP_CipherUpdate(ctx, cipher + pos, &outl, plain + pos,
                             (int)amount) != 1 || outl != (int)amount) {
            EVP_CIPHER_CTX_free(ctx); return 0;
        }
        pos += amount;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}
static int run_inplace(const unsigned char key[16], const unsigned char iv[16],
                       unsigned char *buffer, size_t total, size_t chunk,
                       uint64_t *elapsed) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 0);
    size_t pos = 0;
    uint64_t start, end;
    if (!ctx) return 0;
    start = now_ns();
    if (!start) { EVP_CIPHER_CTX_free(ctx); return 0; }
    while (pos < total) {
        size_t amount = total - pos;
        int outl = 0;
        if (amount > chunk) amount = chunk;
        if (EVP_CipherUpdate(ctx, buffer + pos, &outl, buffer + pos,
                             (int)amount) != 1 || outl != (int)amount) {
            EVP_CIPHER_CTX_free(ctx); return 0;
        }
        pos += amount;
    }
    end = now_ns(); EVP_CIPHER_CTX_free(ctx);
    if (end < start) return 0;
    *elapsed = end - start;
    return 1;
}
static int run_packet_copy(const unsigned char *src, unsigned char *dst,
                           size_t total, size_t chunk, uint64_t *elapsed) {
    size_t pos = 0;
    uint64_t start = now_ns(), end;
    if (!start) return 0;
    while (pos < total) {
        size_t amount = total - pos;
        if (amount > chunk) amount = chunk;
        memcpy(dst + pos, src + pos, amount);
        pos += amount;
    }
    end = now_ns();
    if (end < start) return 0;
    *elapsed = end - start;
    return 1;
}
static int run_outofplace(const unsigned char key[16], const unsigned char iv[16],
                          const unsigned char *src, unsigned char *dst,
                          size_t total, size_t chunk, uint64_t *elapsed) {
    EVP_CIPHER_CTX *ctx = new_ctx(key, iv, 0);
    size_t pos = 0;
    uint64_t start, end;
    if (!ctx) return 0;
    start = now_ns();
    if (!start) { EVP_CIPHER_CTX_free(ctx); return 0; }
    while (pos < total) {
        size_t amount = total - pos;
        int outl = 0;
        if (amount > chunk) amount = chunk;
        if (EVP_CipherUpdate(ctx, dst + pos, &outl, src + pos,
                             (int)amount) != 1 || outl != (int)amount) {
            EVP_CIPHER_CTX_free(ctx); return 0;
        }
        pos += amount;
    }
    end = now_ns(); EVP_CIPHER_CTX_free(ctx);
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
static uint64_t ns_per_mib(uint64_t ns, size_t bytes) {
    return (uint64_t)((double)ns * (MIB_BYTES / (double)bytes));
}
static int run_case(const unsigned char key[16], const unsigned char iv[16],
                    size_t total, size_t chunk, unsigned int src_residue,
                    unsigned int dst_residue, unsigned char *plain_mem,
                    unsigned char *cipher_mem, unsigned char *mut_mem,
                    unsigned char *out_mem, result_t *result) {
    unsigned char *plain = aligned_offset(plain_mem, 0U);
    unsigned char *cipher = aligned_offset(cipher_mem, src_residue);
    unsigned char *mut = aligned_offset(mut_mem, src_residue);
    unsigned char *out = aligned_offset(out_mem, dst_residue);
    uint64_t base_evp[TRIALS], base_copy[TRIALS], oop[TRIALS];
    uint64_t cipher_hash;
    unsigned int t;

    fill_bytes(plain, total, 0x65e000U ^ (uint32_t)total ^
               (uint32_t)chunk ^ (src_residue << 8) ^ dst_residue);
    if (!encrypt_reference(key, iv, plain, cipher, total)) return 0;
    cipher_hash = checksum64(cipher, total);

    for (t = 0; t < TRIALS; t++) {
        if ((t & 1U) == 0U) {
            memcpy(mut, cipher, total);
            if (!run_inplace(key, iv, mut, total, chunk, &base_evp[t]) ||
                memcmp(mut, plain, total) != 0 ||
                !run_packet_copy(mut, out, total, chunk, &base_copy[t]) ||
                memcmp(out, plain, total) != 0)
                return 0;
            if (!run_outofplace(key, iv, cipher, out, total, chunk, &oop[t]) ||
                memcmp(out, plain, total) != 0 ||
                checksum64(cipher, total) != cipher_hash)
                return 0;
        } else {
            if (!run_outofplace(key, iv, cipher, out, total, chunk, &oop[t]) ||
                memcmp(out, plain, total) != 0 ||
                checksum64(cipher, total) != cipher_hash)
                return 0;
            memcpy(mut, cipher, total);
            if (!run_inplace(key, iv, mut, total, chunk, &base_evp[t]) ||
                memcmp(mut, plain, total) != 0 ||
                !run_packet_copy(mut, out, total, chunk, &base_copy[t]) ||
                memcmp(out, plain, total) != 0)
                return 0;
        }
    }
    result->baseline_evp_ns = median5(base_evp);
    result->baseline_copy_ns = median5(base_copy);
    result->outofplace_ns = median5(oop);
    return 1;
}
int main(void) {
    unsigned char key[16], iv[16];
    unsigned char *plain = NULL, *cipher = NULL, *mut = NULL, *out = NULL;
    unsigned int a, w, c;
    int ok = 0;

    if (EVP_CIPHER_get_block_size(EVP_aes_128_ctr()) != 1) {
        fprintf(stderr, "FAIL: AES-128-CTR EVP block size mismatch\n");
        return 1;
    }
    fill_bytes(key, sizeof(key), 0x65e101U);
    fill_bytes(iv, sizeof(iv), 0x65e102U);
    printf("R65-E realistic AES-128-CTR benchmark: OpenSSL=%s alignments=%u worksets=%u update_sizes=%u trials=%u\n",
           OpenSSL_version(OPENSSL_VERSION), ALIGN_CASES, WORKSET_CASES,
           CHUNK_CASES, TRIALS);

    for (w = 0; w < WORKSET_CASES; w++) {
        size_t total = worksets[w];
        free(plain); free(cipher); free(mut); free(out);
        plain = malloc(total + 64U); cipher = malloc(total + 64U);
        mut = malloc(total + 64U); out = malloc(total + 64U);
        if (!plain || !cipher || !mut || !out) {
            fprintf(stderr, "FAIL: allocate workset=%zu\n", total);
            goto cleanup;
        }
        for (c = 0; c < CHUNK_CASES; c++) {
            size_t chunk = chunks[c];
            for (a = 0; a < ALIGN_CASES; a++) {
                result_t r;
                uint64_t evp, copy, baseline, candidate;
                double delta;
                if (!run_case(key, iv, total, chunk, align_cases[a].src,
                              align_cases[a].dst, plain, cipher, mut, out, &r)) {
                    fprintf(stderr, "FAIL: workset=%zu chunk=%zu src=%u dst=%u\n",
                            total, chunk, align_cases[a].src, align_cases[a].dst);
                    goto cleanup;
                }
                evp = ns_per_mib(r.baseline_evp_ns, total);
                copy = ns_per_mib(r.baseline_copy_ns, total);
                baseline = evp + copy;
                candidate = ns_per_mib(r.outofplace_ns, total);
                delta = baseline ? ((double)candidate - (double)baseline) *
                         100.0 / (double)baseline : 0.0;
                printf("CASE workset_bytes=%zu chunk_bytes=%zu src=%u dst=%u "
                       "baseline_evp_ns_per_mib=%" PRIu64
                       " copy_ns_per_mib=%" PRIu64
                       " baseline_total_ns_per_mib=%" PRIu64
                       " outofplace_ns_per_mib=%" PRIu64
                       " delta_pct=%+.2f\n",
                       total, chunk, align_cases[a].src, align_cases[a].dst,
                       evp, copy, baseline, candidate, delta);
            }
        }
    }
    printf("PASS: R65-E completed 27 configurations x %u trials; plaintext and source immutability verified\n",
           TRIALS);
    ok = 1;

cleanup:
    free(plain); free(cipher); free(mut); free(out);
    return ok ? 0 : 1;
}
