#define _GNU_SOURCE
#include <errno.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define PASSWALL_CRYPTO_ALG_KERN_DRIVER_ONLY 0x00001000U

#define TEST_BYTES 32768U
#define SPLIT_BYTES 1024U

typedef struct {
    struct cmsghdr align;
    unsigned char bytes[
        CMSG_SPACE(sizeof(uint32_t)) +
        CMSG_SPACE(sizeof(struct af_alg_iv) + 16)
    ];
} alg_control_t;

static int open_alg(const char *name, const unsigned char key[16]) {
    struct sockaddr_alg sa;
    int tfm = -1;
    int op = -1;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    if (strcmp(name, "ctr(aes)") != 0) {
        sa.salg_feat = PASSWALL_CRYPTO_ALG_KERN_DRIVER_ONLY;
        sa.salg_mask = PASSWALL_CRYPTO_ALG_KERN_DRIVER_ONLY;
    }
    memcpy(sa.salg_type, "skcipher", sizeof("skcipher"));
    if (strlen(name) >= sizeof(sa.salg_name))
        return -1;
    memcpy(sa.salg_name, name, strlen(name) + 1);

    tfm = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfm < 0)
        return -1;
    if (bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;
    if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY, key, 16) < 0)
        goto fail;
    op = accept(tfm, NULL, 0);
    if (op < 0)
        goto fail;

    close(tfm);
    return op;

fail:
    if (op >= 0)
        close(op);
    if (tfm >= 0)
        close(tfm);
    return -1;
}

static int ctr_operation(int opfd, uint32_t operation,
                         const unsigned char iv[16],
                         const unsigned char *input, size_t length,
                         unsigned char *output) {
    alg_control_t control;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    ssize_t sent;
    size_t received = 0;

    memset(&control, 0, sizeof(control));
    memset(&msg, 0, sizeof(msg));

    iov.iov_base = (void *)input;
    iov.iov_len = length;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
        return -1;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(operation));
    memcpy(CMSG_DATA(cmsg), &operation, sizeof(operation));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (!cmsg)
        return -1;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = 16;
    memcpy(alg_iv->iv, iv, 16);

    do {
        sent = sendmsg(opfd, &msg, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)length)
        return -1;

    while (received < length) {
        ssize_t n = recv(opfd, output + received, length - received, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        received += (size_t)n;
    }
    return 0;
}

static int advance_ctr(unsigned char iv[16], size_t bytes) {
    size_t blocks;
    size_t n;
    if (!bytes || (bytes & 15U))
        return -1;
    blocks = bytes / 16U;
    for (n = 0; n < blocks; n++) {
        int i;
        for (i = 15; i >= 0; i--) {
            iv[i]++;
            if (iv[i])
                break;
        }
    }
    return 0;
}

static int hex_decode(const char *src, unsigned char *dst, size_t bytes) {
    size_t i;
    for (i = 0; i < bytes; i++) {
        unsigned int value;
        if (sscanf(src + i * 2, "%2x", &value) != 1)
            return -1;
        dst[i] = (unsigned char)value;
    }
    return 0;
}

int main(void) {
    static const char key_hex[] =
        "2b7e151628aed2a6abf7158809cf4f3c";
    static const char iv_hex[] =
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    static const char plain_hex[] =
        "6bc1bee22e409f96e93d7e117393172a";
    static const char cipher_hex[] =
        "874d6191b620e3261bef6864990db6ce";
    const char *driver = getenv("AFALG_CTR_DRIVER");
    unsigned char key[16], iv[16], plain[16], expected[16], actual[16];
    unsigned char initial_iv[16], split_iv[16];
    unsigned char *large_in = NULL, *whole = NULL, *split = NULL, *roundtrip = NULL;
    size_t i;
    int opfd = -1;
    int failed = 0;

    if (!driver || !*driver)
        driver = "ctr(aes)";
    if (hex_decode(key_hex, key, sizeof(key)) ||
        hex_decode(iv_hex, iv, sizeof(iv)) ||
        hex_decode(plain_hex, plain, sizeof(plain)) ||
        hex_decode(cipher_hex, expected, sizeof(expected))) {
        fprintf(stderr, "FAIL: invalid built-in AES-CTR test vector\n");
        return 1;
    }

    opfd = open_alg(driver, key);
    if (opfd < 0) {
        if (errno == ENOENT || errno == EAFNOSUPPORT ||
            errno == EOPNOTSUPP || errno == ENODEV ||
            errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
            errno == ENOSYS || errno == EPERM || errno == EACCES) {
            printf("SKIP: AF_ALG driver '%s' is unavailable on this host\n", driver);
            return 0;
        }
        fprintf(stderr, "FAIL: AF_ALG bind/key setup for '%s': %s\n",
                driver, strerror(errno));
        return 1;
    }

    if (ctr_operation(opfd, ALG_OP_ENCRYPT, iv, plain,
                      sizeof(plain), actual) != 0 ||
        memcmp(actual, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "FAIL: AES-128-CTR NIST known-answer vector\n");
        failed = 1;
        goto done;
    }

    large_in = malloc(TEST_BYTES);
    whole = malloc(TEST_BYTES);
    split = malloc(TEST_BYTES);
    roundtrip = malloc(TEST_BYTES);
    if (!large_in || !whole || !split || !roundtrip) {
        fprintf(stderr, "FAIL: unable to allocate AF_ALG regression buffers\n");
        failed = 1;
        goto done;
    }

    for (i = 0; i < TEST_BYTES; i++)
        large_in[i] = (unsigned char)((i * 29U + (i >> 3) + 7U) & 0xffU);
    memcpy(initial_iv, iv, sizeof(iv));

    if (ctr_operation(opfd, ALG_OP_ENCRYPT, initial_iv, large_in,
                      TEST_BYTES, whole) != 0) {
        fprintf(stderr, "FAIL: AF_ALG 64 KiB contiguous encryption\n");
        failed = 1;
        goto done;
    }

    memcpy(split_iv, initial_iv, sizeof(split_iv));
    for (i = 0; i < TEST_BYTES; i += SPLIT_BYTES) {
        if (ctr_operation(opfd, ALG_OP_ENCRYPT, split_iv,
                          large_in + i, SPLIT_BYTES, split + i) != 0 ||
            advance_ctr(split_iv, SPLIT_BYTES) != 0) {
            fprintf(stderr, "FAIL: AF_ALG split encryption at offset %zu\n", i);
            failed = 1;
            goto done;
        }
    }
    if (memcmp(whole, split, TEST_BYTES) != 0) {
        fprintf(stderr, "FAIL: split CTR operations differ from contiguous output\n");
        failed = 1;
        goto done;
    }

    if (ctr_operation(opfd, ALG_OP_DECRYPT, initial_iv, whole,
                      TEST_BYTES, roundtrip) != 0 ||
        memcmp(roundtrip, large_in, TEST_BYTES) != 0) {
        fprintf(stderr, "FAIL: AF_ALG 64 KiB decrypt round-trip\n");
        failed = 1;
        goto done;
    }

    printf("PASS: AF_ALG %s AES-128-CTR KAT, 64 KiB batching, "
           "split-IV continuity, and decrypt round-trip\n", driver);

done:
    if (opfd >= 0)
        close(opfd);
    free(large_in);
    free(whole);
    free(split);
    free(roundtrip);
    return failed ? 1 : 0;
}
