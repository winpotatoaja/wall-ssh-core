#define _GNU_SOURCE
#include "../spsc_rb.h"

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define CAPACITY 32768U
#define TOTAL_BYTES (16U * 1024U * 1024U)

#define CHECK(condition, message)                                      \
    do {                                                               \
        if (!(condition)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);   \
            return 1;                                                  \
        }                                                              \
    } while (0)

typedef struct {
    spsc_rb_t *q;
    uint64_t total;
    int failed;
} stress_t;

static uint8_t byte_at(uint64_t position)
{
    uint64_t value = position * UINT64_C(0x9e3779b185ebca87);
    value ^= value >> 29;
    value ^= value >> 17;
    return (uint8_t)(value ^ (value >> 8) ^ (value >> 24));
}

static uint32_t random_next(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static int test_basic_and_pinning(void)
{
    spsc_rb_t q;
    CHECK(spsc_rb_init(&q, 0U) != 0, "reject zero capacity");
    CHECK(spsc_rb_init(&q, 3U) != 0, "reject non-power-of-two capacity");
    CHECK(spsc_rb_init(&q, 1U << 31) != 0, "reject capacity above 2^30");

    CHECK(spsc_rb_init(&q, 8U) == 0, "initialize basic ring");

    size_t available = 0U;
    uint32_t ticket = 0U;
    uint8_t *write_ptr = spsc_rb_write_span(&q, &available, &ticket);
    CHECK(write_ptr && available == 8U && ticket == 0U,
          "initial writable span");

    memcpy(write_ptr, "01234567", 8U);
    CHECK(spsc_rb_commit_write(&q, ticket, 8U) == 0,
          "commit full ring");
    CHECK(spsc_rb_write_span(&q, &available, &ticket) == NULL &&
              available == 0U,
          "full ring has no writable span");

    const uint8_t *read_ptr =
        spsc_rb_read_span(&q, &available, &ticket);
    CHECK(read_ptr && available == 8U &&
              memcmp(read_ptr, "01234567", 8U) == 0,
          "read full ring");

    CHECK(spsc_rb_commit_read(&q, ticket, 5U) == 0,
          "partial consumer commit");

    write_ptr = spsc_rb_write_span(&q, &available, &ticket);
    CHECK(write_ptr && available == 5U, "wrapped producer span");
    memcpy(write_ptr, "abcde", 5U);
    CHECK(spsc_rb_commit_write(&q, ticket, 5U) == 0,
          "commit wrapped bytes");

    read_ptr = spsc_rb_read_span(&q, &available, &ticket);
    CHECK(read_ptr && available == 3U &&
              memcmp(read_ptr, "567", 3U) == 0,
          "read first physical segment");
    CHECK(spsc_rb_commit_read(&q, ticket, 3U) == 0,
          "commit first physical segment");

    read_ptr = spsc_rb_read_span(&q, &available, &ticket);
    CHECK(read_ptr && available == 5U &&
              memcmp(read_ptr, "abcde", 5U) == 0,
          "read wrapped physical segment");
    CHECK(spsc_rb_commit_read(&q, ticket, 5U) == 0,
          "drain ring");

    uint32_t head = __atomic_load_n(&q.head.value, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&q.tail.value, __ATOMIC_RELAXED);
    CHECK(head == tail && head == 13U,
          "empty ring keeps monotonically increasing counters");
    spsc_rb_destroy(&q);

    CHECK(spsc_rb_init(&q, 16U) == 0, "initialize pinned-span ring");

    write_ptr = spsc_rb_write_span(&q, &available, &ticket);
    CHECK(write_ptr && available >= 8U, "initial pinned write span");
    memcpy(write_ptr, "abcdefgh", 8U);
    CHECK(spsc_rb_commit_write(&q, ticket, 8U) == 0,
          "commit pinned write span");

    read_ptr = spsc_rb_read_span(&q, &available, &ticket);
    CHECK(read_ptr && available >= 8U, "initial pinned read span");
    uint32_t read_ticket = ticket;
    const uint8_t *pinned = spsc_rb_read_span_at(&q, read_ticket, 8U);
    CHECK(pinned == read_ptr, "pinned read pointer identity");

    write_ptr = spsc_rb_write_span(&q, &available, &ticket);
    CHECK(write_ptr && available >= 4U, "producer can append while pinned");
    memcpy(write_ptr, "ijkl", 4U);
    CHECK(spsc_rb_commit_write(&q, ticket, 4U) == 0,
          "commit append while pinned");

    CHECK(spsc_rb_read_span_at(&q, read_ticket, 8U) == pinned &&
              memcmp(pinned, "abcdefgh", 8U) == 0,
          "producer append cannot invalidate pinned read span");
    CHECK(spsc_rb_commit_read(&q, read_ticket, 8U) == 0,
          "commit pinned read span");

    spsc_rb_destroy(&q);
    return 0;
}

static void *producer_thread(void *opaque)
{
    static const size_t chunks[] = { 1U, 7U, 513U, 4093U };
    stress_t *context = (stress_t *)opaque;
    uint64_t position = 0U;
    uint32_t random_state = UINT32_C(0x1234abcd);

    while (position < context->total &&
           !__atomic_load_n(&context->failed, __ATOMIC_ACQUIRE)) {
        size_t available = 0U;
        uint32_t ticket = 0U;
        uint8_t *span =
            spsc_rb_write_span(context->q, &available, &ticket);
        if (!span || available == 0U) {
            sched_yield();
            continue;
        }

        size_t amount = chunks[random_next(&random_state) & 3U];
        if (amount > available) {
            amount = available;
        }
        if ((uint64_t)amount > context->total - position) {
            amount = (size_t)(context->total - position);
        }

        for (size_t i = 0U; i < amount; i++) {
            span[i] = byte_at(position + (uint64_t)i);
        }

        if (spsc_rb_commit_write(context->q, ticket, amount) != 0) {
            __atomic_store_n(&context->failed, 1, __ATOMIC_RELEASE);
            break;
        }
        position += (uint64_t)amount;
    }

    return NULL;
}

static void *consumer_thread(void *opaque)
{
    static const size_t chunks[] = { 7U, 1U, 4093U, 513U };
    stress_t *context = (stress_t *)opaque;
    uint64_t position = 0U;
    uint32_t random_state = UINT32_C(0x87654321);

    while (position < context->total &&
           !__atomic_load_n(&context->failed, __ATOMIC_ACQUIRE)) {
        size_t available = 0U;
        uint32_t ticket = 0U;
        const uint8_t *span =
            spsc_rb_read_span(context->q, &available, &ticket);
        if (!span || available == 0U) {
            sched_yield();
            continue;
        }

        size_t amount = chunks[random_next(&random_state) & 3U];
        if (amount > available) {
            amount = available;
        }
        if ((uint64_t)amount > context->total - position) {
            amount = (size_t)(context->total - position);
        }

        for (size_t i = 0U; i < amount; i++) {
            if (span[i] != byte_at(position + (uint64_t)i)) {
                fprintf(stderr, "byte mismatch at offset %llu\n",
                        (unsigned long long)(position + (uint64_t)i));
                __atomic_store_n(&context->failed, 1, __ATOMIC_RELEASE);
                return NULL;
            }
        }

        if (spsc_rb_commit_read(context->q, ticket, amount) != 0) {
            __atomic_store_n(&context->failed, 1, __ATOMIC_RELEASE);
            break;
        }
        position += (uint64_t)amount;
    }

    return NULL;
}

static int check_pthread_error(const char *operation);

static int run_stress(uint32_t initial_counter, const char *label)
{
    spsc_rb_t q;
    CHECK(spsc_rb_init(&q, CAPACITY) == 0, "initialize stress ring");

    /* Quiescent setup starts near UINT32_MAX to force counter rollover. */
    __atomic_store_n(&q.head.value, initial_counter, __ATOMIC_RELAXED);
    __atomic_store_n(&q.tail.value, initial_counter, __ATOMIC_RELAXED);

    stress_t context = {
        .q = &q,
        .total = TOTAL_BYTES,
        .failed = 0
    };
    pthread_t producer;
    pthread_t consumer;

    int rc = pthread_create(&producer, NULL, producer_thread, &context);
    if (rc != 0) {
        errno = rc;
        spsc_rb_destroy(&q);
        return check_pthread_error("create producer");
    }

    rc = pthread_create(&consumer, NULL, consumer_thread, &context);
    if (rc != 0) {
        __atomic_store_n(&context.failed, 1, __ATOMIC_RELEASE);
        (void)pthread_join(producer, NULL);
        errno = rc;
        spsc_rb_destroy(&q);
        return check_pthread_error("create consumer");
    }

    int producer_rc = pthread_join(producer, NULL);
    int consumer_rc = pthread_join(consumer, NULL);
    if (producer_rc != 0 || consumer_rc != 0) {
        errno = producer_rc != 0 ? producer_rc : consumer_rc;
        spsc_rb_destroy(&q);
        return check_pthread_error("join stress threads");
    }

    CHECK(!__atomic_load_n(&context.failed, __ATOMIC_ACQUIRE),
          "stress byte integrity");

    uint32_t head = __atomic_load_n(&q.head.value, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&q.tail.value, __ATOMIC_RELAXED);
    CHECK(head == tail &&
              head == initial_counter + (uint32_t)TOTAL_BYTES,
          "ring drained and counter arithmetic survived rollover");

    spsc_rb_destroy(&q);
    printf("PASS: SPSC stress %s (%u bytes)\n", label, TOTAL_BYTES);
    return 0;
}

static int check_pthread_error(const char *operation)
{
    fprintf(stderr, "FAIL: %s (pthread error=%d)\n", operation, errno);
    return 1;
}

int main(void)
{
    if (test_basic_and_pinning() != 0) {
        return 1;
    }
    if (run_stress(0U, "normal counters") != 0) {
        return 1;
    }
    if (run_stress(UINT32_C(0xFFFFFF00), "uint32_t rollover") != 0) {
        return 1;
    }

    puts("PASS: all SPSC ring tests");
    return 0;
}
