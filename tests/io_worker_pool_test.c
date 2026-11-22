#define _GNU_SOURCE
#include "../io_worker_pool.h"

#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#define STRESS_TASKS 50000U
#define PAYLOAD_LEN 32U

typedef struct {
    unsigned int delay_us;
    _Atomic unsigned int calls;
    _Atomic unsigned int active;
    _Atomic unsigned int max_active;
} test_context_t;

static int check(int ok, const char *what)
{
    if (ok) return 0;
    fprintf(stderr, "FAIL: %s\n", what);
    return -1;
}

static void update_max(_Atomic unsigned int *maximum, unsigned int value)
{
    unsigned int old = atomic_load_explicit(maximum, memory_order_relaxed);
    while (old < value &&
           !atomic_compare_exchange_weak_explicit(maximum, &old, value,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) { }
}

static int execute_task(const io_worker_task_t *task,
                        io_worker_completion_t *completion,
                        const void *opaque)
{
    test_context_t *ctx = (test_context_t *)opaque;
    unsigned int active = atomic_fetch_add_explicit(&ctx->active, 1U,
                                                     memory_order_relaxed) + 1U;
    update_max(&ctx->max_active, active);
    atomic_fetch_add_explicit(&ctx->calls, 1U, memory_order_relaxed);
    if (ctx->delay_us) {
        struct timespec delay = {
            (time_t)(ctx->delay_us / 1000000U),
            (long)(ctx->delay_us % 1000000U) * 1000L
        };
        while (nanosleep(&delay, &delay) < 0 && errno == EINTR) { }
    }
    completion->result_len = task->payload_len;
    for (uint32_t i = 0; i < task->payload_len; i++)
        completion->result[i] = task->payload[i] ^ (uint8_t)task->opcode;
    atomic_fetch_sub_explicit(&ctx->active, 1U, memory_order_relaxed);
    return 0;
}

static void make_task(io_worker_task_t *task, uint64_t id,
                      uint64_t client_id, uint64_t generation)
{
    memset(task, 0, sizeof(*task));
    task->task_id = id;
    task->client_id = client_id;
    task->generation = generation;
    task->opcode = (uint32_t)(id & 0xffU);
    task->payload_len = PAYLOAD_LEN;
    for (uint32_t i = 0; i < PAYLOAD_LEN; i++)
        task->payload[i] = (uint8_t)(id + i * 13U);
}

static int owner_accepts(const io_worker_completion_t *completion,
                         uint64_t client_id, uint64_t generation)
{
    return completion && completion->client_id == client_id &&
           completion->generation == generation;
}

static int verify(const io_worker_completion_t *completion,
                  const io_worker_task_t *expected)
{
    if (completion->status || completion->task_id != expected->task_id ||
        completion->client_id != expected->client_id ||
        completion->generation != expected->generation ||
        completion->result_len != expected->payload_len)
        return -1;
    for (uint32_t i = 0; i < expected->payload_len; i++) {
        if (completion->result[i] !=
            (uint8_t)(expected->payload[i] ^ (uint8_t)expected->opcode))
            return -1;
    }
    return 0;
}

static int stop_destroy(io_worker_pool_t *pool, int drain)
{
    if (io_worker_pool_request_stop(pool, drain) < 0 ||
        io_worker_pool_join(pool, 5000) < 0 ||
        io_worker_pool_destroy(pool) < 0)
        return -1;
    return 0;
}

static int test_validation(void)
{
    test_context_t ctx = {0};
    errno = 0;
    if (check(!io_worker_pool_create(0, 8, execute_task, &ctx) && errno == EINVAL,
              "reject zero workers")) return -1;
    errno = 0;
    if (check(!io_worker_pool_create(1, 3, execute_task, &ctx) && errno == EINVAL,
              "reject non power-of-two queue")) return -1;
    errno = 0;
    if (check(!io_worker_pool_create(1, 8, NULL, &ctx) && errno == EINVAL,
              "reject missing callback")) return -1;
    return 0;
}

static int test_round_robin_generation(void)
{
    test_context_t ctx = {0};
    io_worker_pool_t *pool = io_worker_pool_create(3, 8, execute_task, &ctx);
    if (check(pool != NULL, "create round-robin pool")) return -1;
    io_worker_task_t expected[9], task;
    unsigned int assigned[3] = {0};
    for (uint64_t i = 0; i < 9; i++) {
        make_task(&task, i + 1, 100 + i, UINT64_C(0x100000000) + i);
        expected[i] = task;
        uint32_t worker = 0;
        if (io_worker_pool_submit(pool, &task, &worker) < 0 || worker >= 3) {
            (void)stop_destroy(pool, 0);
            return check(0, "submit round-robin task");
        }
        assigned[worker]++;
    }
    if (check(assigned[0] == 3 && assigned[1] == 3 && assigned[2] == 3,
              "round-robin assignment")) {
        (void)stop_destroy(pool, 0);
        return -1;
    }
    unsigned int received = 0;
    while (received < 9) {
        struct pollfd fds[3];
        for (uint32_t i = 0; i < 3; i++)
            fds[i] = (struct pollfd){io_worker_pool_completion_fd(pool, i), POLLIN, 0};
        if (poll(fds, 3, 3000) <= 0) {
            (void)stop_destroy(pool, 0);
            return check(0, "round-robin completion wakeup");
        }
        for (uint32_t i = 0; i < 3; i++) if (fds[i].revents & POLLIN) {
            io_worker_completion_t out[4];
            size_t n = io_worker_pool_drain_completions(pool, i, out, 4);
            for (size_t j = 0; j < n; j++) {
                uint64_t id = out[j].task_id;
                if (!id || id > 9 || verify(&out[j], &expected[id - 1]) < 0 ||
                    owner_accepts(&out[j], expected[id - 1].client_id,
                                  expected[id - 1].generation + 1) ||
                    !owner_accepts(&out[j], expected[id - 1].client_id,
                                   expected[id - 1].generation)) {
                    (void)stop_destroy(pool, 0);
                    return check(0, "payload integrity and stale generation rejection");
                }
                received++;
            }
        }
    }
    if (io_worker_pool_error(pool) || stop_destroy(pool, 1) < 0)
        return check(0, "round-robin shutdown");
    puts("PASS round-robin, copied payload, and generation-token validation");
    return 0;
}

static int poll_and_drain(io_worker_pool_t *pool, uint32_t workers,
                          uint32_t capacity, unsigned int *received,
                          unsigned int target, unsigned char *seen)
{
    struct pollfd fds[IO_WORKER_POOL_MAX_WORKERS];
    for (uint32_t i = 0; i < workers; i++)
        fds[i] = (struct pollfd){io_worker_pool_completion_fd(pool, i), POLLIN, 0};
    if (poll(fds, workers, 5000) <= 0) return -1;
    for (uint32_t i = 0; i < workers; i++) if (fds[i].revents & POLLIN) {
        io_worker_completion_t out[64];
        size_t n = io_worker_pool_drain_completions(pool, i, out, capacity);
        for (size_t j = 0; j < n; j++) {
            if (out[j].status != 0) return -1;
            if (seen) {
                uint64_t id = out[j].task_id;
                if (!id || id > target || seen[id]) return -1;
                io_worker_task_t expected;
                make_task(&expected, id, id % 31 + 1,
                          UINT64_C(0xabc0000000000000) ^ id);
                if (verify(&out[j], &expected) < 0) return -1;
                seen[id] = 1;
            }
            (*received)++;
        }
    }
    return 0;
}

static int test_backpressure_and_stress(void)
{
    test_context_t ctx = {.delay_us = 20000};
    io_worker_pool_t *pool = io_worker_pool_create(2, 2, execute_task, &ctx);
    if (check(pool != NULL, "create backpressure pool")) return -1;
    io_worker_task_t task;
    for (uint64_t i = 1; i <= 4; i++) {
        make_task(&task, i, 1, 9);
        if (io_worker_pool_submit(pool, &task, NULL) < 0) {
            (void)stop_destroy(pool, 0);
            return check(0, "submit bounded tasks");
        }
    }
    make_task(&task, 5, 1, 9);
    errno = 0;
    if (check(io_worker_pool_submit(pool, &task, NULL) < 0 && errno == EAGAIN,
              "bounded outstanding credits return EAGAIN")) {
        (void)stop_destroy(pool, 0);
        return -1;
    }
    unsigned int received = 0;
    while (received < 4)
        if (poll_and_drain(pool, 2, 2, &received, 4, NULL) < 0) {
            (void)stop_destroy(pool, 0);
            return check(0, "drain backpressure completions");
        }
    make_task(&task, 6, 1, 10);
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0,
              "completion drain releases submission credit")) {
        (void)stop_destroy(pool, 0);
        return -1;
    }
    if (stop_destroy(pool, 1) < 0) return check(0, "backpressure shutdown");
    puts("PASS bounded in-flight credits and EAGAIN backpressure");

    memset(&ctx, 0, sizeof(ctx));
    pool = io_worker_pool_create(4, 64, execute_task, &ctx);
    if (check(pool != NULL, "create 50k stress pool")) return -1;
    unsigned char *seen = calloc(STRESS_TASKS + 1, 1);
    if (!seen) { (void)stop_destroy(pool, 0); return -1; }
    uint64_t next = 1;
    received = 0;
    while (received < STRESS_TASKS) {
        while (next <= STRESS_TASKS) {
            make_task(&task, next, next % 31 + 1,
                      UINT64_C(0xabc0000000000000) ^ next);
            if (io_worker_pool_submit(pool, &task, NULL) == 0) { next++; continue; }
            if (errno == EAGAIN) break;
            free(seen); (void)stop_destroy(pool, 0);
            return check(0, "stress task submission");
        }
        if (poll_and_drain(pool, 4, 64, &received, STRESS_TASKS, seen) < 0) {
            free(seen); (void)stop_destroy(pool, 0);
            return check(0, "stress completions and exactly-once ordering");
        }
    }
    int parallel = atomic_load_explicit(&ctx.max_active, memory_order_relaxed) > 1;
    free(seen);
    if (!parallel || io_worker_pool_error(pool) || stop_destroy(pool, 1) < 0)
        return check(0, "50k stress concurrency or shutdown");
    puts("PASS 50,000-task stress, exactly-once completion, and payload integrity");
    return 0;
}

static int test_eventfd_rearm(void)
{
    test_context_t ctx = {.delay_us = 3000};
    io_worker_pool_t *pool = io_worker_pool_create(1, 8, execute_task, &ctx);
    if (check(pool != NULL, "create eventfd rearm pool")) return -1;
    io_worker_task_t task;
    for (uint64_t i = 1; i <= 8; i++) {
        make_task(&task, i, 77, i + 100);
        if (io_worker_pool_submit(pool, &task, NULL) < 0) {
            (void)stop_destroy(pool, 0);
            return check(0, "submit eventfd rearm batch");
        }
    }
    for (unsigned int i = 0; i < 3000 &&
         (atomic_load_explicit(&ctx.calls, memory_order_relaxed) < 8 ||
          atomic_load_explicit(&ctx.active, memory_order_relaxed) != 0); i++) {
        struct timespec pause = {0, 1000000L};
        (void)nanosleep(&pause, NULL);
    }
    struct timespec settle = {0, 5000000L};
    (void)nanosleep(&settle, NULL);
    struct pollfd fd = {io_worker_pool_completion_fd(pool, 0), POLLIN, 0};
    if (poll(&fd, 1, 3000) <= 0) {
        (void)stop_destroy(pool, 0); return check(0, "completion eventfd readiness");
    }
    io_worker_completion_t out[8];
    if (io_worker_pool_drain_completions(pool, 0, out, 1) != 1) {
        (void)stop_destroy(pool, 0); return check(0, "partial completion drain");
    }
    fd.revents = 0;
    if (check(poll(&fd, 1, 0) == 1 && (fd.revents & POLLIN),
              "eventfd rearm while completions remain")) {
        (void)stop_destroy(pool, 0); return -1;
    }
    if (check(io_worker_pool_drain_completions(pool, 0, out, 8) == 7,
              "drain remaining completion records")) {
        (void)stop_destroy(pool, 0); return -1;
    }
    if (stop_destroy(pool, 1) < 0) return check(0, "eventfd rearm shutdown");
    puts("PASS eventfd re-arm after partial completion drain");
    return 0;
}

static int test_shutdown(void)
{
    test_context_t ctx = {.delay_us = 50000};
    io_worker_pool_t *pool = io_worker_pool_create(2, 8, execute_task, &ctx);
    if (check(pool != NULL, "create cancel pool")) return -1;
    io_worker_task_t task;
    for (uint64_t i = 1; i <= 8; i++) {
        make_task(&task, i, 2, 3);
        if (io_worker_pool_submit(pool, &task, NULL) < 0) {
            (void)stop_destroy(pool, 0); return check(0, "submit cancel tasks");
        }
    }
    for (unsigned int i = 0; i < 2000 &&
         atomic_load_explicit(&ctx.active, memory_order_relaxed) < 2; i++) {
        struct timespec pause = {0, 1000000L};
        (void)nanosleep(&pause, NULL);
    }
    if (check(atomic_load_explicit(&ctx.active, memory_order_relaxed) == 2,
              "both workers entered callback")) {
        (void)stop_destroy(pool, 0); return -1;
    }
    if (check(io_worker_pool_request_stop(pool, 0) == 0,
              "request cancel-pending shutdown")) return -1;
    errno = 0;
    if (check(io_worker_pool_request_stop(pool, 1) < 0 && errno == EALREADY,
              "shutdown mode is immutable")) return -1;
    errno = 0;
    if (check(io_worker_pool_join(pool, 1) < 0 && errno == ETIMEDOUT,
              "bounded join timeout is retryable")) return -1;
    if (io_worker_pool_join(pool, 5000) < 0) return check(0, "join after timeout");
    unsigned int total = 0, canceled = 0;
    for (uint32_t i = 0; i < 2; i++) {
        io_worker_completion_t out[8];
        size_t n = io_worker_pool_drain_completions(pool, i, out, 8);
        total += (unsigned int)n;
        for (size_t j = 0; j < n; j++)
            if (out[j].status == ECANCELED) canceled++;
            else if (out[j].status != 0) return check(0, "cancel completion status");
    }
    if (check(total == 8 && canceled > 0, "queued tasks canceled with ECANCELED"))
        return -1;
    if (check(io_worker_pool_destroy(pool) == 0, "destroy joined pool")) return -1;

    memset(&ctx, 0, sizeof(ctx));
    pool = io_worker_pool_create(2, 4, execute_task, &ctx);
    if (check(pool != NULL, "create idle workers")) return -1;
    if (stop_destroy(pool, 1) < 0) return check(0, "idle workers wake and drain-stop");
    puts("PASS cancel/drain shutdown, retryable join timeout, and idle wakeup");
    return 0;
}


static void make_socket_task(io_worker_task_t *task, uint64_t id, int fd,
                             uint32_t opcode, const void *bytes,
                             uint32_t length)
{
    memset(task, 0, sizeof(*task));
    task->task_id = id;
    task->client_id = 77;
    task->generation = 9001;
    task->opcode = opcode;
    memcpy(task->payload, &fd, sizeof(int32_t));
    memcpy(task->payload + 4U, &length, sizeof(length));
    if (bytes && length && opcode == IO_WORKER_OP_SOCKET_WRITE)
        memcpy(task->payload + 8U, bytes, length);
    task->payload_len = opcode == IO_WORKER_OP_SOCKET_WRITE ?
                        8U + length : 8U;
}

static int wait_socket_completion(io_worker_pool_t *pool,
                                   io_worker_completion_t *out)
{
    struct pollfd pfd = {io_worker_pool_completion_fd(pool, 0), POLLIN, 0};
    if (poll(&pfd, 1, 3000) <= 0 || !(pfd.revents & POLLIN)) return -1;
    return io_worker_pool_drain_completions(pool, 0, out, 1) == 1 ? 0 : -1;
}

static int test_socket_io_primitives(void)
{
    int pair[2] = {-1, -1};
    if (check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         0, pair) == 0, "create nonblocking socketpair"))
        return -1;

    io_worker_pool_t *pool = io_worker_pool_create(1, 8,
                                                   io_worker_socket_execute,
                                                   NULL);
    if (check(pool != NULL, "create socket I/O worker")) {
        close(pair[0]); close(pair[1]); return -1;
    }

    io_worker_task_t task;
    io_worker_completion_t done;
    const char outbound[] = "worker-send-partial-safe";
    make_socket_task(&task, 1, pair[0], IO_WORKER_OP_SOCKET_WRITE,
                     outbound, (uint32_t)(sizeof(outbound) - 1U));
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0 &&
              wait_socket_completion(pool, &done) == 0 &&
              done.status == 0 &&
              done.result_len == sizeof(outbound) - 1U,
              "worker nonblocking socket write completion")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }
    char received[64] = {0};
    ssize_t nr = recv(pair[1], received, sizeof(received), MSG_DONTWAIT);
    if (check(nr == (ssize_t)(sizeof(outbound) - 1U) &&
              memcmp(received, outbound, sizeof(outbound) - 1U) == 0,
              "worker write payload integrity")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }

    /* Exercise the full S2C worker payload, not only a short control-sized write. */
    uint8_t large_out[IO_WORKER_SOCKET_WRITE_MAX];
    uint8_t large_received[IO_WORKER_SOCKET_WRITE_MAX];
    for (size_t i = 0; i < sizeof(large_out); i++)
        large_out[i] = (uint8_t)(i * 37U + 11U);
    make_socket_task(&task, 5, pair[0], IO_WORKER_OP_SOCKET_WRITE,
                     large_out, (uint32_t)sizeof(large_out));
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0 &&
              wait_socket_completion(pool, &done) == 0 &&
              done.status == 0 &&
              done.result_len == sizeof(large_out),
              "worker accepts a full 16 KiB socket write")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }
    size_t large_received_len = 0U;
    while (large_received_len < sizeof(large_received)) {
        ssize_t got = recv(pair[1], large_received + large_received_len,
                           sizeof(large_received) - large_received_len,
                           MSG_DONTWAIT);
        if (got > 0) {
            large_received_len += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) continue;
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd readable = {pair[1], POLLIN, 0};
            if (poll(&readable, 1, 3000) > 0) continue;
        }
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]);
        return check(0, "read complete 16 KiB worker write");
    }
    if (check(memcmp(large_received, large_out, sizeof(large_out)) == 0,
              "full-size worker write payload integrity")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }

    const char inbound[] = "owner-receive";
    if (send(pair[1], inbound, sizeof(inbound) - 1U, MSG_NOSIGNAL) !=
        (ssize_t)(sizeof(inbound) - 1U)) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]);
        return check(0, "seed socket read data");
    }
    make_socket_task(&task, 2, pair[0], IO_WORKER_OP_SOCKET_READ, NULL,
                     IO_WORKER_POOL_PAYLOAD_SIZE);
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0 &&
              wait_socket_completion(pool, &done) == 0 &&
              done.status == 0 &&
              done.result_len == sizeof(inbound) - 1U &&
              memcmp(done.result, inbound, sizeof(inbound) - 1U) == 0,
              "worker read copies bytes into completion")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }

    make_socket_task(&task, 3, pair[0], IO_WORKER_OP_SOCKET_READ, NULL, 32U);
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0 &&
              wait_socket_completion(pool, &done) == 0 &&
              done.status == EAGAIN && done.result_len == 0U,
              "worker read reports EAGAIN without blocking")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }

    if (shutdown(pair[1], SHUT_WR) < 0) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]);
        return check(0, "shutdown peer write side");
    }
    make_socket_task(&task, 4, pair[0], IO_WORKER_OP_SOCKET_READ, NULL, 32U);
    if (check(io_worker_pool_submit(pool, &task, NULL) == 0 &&
              wait_socket_completion(pool, &done) == 0 &&
              done.status == 0 && done.result_len == 0U,
              "worker read reports orderly EOF")) {
        (void)stop_destroy(pool, 0); close(pair[0]); close(pair[1]); return -1;
    }

    if (stop_destroy(pool, 1) < 0) {
        close(pair[0]); close(pair[1]);
        return check(0, "socket worker graceful shutdown");
    }
    close(pair[0]); close(pair[1]);
    puts("PASS bounded nonblocking socket read/write, EAGAIN, EOF, copied completion");
    return 0;
}

int main(void)
{
    if (test_validation() < 0 || test_round_robin_generation() < 0 ||
        test_backpressure_and_stress() < 0 || test_eventfd_rearm() < 0 ||
        test_socket_io_primitives() < 0 || test_shutdown() < 0) {
        puts("IO worker pool regression FAILED");
        return 1;
    }
    puts("IO worker pool regression PASSED");
    return 0;
}
