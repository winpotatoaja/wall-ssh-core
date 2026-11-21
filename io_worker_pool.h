#ifndef PASSWALL_SSH_CORE_IO_WORKER_POOL_H
#define PASSWALL_SSH_CORE_IO_WORKER_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IO_WORKER_POOL_MAX_WORKERS 4U
#define IO_WORKER_POOL_PAYLOAD_SIZE 128U
#define IO_WORKER_POOL_STACK_SIZE (512U * 1024U)

typedef struct io_worker_pool io_worker_pool_t;

typedef struct {
    uint64_t task_id;
    uint64_t client_id;
    uint64_t generation;
    uint32_t opcode;
    uint32_t payload_len;
    uint8_t payload[IO_WORKER_POOL_PAYLOAD_SIZE];
} io_worker_task_t;

typedef struct {
    uint64_t task_id;
    uint64_t client_id;
    uint64_t generation;
    uint32_t worker_id;
    int32_t status; /* zero on success; otherwise a positive errno value */
    uint32_t result_len;
    uint8_t result[IO_WORKER_POOL_PAYLOAD_SIZE];
} io_worker_completion_t;

/*
 * The callback runs on a worker thread. It receives only a copied task and a
 * private completion record; it must not retain either pointer. The optional
 * context is borrowed read-only or independently synchronized data. It must
 * never reference a client_conn, LIBSSH2_SESSION, TLS Engine, or other mutable
 * SSH-Owner state.
 * The callback must be bounded and must not wait for work that only the SSH
 * Owner can perform. Return zero or a positive errno value.
 */
typedef int (*io_worker_execute_fn)(const io_worker_task_t *task,
                                     io_worker_completion_t *completion,
                                     const void *context);

/* queue_capacity is a power of two in [2, 2^20], per worker. */
io_worker_pool_t *io_worker_pool_create(uint32_t worker_count,
                                        uint32_t queue_capacity,
                                        io_worker_execute_fn execute,
                                        const void *context);

/*
 * Single SSH-Owner producer. The task is copied before this function returns.
 * Returns 0 on acceptance, -1 with errno=EAGAIN when all worker credits are
 * occupied, or -1 for invalid/shutdown state. No client pointer is accepted.
 */
int io_worker_pool_submit(io_worker_pool_t *pool,
                          const io_worker_task_t *task,
                          uint32_t *worker_id_out);

/* Single SSH-Owner consumer: add this fd to epoll, then drain on readiness. */
int io_worker_pool_completion_fd(const io_worker_pool_t *pool,
                                 uint32_t worker_id);
size_t io_worker_pool_drain_completions(io_worker_pool_t *pool,
                                        uint32_t worker_id,
                                        io_worker_completion_t *out,
                                        size_t out_capacity);
uint32_t io_worker_pool_worker_count(const io_worker_pool_t *pool);
uint32_t io_worker_pool_outstanding(const io_worker_pool_t *pool,
                                    uint32_t worker_id);
int io_worker_pool_error(const io_worker_pool_t *pool);

/*
 * Stop request is idempotent only when drain_pending matches the first call.
 * drain_pending=1 completes queued tasks; zero completes them with ECANCELED.
 * A callback already running is allowed to finish in either mode.
 */
int io_worker_pool_request_stop(io_worker_pool_t *pool, int drain_pending);

/* Wait at most timeout_ms for all workers, then join. Timeout leaves the pool
 * allocated and safe to retry; do not destroy it while any worker is alive.
 */
int io_worker_pool_join(io_worker_pool_t *pool, int timeout_ms);

/* Destroy succeeds only after every started worker has been joined. */
int io_worker_pool_destroy(io_worker_pool_t *pool);

#ifdef __cplusplus
}
#endif

#endif
