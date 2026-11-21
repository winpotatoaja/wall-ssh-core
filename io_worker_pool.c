#define _GNU_SOURCE
#include "io_worker_pool.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#define IO_WORKER_QUEUE_MAX (1U << 20)
#define IO_WORKER_CACHELINE 64U

typedef struct {
    _Alignas(IO_WORKER_CACHELINE) uint32_t head;
    unsigned char head_pad[IO_WORKER_CACHELINE - sizeof(uint32_t)];
    _Alignas(IO_WORKER_CACHELINE) uint32_t tail;
    unsigned char tail_pad[IO_WORKER_CACHELINE - sizeof(uint32_t)];
    uint32_t capacity;
    uint32_t mask;
    size_t item_size;
    unsigned char *items;
} worker_spsc_queue_t;

_Static_assert(offsetof(worker_spsc_queue_t, tail) -
               offsetof(worker_spsc_queue_t, head) >= IO_WORKER_CACHELINE,
               "SPSC indices must use separate cache-line strides");
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0),
               "worker queue requires lock-free 32-bit atomics");

typedef struct {
    uint32_t command;
    uint32_t drain_pending;
} worker_control_t;

#define WORKER_CONTROL_STOP 1U
#define WORKER_CONTROL_QUEUE_CAPACITY 2U

typedef struct io_worker io_worker_t;

struct io_worker {
    struct io_worker_pool *pool;
    pthread_t thread;
    int thread_started;
    int joined;
    int task_event_fd;
    int completion_event_fd;
    int done_event_fd;
    worker_spsc_queue_t controls;
    worker_spsc_queue_t tasks;
    worker_spsc_queue_t completions;
    uint32_t outstanding;
    uint32_t worker_id;
};

struct io_worker_pool {
    uint32_t worker_count;
    uint32_t queue_capacity;
    uint32_t next_worker;
    io_worker_execute_fn execute;
    const void *context;
    io_worker_t workers[IO_WORKER_POOL_MAX_WORKERS];
    int stop_mode;
    int joined_count;
    int fatal_error;
};

static int queue_init(worker_spsc_queue_t *q, uint32_t capacity,
                      size_t item_size)
{
    if (!q || capacity < 2U || capacity > IO_WORKER_QUEUE_MAX ||
        (capacity & (capacity - 1U)) != 0U || item_size == 0U ||
        (size_t)capacity > SIZE_MAX / item_size) {
        errno = EINVAL;
        return -1;
    }

    memset(q, 0, sizeof(*q));
    q->items = (unsigned char *)calloc((size_t)capacity, item_size);
    if (!q->items)
        return -1;
    q->capacity = capacity;
    q->mask = capacity - 1U;
    q->item_size = item_size;
    __atomic_store_n(&q->head, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&q->tail, 0U, __ATOMIC_RELAXED);
    return 0;
}

static void queue_destroy(worker_spsc_queue_t *q)
{
    if (!q)
        return;
    free(q->items);
    q->items = NULL;
    q->capacity = 0U;
    q->mask = 0U;
    q->item_size = 0U;
    __atomic_store_n(&q->head, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&q->tail, 0U, __ATOMIC_RELAXED);
}

/* Exactly one producer; queue publication is the release-store to tail. */
static int queue_push(worker_spsc_queue_t *q, const void *item)
{
    uint32_t tail = __atomic_load_n(&q->tail, __ATOMIC_RELAXED);
    uint32_t head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);
    uint32_t used = (uint32_t)(tail - head);
    if (used > q->capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    if (used == q->capacity)
        return 0;

    memcpy(q->items + (size_t)(tail & q->mask) * q->item_size,
           item, q->item_size);
    __atomic_store_n(&q->tail, tail + 1U, __ATOMIC_RELEASE);
    return 1;
}

/* Exactly one consumer; acquire-load of tail observes the complete item. */
static int queue_pop(worker_spsc_queue_t *q, void *item)
{
    uint32_t head = __atomic_load_n(&q->head, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
    uint32_t used = (uint32_t)(tail - head);
    if (used > q->capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    if (used == 0U)
        return 0;

    memcpy(item, q->items + (size_t)(head & q->mask) * q->item_size,
           q->item_size);
    __atomic_store_n(&q->head, head + 1U, __ATOMIC_RELEASE);
    return 1;
}

static int queue_is_empty(const worker_spsc_queue_t *q)
{
    uint32_t head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
    return head == tail;
}

/* EAGAIN is safe: an eventfd already at its maximum count remains readable. */
static int eventfd_signal(int fd)
{
    const uint64_t one = 1U;
    for (;;) {
        ssize_t n = write(fd, &one, sizeof(one));
        if (n == (ssize_t)sizeof(one) || (n < 0 && errno == EAGAIN))
            return 0;
        if (n < 0 && errno == EINTR)
            continue;
        if (n >= 0)
            errno = EIO;
        return -1;
    }
}

static void eventfd_drain(int fd)
{
    uint64_t value;
    for (;;) {
        ssize_t n = read(fd, &value, sizeof(value));
        if (n == (ssize_t)sizeof(value))
            continue;
        if (n < 0 && errno == EINTR)
            continue;
        break;
    }
}

static void pool_set_error(io_worker_pool_t *pool, int error)
{
    int expected = 0;
    if (error <= 0)
        error = EIO;
    if (__atomic_compare_exchange_n(&pool->fatal_error, &expected, error,
                                   0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&pool->stop_mode, 0, __ATOMIC_RELEASE);
        /* Fatal state is out-of-band so each per-worker control queue stays SPSC. */
        for (uint32_t i = 0U; i < pool->worker_count; i++) {
            int fd = pool->workers[i].task_event_fd;
            if (fd >= 0)
                (void)eventfd_signal(fd);
        }
    }
}

static void *worker_thread_main(void *opaque)
{
    io_worker_t *worker = (io_worker_t *)opaque;
    io_worker_pool_t *pool = worker->pool;
    struct pollfd pfd = {worker->task_event_fd, POLLIN, 0};
    int local_stop_mode = -1;

    for (;;) {
        eventfd_drain(worker->task_event_fd);

        for (;;) {
            for (;;) {
                worker_control_t control;
                int control_rc = queue_pop(&worker->controls, &control);
                if (control_rc < 0) {
                    pool_set_error(pool, errno);
                    break;
                }
                if (control_rc == 0)
                    break;
                if (control.command == WORKER_CONTROL_STOP &&
                    control.drain_pending <= 1U)
                    local_stop_mode = (int)control.drain_pending;
                else
                    pool_set_error(pool, EPROTO);
            }
            if (__atomic_load_n(&pool->fatal_error, __ATOMIC_ACQUIRE) != 0)
                break;

            /* Also observe this out-of-band path after partial pthread_create failure. */
            if (local_stop_mode < 0) {
                int shared_stop = __atomic_load_n(&pool->stop_mode,
                                                  __ATOMIC_ACQUIRE);
                if (shared_stop >= 0)
                    local_stop_mode = shared_stop;
            }

            io_worker_task_t task;
            int pop_rc = queue_pop(&worker->tasks, &task);
            if (pop_rc < 0) {
                pool_set_error(pool, errno);
                break;
            }
            if (pop_rc == 0)
                break;

            io_worker_completion_t completion;
            memset(&completion, 0, sizeof(completion));
            int status;
            if (local_stop_mode == 0) {
                status = ECANCELED;
            } else {
                status = pool->execute(&task, &completion, pool->context);
                if (status < 0)
                    status = EIO;
            }
            if (completion.result_len > IO_WORKER_POOL_PAYLOAD_SIZE) {
                completion.result_len = 0U;
                status = EOVERFLOW;
            }
            /* Callback cannot rewrite the client-generation identity token. */
            completion.task_id = task.task_id;
            completion.client_id = task.client_id;
            completion.generation = task.generation;
            completion.worker_id = worker->worker_id;
            completion.status = status;

            int push_rc = queue_push(&worker->completions, &completion);
            if (push_rc != 1) {
                pool_set_error(pool, push_rc < 0 ? errno : EOVERFLOW);
                break;
            }
            if (eventfd_signal(worker->completion_event_fd) < 0)
                pool_set_error(pool, errno);
        }

        if (__atomic_load_n(&pool->fatal_error, __ATOMIC_ACQUIRE) != 0)
            break;
        if (local_stop_mode >= 0 && queue_is_empty(&worker->tasks))
            break;

        pfd.revents = 0;
        int poll_rc;
        do {
            poll_rc = poll(&pfd, 1U, -1);
        } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            pool_set_error(pool, poll_rc < 0 ? errno : EIO);
            break;
        }
    }

    if (eventfd_signal(worker->done_event_fd) < 0)
        pool_set_error(pool, errno);
    return NULL;
}

static void worker_resources_close(io_worker_t *worker)
{
    if (worker->task_event_fd >= 0)
        close(worker->task_event_fd);
    if (worker->completion_event_fd >= 0)
        close(worker->completion_event_fd);
    if (worker->done_event_fd >= 0)
        close(worker->done_event_fd);
    worker->task_event_fd = -1;
    worker->completion_event_fd = -1;
    worker->done_event_fd = -1;
    queue_destroy(&worker->controls);
    queue_destroy(&worker->tasks);
    queue_destroy(&worker->completions);
}

io_worker_pool_t *io_worker_pool_create(uint32_t worker_count,
                                        uint32_t queue_capacity,
                                        io_worker_execute_fn execute,
                                        const void *context)
{
    if (worker_count == 0U || worker_count > IO_WORKER_POOL_MAX_WORKERS ||
        queue_capacity < 2U || queue_capacity > IO_WORKER_QUEUE_MAX ||
        (queue_capacity & (queue_capacity - 1U)) != 0U || !execute) {
        errno = EINVAL;
        return NULL;
    }

    io_worker_pool_t *pool = NULL;
    int alloc_rc = posix_memalign((void **)&pool, IO_WORKER_CACHELINE,
                                  sizeof(*pool));
    if (alloc_rc != 0) {
        errno = alloc_rc;
        return NULL;
    }
    memset(pool, 0, sizeof(*pool));
    pool->worker_count = worker_count;
    pool->queue_capacity = queue_capacity;
    pool->execute = execute;
    pool->context = context;
    pool->stop_mode = -1;
    for (uint32_t i = 0U; i < IO_WORKER_POOL_MAX_WORKERS; i++) {
        io_worker_t *worker = &pool->workers[i];
        worker->pool = pool;
        worker->worker_id = i;
        worker->task_event_fd = -1;
        worker->completion_event_fd = -1;
        worker->done_event_fd = -1;
    }

    for (uint32_t i = 0U; i < worker_count; i++) {
        io_worker_t *worker = &pool->workers[i];
        if (queue_init(&worker->controls, WORKER_CONTROL_QUEUE_CAPACITY,
                       sizeof(worker_control_t)) < 0 ||
            queue_init(&worker->tasks, queue_capacity,
                       sizeof(io_worker_task_t)) < 0 ||
            queue_init(&worker->completions, queue_capacity,
                       sizeof(io_worker_completion_t)) < 0)
            goto fail_resources;
        worker->task_event_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
        worker->completion_event_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
        worker->done_event_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
        if (worker->task_event_fd < 0 || worker->completion_event_fd < 0 ||
            worker->done_event_fd < 0)
            goto fail_resources;
    }

    for (uint32_t i = 0U; i < worker_count; i++) {
        io_worker_t *worker = &pool->workers[i];
        pthread_attr_t attr;
        int rc = pthread_attr_init(&attr);
        if (rc != 0) {
            errno = rc;
            goto fail_threads;
        }
        rc = pthread_attr_setstacksize(&attr, IO_WORKER_POOL_STACK_SIZE);
        if (rc == 0)
            rc = pthread_create(&worker->thread, &attr, worker_thread_main, worker);
        (void)pthread_attr_destroy(&attr);
        if (rc != 0) {
            errno = rc;
            goto fail_threads;
        }
        worker->thread_started = 1;
    }
    return pool;

fail_threads:
    __atomic_store_n(&pool->stop_mode, 0, __ATOMIC_RELEASE);
    for (uint32_t i = 0U; i < worker_count; i++) {
        io_worker_t *worker = &pool->workers[i];
        if (worker->thread_started)
            (void)eventfd_signal(worker->task_event_fd);
    }
    for (uint32_t i = 0U; i < worker_count; i++) {
        io_worker_t *worker = &pool->workers[i];
        if (worker->thread_started) {
            (void)pthread_join(worker->thread, NULL);
            worker->joined = 1;
        }
    }
fail_resources:
    for (uint32_t i = 0U; i < worker_count; i++)
        worker_resources_close(&pool->workers[i]);
    free(pool);
    return NULL;
}

static int validate_submit(io_worker_pool_t *pool,
                           const io_worker_task_t *task)
{
    if (!pool || !task || task->payload_len > IO_WORKER_POOL_PAYLOAD_SIZE) {
        errno = EINVAL;
        return -1;
    }
    if (__atomic_load_n(&pool->stop_mode, __ATOMIC_ACQUIRE) >= 0) {
        errno = ESHUTDOWN;
        return -1;
    }
    int fatal = __atomic_load_n(&pool->fatal_error, __ATOMIC_ACQUIRE);
    if (fatal != 0) {
        errno = fatal;
        return -1;
    }
    return 0;
}

int io_worker_pool_select_worker(const io_worker_pool_t *pool,
                                 uint32_t *worker_id_out)
{
    if (!pool || !worker_id_out) {
        errno = EINVAL;
        return -1;
    }
    if (__atomic_load_n(&pool->stop_mode, __ATOMIC_ACQUIRE) >= 0) {
        errno = ESHUTDOWN;
        return -1;
    }
    int fatal = __atomic_load_n(&pool->fatal_error, __ATOMIC_ACQUIRE);
    if (fatal != 0) {
        errno = fatal;
        return -1;
    }
    for (uint32_t step = 0U; step < pool->worker_count; step++) {
        uint32_t index = (pool->next_worker + step) % pool->worker_count;
        if (pool->workers[index].outstanding < pool->queue_capacity) {
            *worker_id_out = index;
            return 0;
        }
    }
    errno = EAGAIN;
    return -1;
}

int io_worker_pool_submit_to_worker(io_worker_pool_t *pool,
                                    const io_worker_task_t *task,
                                    uint32_t worker_id)
{
    if (validate_submit(pool, task) < 0)
        return -1;
    if (worker_id >= pool->worker_count) {
        errno = EINVAL;
        return -1;
    }
    io_worker_t *worker = &pool->workers[worker_id];
    if (worker->outstanding >= pool->queue_capacity) {
        errno = EAGAIN;
        return -1;
    }
    int push_rc = queue_push(&worker->tasks, task);
    if (push_rc < 0) {
        pool_set_error(pool, errno);
        return -1;
    }
    if (push_rc == 0) {
        errno = EAGAIN;
        return -1;
    }

    worker->outstanding++;
    pool->next_worker = (worker_id + 1U) % pool->worker_count;
    /* Task publication always precedes the eventfd write. */
    if (eventfd_signal(worker->task_event_fd) < 0) {
        pool_set_error(pool, errno);
        return 0; /* Accepted task; pool_error() reports fatal notification failure. */
    }
    return 0;
}

int io_worker_pool_submit(io_worker_pool_t *pool,
                          const io_worker_task_t *task,
                          uint32_t *worker_id_out)
{
    if (validate_submit(pool, task) < 0)
        return -1;
    uint32_t worker_id = 0U;
    if (io_worker_pool_select_worker(pool, &worker_id) < 0)
        return -1;
    if (io_worker_pool_submit_to_worker(pool, task, worker_id) < 0)
        return -1;
    if (worker_id_out)
        *worker_id_out = worker_id;
    return 0;
}
int io_worker_pool_completion_fd(const io_worker_pool_t *pool,
                                 uint32_t worker_id)
{
    if (!pool || worker_id >= pool->worker_count) {
        errno = EINVAL;
        return -1;
    }
    return pool->workers[worker_id].completion_event_fd;
}

size_t io_worker_pool_drain_completions(io_worker_pool_t *pool,
                                        uint32_t worker_id,
                                        io_worker_completion_t *out,
                                        size_t out_capacity)
{
    if (!pool || worker_id >= pool->worker_count || !out || out_capacity == 0U) {
        errno = EINVAL;
        return 0U;
    }

    io_worker_t *worker = &pool->workers[worker_id];
    eventfd_drain(worker->completion_event_fd);
    size_t count = 0U;
    while (count < out_capacity) {
        int pop_rc = queue_pop(&worker->completions, &out[count]);
        if (pop_rc < 0) {
            pool_set_error(pool, errno);
            break;
        }
        if (pop_rc == 0)
            break;
        count++;
        if (worker->outstanding > 0U)
            worker->outstanding--;
        else
            pool_set_error(pool, EOVERFLOW);
    }

    /* Preserve level-triggered epoll readiness when a bounded drain leaves records. */
    if (!queue_is_empty(&worker->completions) &&
        eventfd_signal(worker->completion_event_fd) < 0)
        pool_set_error(pool, errno);
    return count;
}

uint32_t io_worker_pool_worker_count(const io_worker_pool_t *pool)
{
    return pool ? pool->worker_count : 0U;
}

uint32_t io_worker_pool_outstanding(const io_worker_pool_t *pool,
                                    uint32_t worker_id)
{
    if (!pool || worker_id >= pool->worker_count)
        return 0U;
    return pool->workers[worker_id].outstanding;
}

int io_worker_pool_error(const io_worker_pool_t *pool)
{
    return pool ? __atomic_load_n(&pool->fatal_error, __ATOMIC_ACQUIRE) : EINVAL;
}

int io_worker_pool_request_stop(io_worker_pool_t *pool, int drain_pending)
{
    if (!pool || (drain_pending != 0 && drain_pending != 1)) {
        errno = EINVAL;
        return -1;
    }
    int expected = -1;
    if (!__atomic_compare_exchange_n(&pool->stop_mode, &expected, drain_pending,
                                     0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (expected != drain_pending) {
            errno = EALREADY;
            return -1;
        }
        return 0;
    }

    worker_control_t control = {WORKER_CONTROL_STOP, (uint32_t)drain_pending};
    for (uint32_t i = 0U; i < pool->worker_count; i++) {
        io_worker_t *worker = &pool->workers[i];
        int control_rc = queue_push(&worker->controls, &control);
        if (control_rc != 1) {
            int error = control_rc < 0 ? errno : EOVERFLOW;
            pool_set_error(pool, error);
            errno = error;
            return -1;
        }
        if (eventfd_signal(worker->task_event_fd) < 0) {
            pool_set_error(pool, errno);
            return -1;
        }
    }
    return 0;
}

static int remaining_timeout_ms(const struct timespec *start, int timeout_ms)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    int64_t elapsed_ns = ((int64_t)now.tv_sec - (int64_t)start->tv_sec) *
                         1000000000LL +
                         ((int64_t)now.tv_nsec - (int64_t)start->tv_nsec);
    int64_t remain_ns = (int64_t)timeout_ms * 1000000LL - elapsed_ns;
    if (remain_ns <= 0)
        return 0;
    int64_t remain_ms = (remain_ns + 999999LL) / 1000000LL;
    return remain_ms > INT32_MAX ? INT32_MAX : (int)remain_ms;
}

int io_worker_pool_join(io_worker_pool_t *pool, int timeout_ms)
{
    if (!pool || timeout_ms < 0 ||
        __atomic_load_n(&pool->stop_mode, __ATOMIC_ACQUIRE) < 0) {
        errno = EINVAL;
        return -1;
    }

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
        return -1;

    while (pool->joined_count < (int)pool->worker_count) {
        struct pollfd pfds[IO_WORKER_POOL_MAX_WORKERS];
        uint32_t ids[IO_WORKER_POOL_MAX_WORKERS];
        nfds_t count = 0U;
        for (uint32_t i = 0U; i < pool->worker_count; i++) {
            io_worker_t *worker = &pool->workers[i];
            if (worker->joined)
                continue;
            pfds[count].fd = worker->done_event_fd;
            pfds[count].events = POLLIN;
            pfds[count].revents = 0;
            ids[count] = i;
            count++;
        }
        if (count == 0U)
            break;

        int remain = remaining_timeout_ms(&start, timeout_ms);
        if (remain < 0)
            return -1;
        int poll_rc;
        do {
            poll_rc = poll(pfds, count, remain);
            if (poll_rc < 0 && errno == EINTR) {
                remain = remaining_timeout_ms(&start, timeout_ms);
                if (remain < 0)
                    return -1;
            }
        } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (poll_rc < 0)
            return -1;

        for (nfds_t j = 0U; j < count; j++) {
            if (!(pfds[j].revents & POLLIN)) {
                if (pfds[j].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    errno = EIO;
                    return -1;
                }
                continue;
            }
            io_worker_t *worker = &pool->workers[ids[j]];
            eventfd_drain(worker->done_event_fd);
            int rc = pthread_join(worker->thread, NULL);
            if (rc != 0) {
                errno = rc;
                return -1;
            }
            worker->joined = 1;
            pool->joined_count++;
        }
        if (remaining_timeout_ms(&start, timeout_ms) == 0 &&
            pool->joined_count < (int)pool->worker_count) {
            errno = ETIMEDOUT;
            return -1;
        }
    }
    return 0;
}

int io_worker_pool_destroy(io_worker_pool_t *pool)
{
    if (!pool) {
        errno = EINVAL;
        return -1;
    }
    if (pool->joined_count != (int)pool->worker_count) {
        errno = EBUSY;
        return -1;
    }
    for (uint32_t i = 0U; i < pool->worker_count; i++)
        worker_resources_close(&pool->workers[i]);
    free(pool);
    return 0;
}

/*
 * Execute one bounded, nonblocking operation on a local client socket.
 * The SSH Owner passes only an FD value and copied bytes; no client/session
 * pointer crosses the thread boundary. The Owner must pin the FD lifetime
 * until it consumes this task's completion (including stale completions).
 */
int io_worker_socket_execute(const io_worker_task_t *task,
                             io_worker_completion_t *completion,
                             const void *context)
{
    int32_t fd_value;
    uint32_t length;
    ssize_t n;

    (void)context;
    if (!task || !completion || task->payload_len < 8U) return EINVAL;
    memcpy(&fd_value, task->payload, sizeof(fd_value));
    memcpy(&length, task->payload + sizeof(fd_value), sizeof(length));
    if (fd_value < 0 || length == 0U) return EINVAL;

    if (task->opcode == IO_WORKER_OP_SOCKET_READ) {
        if (task->payload_len != 8U ||
            length > IO_WORKER_POOL_PAYLOAD_SIZE) return EINVAL;
        do {
            n = recv((int)fd_value, completion->result, (size_t)length,
                     MSG_DONTWAIT);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return errno;
        completion->result_len = (uint32_t)n; /* zero is orderly EOF */
        return 0;
    }

    if (task->opcode == IO_WORKER_OP_SOCKET_WRITE) {
        if (length > IO_WORKER_SOCKET_WRITE_MAX ||
            task->payload_len != 8U + length) return EINVAL;
        do {
            n = send((int)fd_value, task->payload + 8U, (size_t)length,
                     MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return errno;
        if (n == 0) return EPIPE;
        completion->result_len = (uint32_t)n; /* partial writes are valid */
        return 0;
    }

    return EOPNOTSUPP;
}
