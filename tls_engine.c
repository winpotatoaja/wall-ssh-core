#define _GNU_SOURCE
#include "tls_engine.h"
#include "spsc_rb.h"

#include <openssl/err.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#define TLS_ENGINE_IO_CHUNK 16384U
#define TLS_ENGINE_DEFAULT_TIMEOUT_MS 15000
#define TLS_ENGINE_DEFAULT_SHUTDOWN_MS 2500

struct tls_engine {
    spsc_rb_t ssh_to_tls;
    spsc_rb_t tls_to_ssh;
    int worker_event_fd; /* SSH owner -> TLS owner */
    int owner_event_fd;  /* TLS owner -> SSH owner */
    int socket_fd;       /* exclusively owned by TLS owner after start */
    SSL_CTX *ctx;        /* borrowed; caller frees after destroy */
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int mutex_ready;
    int cond_ready;
    int thread_created;
    int thread_joined;
    int startup_done;
    int startup_ok;
    int startup_error;
    int startup_retryable;
    int verify_peer;
    int handshake_timeout_ms;
    int stop_timeout_ms;
    int graceful_stop;
    char server_name[256];
    char tls_version[32];
    char cipher[128];
    int rx_closed;
    int rx_terminal_error;
    int tx_terminal_error;
    int stop_requested;
};

/* All state exchanged across threads uses compiler atomics. */
static void signal_eventfd(int fd)
{
    if (fd < 0) return;
    uint64_t one = 1;
    ssize_t n;
    do {
        n = write(fd, &one, sizeof(one));
    } while (n < 0 && errno == EINTR);
    /* EAGAIN means the eventfd is already readable; the notification is coalesced. */
}

static void drain_eventfd(int fd)
{
    uint64_t value;
    for (;;) {
        ssize_t n = read(fd, &value, sizeof(value));
        if (n == (ssize_t)sizeof(value)) continue;
        if (n < 0 && errno == EINTR) continue;
        break;
    }
}

static int ring_used(const spsc_rb_t *q)
{
    uint32_t head = __atomic_load_n(&q->head.value, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&q->tail.value, __ATOMIC_ACQUIRE);
    uint32_t used = (uint32_t)(tail - head);
    return used > q->capacity ? (int)q->capacity : (int)used;
}

static int ring_free(const spsc_rb_t *q)
{
    int used = ring_used(q);
    return used >= (int)q->capacity ? 0 : (int)q->capacity - used;
}

static void ssl_prepare_io(void)
{
    ERR_clear_error();
    errno = 0;
}

static int ssl_error_to_errno(int error, int saved_errno)
{
    if (error == SSL_ERROR_ZERO_RETURN) return 0;
    if (error == SSL_ERROR_SYSCALL)
        return saved_errno > 0 ? saved_errno : ECONNRESET;

    if (error == SSL_ERROR_SSL) {
        unsigned long code = ERR_peek_last_error();
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
        if (code && ERR_GET_LIB(code) == ERR_LIB_SSL &&
            ERR_GET_REASON(code) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            return ECONNRESET;
#endif
        return EPROTO;
    }
    return EIO;
}

static long long monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int wait_socket_until(int fd, short events, long long deadline_ms)
{
    for (;;) {
        long long remaining = deadline_ms - monotonic_ms();
        if (remaining <= 0) return 0;
        int timeout = remaining > 1000 ? 1000 : (int)remaining;
        struct pollfd pfd = { .fd = fd, .events = events };
        int rc = poll(&pfd, 1, timeout);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) continue;
        if (pfd.revents & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        if (pfd.revents & POLLERR) {
            int error = 0;
            socklen_t length = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
                return -1;
            errno = error ? error : EIO;
            return -1;
        }
        if (pfd.revents & events) return 1;
        if ((pfd.revents & POLLHUP) && (events & POLLIN)) return 1;
        if (pfd.revents & (POLLHUP | POLLERR)) {
            errno = EPIPE;
            return -1;
        }
    }
}

static int tls_handshake(tls_engine_t *engine, SSL **ssl_out,
                         int *retryable_out)
{
    *ssl_out = NULL;
    *retryable_out = 0;

    SSL *ssl = SSL_new(engine->ctx);
    if (!ssl) {
        ERR_clear_error();
        return EIO;
    }

    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
                      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (engine->server_name[0]) {
        if (SSL_set_tlsext_host_name(ssl, engine->server_name) != 1) {
            SSL_free(ssl);
            return EINVAL;
        }
        if (engine->verify_peer &&
            SSL_set1_host(ssl, engine->server_name) != 1) {
            SSL_free(ssl);
            return EINVAL;
        }
    }
    if (SSL_set_fd(ssl, engine->socket_fd) != 1) {
        SSL_free(ssl);
        return EIO;
    }

    long long deadline = monotonic_ms() + engine->handshake_timeout_ms;
    for (;;) {
        ssl_prepare_io();
        int rc = SSL_connect(ssl);
        int saved_errno = errno;
        if (rc == 1) {
            *ssl_out = ssl;
            return 0;
        }

        int error = SSL_get_error(ssl, rc);
        short events = 0;
        if (error == SSL_ERROR_WANT_READ) events = POLLIN;
        else if (error == SSL_ERROR_WANT_WRITE) events = POLLOUT;
        else {
            int mapped = ssl_error_to_errno(error, saved_errno);
            if (mapped == ECONNRESET || mapped == ETIMEDOUT ||
                mapped == EHOSTUNREACH || mapped == ENETUNREACH ||
                mapped == ECONNREFUSED || mapped == EPIPE)
                *retryable_out = 1;
            SSL_free(ssl);
            return mapped ? mapped : ECONNRESET;
        }

        int waited = wait_socket_until(engine->socket_fd, events, deadline);
        if (waited <= 0) {
            int saved = waited < 0 ? errno : ETIMEDOUT;
            *retryable_out = 1;
            SSL_free(ssl);
            return saved;
        }
    }
}

static void publish_startup(tls_engine_t *engine, int ok, int error,
                            int retryable, SSL *ssl)
{
    if (ok && ssl) {
        const char *version = SSL_get_version(ssl);
        const char *cipher = SSL_get_cipher_name(ssl);
        snprintf(engine->tls_version, sizeof(engine->tls_version), "%s",
                 version ? version : "unknown");
        snprintf(engine->cipher, sizeof(engine->cipher), "%s",
                 cipher ? cipher : "unknown");
    }

    pthread_mutex_lock(&engine->mutex);
    engine->startup_done = 1;
    engine->startup_ok = ok;
    __atomic_store_n(&engine->startup_error, error, __ATOMIC_RELEASE);
    __atomic_store_n(&engine->startup_retryable, retryable, __ATOMIC_RELEASE);
    pthread_cond_broadcast(&engine->cond);
    pthread_mutex_unlock(&engine->mutex);
    signal_eventfd(engine->owner_event_fd);
}

static void publish_terminal(tls_engine_t *engine, int error)
{
    __atomic_store_n(&engine->rx_terminal_error, error, __ATOMIC_RELAXED);
    __atomic_store_n(&engine->tx_terminal_error, error, __ATOMIC_RELAXED);
    __atomic_store_n(&engine->rx_closed, 1, __ATOMIC_RELEASE);
    signal_eventfd(engine->owner_event_fd);
}

static int engine_try_write(tls_engine_t *engine, SSL *ssl,
                            int *pending, uint32_t *ticket,
                            size_t *pinned_length, int *want_events,
                            int *fatal_error)
{
    size_t available = 0;
    uint32_t current_ticket = 0;
    const uint8_t *data = NULL;

    if (*pending) {
        data = spsc_rb_read_span_at(&engine->ssh_to_tls, *ticket,
                                    *pinned_length);
        if (!data) {
            *fatal_error = ESTALE;
            return -1;
        }
    } else {
        data = spsc_rb_read_span(&engine->ssh_to_tls, &available,
                                 &current_ticket);
        if (!data || available == 0) return 0;
        if (available > TLS_ENGINE_IO_CHUNK) available = TLS_ENGINE_IO_CHUNK;
        *ticket = current_ticket;
        *pinned_length = available;
    }

    ssl_prepare_io();
    int rc = SSL_write(ssl, data, (int)*pinned_length);
    int saved_errno = errno;
    if (rc > 0) {
        if (spsc_rb_commit_read(&engine->ssh_to_tls, *ticket,
                                (size_t)rc) != 0) {
            *fatal_error = errno ? errno : EIO;
            return -1;
        }
        *pending = 0;
        *want_events = 0;
        *pinned_length = 0;
        signal_eventfd(engine->owner_event_fd);
        return 1;
    }

    int error = SSL_get_error(ssl, rc);
    if (error == SSL_ERROR_WANT_READ) {
        *pending = 1;
        *want_events = POLLIN;
        return 0;
    }
    if (error == SSL_ERROR_WANT_WRITE) {
        *pending = 1;
        *want_events = POLLOUT;
        return 0;
    }
    if (error == SSL_ERROR_SYSCALL &&
        (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)) {
        *pending = 1;
        *want_events = POLLOUT;
        return 0;
    }

    *fatal_error = ssl_error_to_errno(ssl, rc, saved_errno);
    if (*fatal_error == 0) *fatal_error = EPIPE;
    return -1;
}

static int engine_try_read(tls_engine_t *engine, SSL *ssl,
                           int *pending, uint8_t **pinned_buffer,
                           uint32_t *ticket, size_t *pinned_length,
                           int *want_events, int *fatal_error)
{
    size_t available = 0;
    uint32_t current_ticket = 0;
    uint8_t *buffer = NULL;

    if (*pending) {
        buffer = *pinned_buffer;
    } else {
        buffer = spsc_rb_write_span(&engine->tls_to_ssh, &available,
                                    &current_ticket);
        if (!buffer || available == 0) return 0;
        if (available > TLS_ENGINE_IO_CHUNK) available = TLS_ENGINE_IO_CHUNK;
        *ticket = current_ticket;
        *pinned_length = available;
        *pinned_buffer = buffer;
    }

    ssl_prepare_io();
    int rc = SSL_read(ssl, buffer, (int)*pinned_length);
    int saved_errno = errno;
    if (rc > 0) {
        if (spsc_rb_commit_write(&engine->tls_to_ssh, *ticket,
                                 (size_t)rc) != 0) {
            *fatal_error = errno ? errno : EIO;
            return -1;
        }
        *pending = 0;
        *pinned_buffer = NULL;
        *pinned_length = 0;
        *want_events = 0;
        signal_eventfd(engine->owner_event_fd);
        return 1;
    }

    int error = SSL_get_error(ssl, rc);
    if (error == SSL_ERROR_WANT_READ) {
        /* An idle read WANT_READ does not block a later independent write. */
        *pending = 0;
        *pinned_buffer = NULL;
        *pinned_length = 0;
        *want_events = POLLIN;
        return 0;
    }
    if (error == SSL_ERROR_WANT_WRITE) {
        *pending = 1;
        *want_events = POLLOUT;
        return 0;
    }
    if (error == SSL_ERROR_SYSCALL &&
        (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)) {
        *pending = 0;
        *pinned_buffer = NULL;
        *pinned_length = 0;
        *want_events = POLLIN;
        return 0;
    }
    if (error == SSL_ERROR_ZERO_RETURN) {
        __atomic_store_n(&engine->rx_terminal_error, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&engine->rx_closed, 1, __ATOMIC_RELEASE);
        signal_eventfd(engine->owner_event_fd);
        *pending = 0;
        *pinned_buffer = NULL;
        *pinned_length = 0;
        *want_events = 0;
        return 2;
    }

    *fatal_error = ssl_error_to_errno(ssl, rc, saved_errno);
    if (*fatal_error == 0) *fatal_error = EIO;
    return -1;
}

static int tls_shutdown_bounded(SSL *ssl, int fd, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        ssl_prepare_io();
        int rc = SSL_shutdown(ssl);
        if (rc == 1) return 0;
        if (rc == 0) {
            int waited = wait_socket_until(fd, POLLIN, deadline);
            if (waited <= 0) return waited == 0 ? ETIMEDOUT : errno;
            continue;
        }

        int error = SSL_get_error(ssl, rc);
        short events = error == SSL_ERROR_WANT_READ ? POLLIN :
                       error == SSL_ERROR_WANT_WRITE ? POLLOUT : 0;
        if (!events) return ssl_error_to_errno(error, errno);
        int waited = wait_socket_until(fd, events, deadline);
        if (waited <= 0) return waited == 0 ? ETIMEDOUT : errno;
    }
}

static void *tls_engine_thread(void *opaque)
{
    tls_engine_t *engine = (tls_engine_t *)opaque;
    SSL *ssl = NULL;
    int retryable = 0;
    int start_error = tls_handshake(engine, &ssl, &retryable);
    if (start_error != 0) {
        publish_startup(engine, 0, start_error, retryable, NULL);
        if (engine->socket_fd >= 0) close(engine->socket_fd);
        engine->socket_fd = -1;
        return NULL;
    }

    publish_startup(engine, 1, 0, 0, ssl);

    int write_pending = 0;
    uint32_t write_ticket = 0;
    size_t write_length = 0;
    int write_want = 0;

    int read_pending = 0;
    uint8_t *read_buffer = NULL;
    uint32_t read_ticket = 0;
    size_t read_length = 0;
    int read_want = 0;

    int rx_closed = 0;
    int fatal_error = 0;

    for (;;) {
        int stopping = __atomic_load_n(&engine->stop_requested,
                                       __ATOMIC_ACQUIRE);
        int graceful = __atomic_load_n(&engine->graceful_stop,
                                       __ATOMIC_ACQUIRE);
        int timeout_ms = __atomic_load_n(&engine->stop_timeout_ms,
                                         __ATOMIC_RELAXED);
        if (timeout_ms <= 0) timeout_ms = TLS_ENGINE_DEFAULT_SHUTDOWN_MS;

        if (stopping && !graceful) break;
        if (stopping && graceful && !write_pending && !read_pending &&
            ring_used(&engine->ssh_to_tls) == 0) {
            int shutdown_error = tls_shutdown_bounded(ssl, engine->socket_fd,
                                                       timeout_ms);
            if (shutdown_error != 0)
                __atomic_store_n(&engine->tx_terminal_error, shutdown_error,
                                 __ATOMIC_RELEASE);
            break;
        }

        drain_eventfd(engine->worker_event_fd);

        int did_work = 0;
        if (!read_pending && (write_pending ||
                              ring_used(&engine->ssh_to_tls) > 0)) {
            int rc = engine_try_write(engine, ssl, &write_pending,
                                      &write_ticket, &write_length,
                                      &write_want, &fatal_error);
            if (rc < 0) break;
            if (rc > 0) did_work = 1;
        }

        if (!write_pending && !read_pending && !rx_closed &&
            SSL_pending(ssl) > 0 && ring_free(&engine->tls_to_ssh) > 0) {
            int rc = engine_try_read(engine, ssl, &read_pending,
                                     &read_buffer, &read_ticket, &read_length,
                                     &read_want, &fatal_error);
            if (rc < 0) break;
            if (rc > 0) did_work = 1;
            if (rc == 2) rx_closed = 1;
        }
        if (did_work) continue;

        short socket_events = 0;
        if (write_pending) socket_events |= (short)write_want;
        else if (read_pending) socket_events |= (short)read_want;
        else {
            if (ring_used(&engine->ssh_to_tls) > 0) socket_events |= POLLOUT;
            if (!rx_closed && ring_free(&engine->tls_to_ssh) > 0)
                socket_events |= POLLIN;
        }

        struct pollfd pfds[2] = {
            { .fd = engine->socket_fd, .events = socket_events },
            { .fd = engine->worker_event_fd, .events = POLLIN }
        };
        int pr;
        do {
            pr = poll(pfds, 2, stopping ? 100 : 1000);
        } while (pr < 0 && errno == EINTR);
        if (pr < 0) {
            fatal_error = errno ? errno : EIO;
            break;
        }
        if (pfds[1].revents & POLLIN)
            drain_eventfd(engine->worker_event_fd);

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            if (pfds[0].revents & POLLIN) {
                /* Allow SSL_read to classify close_notify / unexpected EOF. */
            } else {
                int socket_error = 0;
                socklen_t error_length = sizeof(socket_error);
                if (getsockopt(engine->socket_fd, SOL_SOCKET, SO_ERROR,
                               &socket_error, &error_length) < 0)
                    socket_error = errno;
                fatal_error = socket_error ? socket_error : ECONNRESET;
                break;
            }
        }

        if (write_pending && (pfds[0].revents & write_want)) {
            int rc = engine_try_write(engine, ssl, &write_pending,
                                      &write_ticket, &write_length,
                                      &write_want, &fatal_error);
            if (rc < 0) break;
        } else if (!write_pending && !read_pending &&
                   ring_used(&engine->ssh_to_tls) > 0 &&
                   (pfds[0].revents & POLLOUT)) {
            int rc = engine_try_write(engine, ssl, &write_pending,
                                      &write_ticket, &write_length,
                                      &write_want, &fatal_error);
            if (rc < 0) break;
        }

        if (read_pending && (pfds[0].revents & read_want)) {
            int rc = engine_try_read(engine, ssl, &read_pending,
                                     &read_buffer, &read_ticket, &read_length,
                                     &read_want, &fatal_error);
            if (rc < 0) break;
            if (rc == 2) rx_closed = 1;
        } else if (!read_pending && !write_pending && !rx_closed &&
                   ring_free(&engine->tls_to_ssh) > 0 &&
                   (pfds[0].revents & POLLIN)) {
            int rc = engine_try_read(engine, ssl, &read_pending,
                                     &read_buffer, &read_ticket, &read_length,
                                     &read_want, &fatal_error);
            if (rc < 0) break;
            if (rc == 2) rx_closed = 1;
        }
    }

    if (fatal_error) publish_terminal(engine, fatal_error);
    else if (rx_closed)
        __atomic_store_n(&engine->tx_terminal_error, 0, __ATOMIC_RELEASE);
    signal_eventfd(engine->owner_event_fd);
    SSL_free(ssl);
    if (engine->socket_fd >= 0) close(engine->socket_fd);
    engine->socket_fd = -1;
    return NULL;
}

tls_engine_t *tls_engine_create(uint32_t queue_capacity)
{
    tls_engine_t *engine = (tls_engine_t *)calloc(1, sizeof(*engine));
    if (!engine) return NULL;

    engine->worker_event_fd = -1;
    engine->owner_event_fd = -1;
    engine->socket_fd = -1;

    if (spsc_rb_init(&engine->ssh_to_tls, queue_capacity) != 0 ||
        spsc_rb_init(&engine->tls_to_ssh, queue_capacity) != 0) {
        tls_engine_destroy(engine);
        return NULL;
    }

    engine->worker_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    engine->owner_event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (engine->worker_event_fd < 0 || engine->owner_event_fd < 0) {
        tls_engine_destroy(engine);
        return NULL;
    }

    int rc = pthread_mutex_init(&engine->mutex, NULL);
    if (rc != 0) {
        errno = rc;
        tls_engine_destroy(engine);
        return NULL;
    }
    engine->mutex_ready = 1;
    rc = pthread_cond_init(&engine->cond, NULL);
    if (rc != 0) {
        errno = rc;
        tls_engine_destroy(engine);
        return NULL;
    }
    engine->cond_ready = 1;
    return engine;
}

int tls_engine_start(tls_engine_t *engine, SSL_CTX *ctx, int fd,
                     const char *server_name, int verify_peer,
                     int handshake_timeout_ms)
{
    if (!engine || !ctx || fd < 0 || engine->thread_created ||
        engine->startup_done) {
        errno = EINVAL;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    engine->ctx = ctx;
    engine->socket_fd = fd;
    engine->verify_peer = verify_peer != 0;
    engine->handshake_timeout_ms = handshake_timeout_ms > 0
        ? handshake_timeout_ms : TLS_ENGINE_DEFAULT_TIMEOUT_MS;
    if (server_name)
        snprintf(engine->server_name, sizeof(engine->server_name), "%s",
                 server_name);

    int rc = pthread_create(&engine->thread, NULL, tls_engine_thread, engine);
    if (rc != 0) {
        engine->socket_fd = -1; /* ownership did not transfer */
        errno = rc;
        return -1;
    }
    engine->thread_created = 1;
    return 0;
}

int tls_engine_wait_ready(tls_engine_t *engine)
{
    if (!engine || !engine->thread_created) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&engine->mutex);
    while (!engine->startup_done)
        pthread_cond_wait(&engine->cond, &engine->mutex);
    int ok = engine->startup_ok;
    int error = engine->startup_error;
    pthread_mutex_unlock(&engine->mutex);
    if (!ok) {
        errno = error ? error : EIO;
        return -1;
    }
    return 0;
}

int tls_engine_start_error(const tls_engine_t *engine)
{
    if (!engine) return EINVAL;
    return __atomic_load_n(&engine->startup_error, __ATOMIC_ACQUIRE);
}

int tls_engine_start_retryable(const tls_engine_t *engine)
{
    if (!engine) return 0;
    return __atomic_load_n(&engine->startup_retryable, __ATOMIC_ACQUIRE);
}

int tls_engine_copy_negotiated(tls_engine_t *engine,
                               char *version, size_t version_size,
                               char *cipher, size_t cipher_size)
{
    if (!engine || !version || version_size == 0 || !cipher ||
        cipher_size == 0) {
        errno = EINVAL;
        return -1;
    }
    pthread_mutex_lock(&engine->mutex);
    if (!engine->startup_done || !engine->startup_ok) {
        pthread_mutex_unlock(&engine->mutex);
        errno = EAGAIN;
        return -1;
    }
    snprintf(version, version_size, "%s", engine->tls_version);
    snprintf(cipher, cipher_size, "%s", engine->cipher);
    pthread_mutex_unlock(&engine->mutex);
    return 0;
}

ssize_t tls_engine_send(tls_engine_t *engine, const void *data, size_t length)
{
    if (!engine || (!data && length != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (length == 0) return 0;
    if (__atomic_load_n(&engine->tx_terminal_error, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&engine->stop_requested, __ATOMIC_ACQUIRE)) {
        errno = EPIPE;
        return -1;
    }

    size_t copied = 0;
    while (copied < length) {
        size_t available = 0;
        uint32_t ticket = 0;
        uint8_t *span = spsc_rb_write_span(&engine->ssh_to_tls,
                                           &available, &ticket);
        if (!span || available == 0) break;
        size_t amount = length - copied;
        if (amount > available) amount = available;
        memcpy(span, (const uint8_t *)data + copied, amount);
        if (spsc_rb_commit_write(&engine->ssh_to_tls, ticket, amount) != 0)
            return copied ? (ssize_t)copied : -1;
        copied += amount;
    }

    if (copied) signal_eventfd(engine->worker_event_fd);
    return (ssize_t)copied;
}

ssize_t tls_engine_recv(tls_engine_t *engine, void *data, size_t length)
{
    if (!engine || (!data && length != 0)) {
        errno = EINVAL;
        return -1;
    }
    if (length == 0) return 0;

    size_t copied = 0;
    while (copied < length) {
        size_t available = 0;
        uint32_t ticket = 0;
        const uint8_t *span = spsc_rb_read_span(&engine->tls_to_ssh,
                                                &available, &ticket);
        if (!span || available == 0) break;
        size_t amount = length - copied;
        if (amount > available) amount = available;
        memcpy((uint8_t *)data + copied, span, amount);
        if (spsc_rb_commit_read(&engine->tls_to_ssh, ticket, amount) != 0)
            return copied ? (ssize_t)copied : -1;
        copied += amount;
    }

    if (copied) signal_eventfd(engine->worker_event_fd);
    if (copied) return (ssize_t)copied;

    int terminal_error = 0;
    if (tls_engine_rx_terminal(engine, &terminal_error)) {
        if (terminal_error == 0) return 0;
        errno = terminal_error;
        return -1;
    }
    errno = EAGAIN;
    return -1;
}

int tls_engine_notify_fd(const tls_engine_t *engine)
{
    return engine ? engine->owner_event_fd : -1;
}

void tls_engine_drain_notify(tls_engine_t *engine)
{
    if (engine) drain_eventfd(engine->owner_event_fd);
}

int tls_engine_rx_pending(const tls_engine_t *engine)
{
    return engine ? ring_used(&engine->tls_to_ssh) : 0;
}

int tls_engine_tx_pending(const tls_engine_t *engine)
{
    return engine ? ring_used(&engine->ssh_to_tls) : 0;
}

int tls_engine_rx_terminal(const tls_engine_t *engine, int *error_out)
{
    if (!engine) return 1;
    int closed = __atomic_load_n(&engine->rx_closed, __ATOMIC_ACQUIRE);
    int error = __atomic_load_n(&engine->rx_terminal_error, __ATOMIC_ACQUIRE);
    if (error_out) *error_out = error;
    return closed;
}

int tls_engine_tx_terminal(const tls_engine_t *engine, int *error_out)
{
    if (!engine) return 1;
    int error = __atomic_load_n(&engine->tx_terminal_error, __ATOMIC_ACQUIRE);
    if (error_out) *error_out = error;
    return error != 0;
}

void tls_engine_stop(tls_engine_t *engine, int graceful,
                     int shutdown_timeout_ms)
{
    if (!engine || !engine->thread_created || engine->thread_joined) return;
    __atomic_store_n(&engine->graceful_stop, graceful != 0, __ATOMIC_RELEASE);
    __atomic_store_n(&engine->stop_timeout_ms,
                     shutdown_timeout_ms > 0 ? shutdown_timeout_ms
                                             : TLS_ENGINE_DEFAULT_SHUTDOWN_MS,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&engine->stop_requested, 1, __ATOMIC_RELEASE);
    signal_eventfd(engine->worker_event_fd);
}

int tls_engine_join(tls_engine_t *engine)
{
    if (!engine || !engine->thread_created || engine->thread_joined) return 0;
    int rc = pthread_join(engine->thread, NULL);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    engine->thread_joined = 1;
    return 0;
}

void tls_engine_destroy(tls_engine_t *engine)
{
    if (!engine) return;
    if (engine->thread_created && !engine->thread_joined) {
        tls_engine_stop(engine, 0, 1);
        (void)tls_engine_join(engine);
    }
    if (engine->socket_fd >= 0) close(engine->socket_fd);
    if (engine->worker_event_fd >= 0) close(engine->worker_event_fd);
    if (engine->owner_event_fd >= 0) close(engine->owner_event_fd);
    if (engine->cond_ready) pthread_cond_destroy(&engine->cond);
    if (engine->mutex_ready) pthread_mutex_destroy(&engine->mutex);
    spsc_rb_destroy(&engine->ssh_to_tls);
    spsc_rb_destroy(&engine->tls_to_ssh);
    free(engine);
}
