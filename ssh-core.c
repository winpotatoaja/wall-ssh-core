#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh2.h>
#include "libssh2_diag.h"
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "tls_engine.h"
#include "client_event_token.h"
#include "client_lifetime.h"
#include "io_worker_pool.h"
#include "io_worker_completion_tracker.h"

#define DEFAULT_LOG_PATH       "/tmp/etc/passwall-ssh.log"
#define AUTH_FAILED_FILE       "/tmp/etc/passwall-ssh.auth_failed"
#define KEX_FAILED_FILE        "/tmp/etc/passwall-ssh.kex_failed"
#define NEED_RESTART_FILE      "/tmp/etc/passwall-ssh.need_restart"
#define ROTATE_STATE_FILE      "/tmp/etc/passwall-rotate.tmp"
#define SSH_CLIENT_BANNER      "SSH-2.0-OpenSSH_9.6"
#define DEFAULT_UA             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

#define MAX_HTTP_HEADER        16384
#define MAX_HTTP_SKIP_BODY     (16U * 1024U * 1024U)
#define C2S_RELAY_BUF_SIZE     32768
#define S2C_RELAY_BUF_SIZE     262144
#define MAX_EVENTS             128
#define SSH_CORE_IO_QUEUE_CAPACITY 64U
#define DEFAULT_MAX_CLIENTS    64
#define MAX_CLIENTS_LIMIT      256
#define DEFAULT_IDLE_TIMEOUT   600
#define HANDSHAKE_TIMEOUT_MS   15000
#define TCP_CONNECT_FAMILY_TIMEOUT_MS 4000
#define TCP_CONNECT_MAX_ADDRS 32
#define TLS_CONNECT_MAX_ADDR_ATTEMPTS 4

static __thread int (*g_tcp_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = getaddrinfo;
static __thread int g_tcp_dial_debug = 1;
#define SOCKS_HS_TIMEOUT_SEC   15
#define SSH_OPEN_SOFT_TO_MS    15000
#define SSH_OPEN_HARD_TO_MS    30000
#define SSH_CHANNEL_CLEANUP_TIMEOUT_MS 10000
#define SHUTDOWN_IO_TIMEOUT_MS 2500
#define UPSTREAM_DRAIN_TIMEOUT_MS 15000
#define UPSTREAM_DRAIN_POLL_MS 25
#ifndef DELAY_WAIT_POLL_MAX_MS
#define DELAY_WAIT_POLL_MAX_MS 60000
#endif

static volatile sig_atomic_t g_stop = 0;
/* Shared stop state: atomic accesses are safe across workers and signal delivery. */
static inline int stop_requested(void) {
    return __atomic_load_n(&g_stop, __ATOMIC_RELAXED) != 0;
}
static inline void request_stop(void) {
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELAXED);
}
#define MAX_WORKERS 4

/*
 * Prefer the CPUs actually allowed to this process (cpuset/affinity). This
 * avoids oversubscribing a device when the service is pinned to fewer CPUs.
 * Older/minimal libc builds may not expose affinity helpers, so sysconf is
 * the portable fallback.
 */
static long detect_available_cpu_count(void) {
#if defined(__linux__) && defined(CPU_COUNT)
    cpu_set_t allowed_cpus;
    CPU_ZERO(&allowed_cpus);
    if (sched_getaffinity(0, sizeof(allowed_cpus), &allowed_cpus) == 0) {
        int allowed_count = CPU_COUNT(&allowed_cpus);
        if (allowed_count > 0) return (long)allowed_count;
    }
#endif

    long online_count = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef _SC_NPROCESSORS_CONF
    if (online_count < 1) online_count = sysconf(_SC_NPROCESSORS_CONF);
#endif
    return online_count > 0 ? online_count : 1;
}

/* CPU count selects auxiliary socket-I/O threads only. */
static int ssh_session_count_for_cpu_count(long cpu_count) {
    (void)cpu_count;
    return 1;
}

static uint32_t io_worker_count_for_cpu_count(long cpu_count) {
    if (cpu_count < 1L) return 1U;
    if (cpu_count > (long)IO_WORKER_POOL_MAX_WORKERS)
        return IO_WORKER_POOL_MAX_WORKERS;
    return (uint32_t)cpu_count;
}

static long g_detected_cpu_count = 1;
static uint32_t g_io_worker_count = 1U;
static int g_worker_count_auto = 1;
static __thread int g_worker_id = 0;
static __thread int g_worker_count = 1;
static __thread uint64_t g_accepted_total = 0;
/* Payload rotation state is shared across workers and must be serialized. */
static pthread_mutex_t g_rotate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_marker_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Shared admission limit across the independent per-thread client lists. */
static int g_total_client_count = 0;
static int reserve_client_slot(int limit) {
    int current = __atomic_load_n(&g_total_client_count, __ATOMIC_RELAXED);
    while (current < limit) {
        if (__atomic_compare_exchange_n(&g_total_client_count, &current, current + 1,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return 1;
    }
    return 0;
}
static void release_client_slot(void) {
    int current = __atomic_load_n(&g_total_client_count, __ATOMIC_RELAXED);
    while (current > 0) {
        if (__atomic_compare_exchange_n(&g_total_client_count, &current, current - 1,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return;
    }
}
static __thread const char *g_log_path = DEFAULT_LOG_PATH;
/* Verbose per-channel flow-control diagnostics are opt-in. */
static __thread int g_log_backpressure = 0;
/* Set when a pending operation makes further libssh2 I/O unsafe. */
static __thread int g_skip_libssh2_cleanup = 0;
static __thread const char *g_kbd_password = "";

/* Sentinel tag untuk O(1) epoll dispatch */
static __thread int g_listen_tag = 0;
static __thread int g_upstream_tag = 0;
static __thread int g_worker_completion_tag = 0;
static __thread uint64_t g_next_io_task_id = 1U;
static __thread io_worker_pool_t *g_io_pool = NULL;
static __thread io_worker_completion_tracker_t *g_io_tracker = NULL;

typedef struct {
    uint8_t *data;
    size_t   cap;
    size_t   head;
    size_t   tail;
    size_t   used;
    uint64_t generation;
} rb_t;

typedef struct {
    int      fd;
    tls_engine_t *tls;
    const char *log_path;
    int      log_worker_id;
    int      log_worker_count;
    uint64_t rx_seq;
    size_t   skip_ssh_banner_bytes;
    int      expect_connect_resp;
    int      tunnel_established;
    int      last_http_code;
    char     last_status[128];
    uint8_t  pre_buf[32768];
    size_t   pre_off;
    size_t   pre_len;
    size_t   http_skip_remaining;
    int      http_pending_tunnel;
    int      http_close_delimited;
    int      allow_http_200_tunnel;
    int      http_in_chunked;
    int      http_chunk_state; /* 0=size, 1=data, 2=delim, 3=trailers */
    size_t   http_chunk_rem;
    size_t   http_chunk_total;
    long long last_activity_ms;
    int      hup_seen;
    int      rx_terminal;
    int      rx_terminal_rc; /* stable callback result: 0 EOF, negative errno */
    int      rx_flush_eagain; /* let channel reads drain libssh2 packets after RX terminal */
    int      tx_terminal;
    int      upstream_epoll_detached;
    long long drain_deadline_ms;
} upstream_ctx_t;

/* Used by the early TLS delay/drain helper and defined with relay state helpers. */
static int tls_want_requires_serial_retry(const upstream_ctx_t *u);
static int upstream_client_write_allowed(const upstream_ctx_t *u);

typedef enum {
    ST_SOCKS_GREETING = 0,
    ST_SOCKS_REQUEST,
    ST_SSH_OPENING,
    ST_RELAY,
    ST_CLOSING
} client_state_t;

typedef enum {
    PENDING_NONE = 0,
    PENDING_OPEN,
    PENDING_WRITE,
    PENDING_SEND_EOF,
    PENDING_READ,
    PENDING_FREE,
    PENDING_KEEPALIVE
} pending_op_t;

typedef struct client_conn {
    uint64_t       client_id;
    uint64_t       generation;
    client_lifetime_t lifetime;
    uint64_t       c2s_worker_task_id;
    int            c2s_worker_inflight;
    int            fd;
    int            fd_close_pending;
    int            in_epoll;
    client_state_t state;
    uint32_t       epoll_events;
    long long      accepted_at_ms;
    long long      open_started_ms;
    long long      ctrl_close_deadline_ms;
    long long      cleanup_deadline_ms;
    long long      last_activity_ms;

    uint8_t  req_buf[512];
    size_t   req_len;
    uint8_t  ctrl_buf[16];
    size_t   ctrl_off;
    size_t   ctrl_len;
    int      close_after_ctrl;

    uint8_t  early_buf[512];
    size_t   early_len;

    char     target_host[256];
    uint16_t target_port;

    LIBSSH2_CHANNEL *channel;
    int              abort_on_open;
    int              abort_on_pending;
    int              need_send_eof;
    int              client_eof;
    int              client_dead;
    int              client_reset;
    int              hup_pending;
    int              rdhup_pending;
    int              ssh_eof;
    int              upstream_read_drained;
    int              upstream_read_stalled;

    /* Pin argumen (ptr, len) per-channel saat EAGAIN */
    int            write_pending;
    size_t         write_pending_head;
    uint64_t       write_pending_generation;
    size_t         write_pending_len;
    int            write_waiting_window;
    uint64_t       write_wait_rx_seq;
    int            write_window_log_active;
    int            write_window_log_seen;
    int            write_window_eagain_logged;
    int            write_window_final_logged;
    int            c2s_post_eof_window_logged;
    size_t         c2s_peak_used;
    size_t         s2c_peak_used;
    int            s2c_saturated;
    int            s2c_final_logged;

    rb_t c2s;
    rb_t s2c;

    struct client_conn *prev;
    struct client_conn *next;
    struct client_conn *retired_next;
} client_conn_t;

static __thread client_conn_t *g_clients = NULL;
/* Clients detached from epoll remain here while worker tasks hold references. */
static __thread client_conn_t *g_retired_clients = NULL;
static uint64_t g_next_client_id = 1;

/* IDs are process-wide, monotonic, and never recycled. Reserve the top bit
 * for client epoll cookies; exhaustion fails closed rather than wrapping. */
static uint64_t allocate_client_id(void) {
    uint64_t current = __atomic_load_n(&g_next_client_id, __ATOMIC_RELAXED);
    for (;;) {
        if (current == 0 || current > CLIENT_EVENT_ID_MASK) return 0;
        uint64_t next = current + UINT64_C(1);
        if (__atomic_compare_exchange_n(&g_next_client_id, &current, next, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return current;
    }
}

static client_conn_t *find_client_by_id(uint64_t client_id) {
    if (client_id == 0) return NULL;
    for (client_conn_t *c = g_clients; c; c = c->next) {
        if (c->client_id == client_id) return c;
    }
    return NULL;
}
static client_conn_t *find_client_any_by_id(uint64_t client_id) {
    client_conn_t *c = find_client_by_id(client_id);
    if (c) return c;
    for (c = g_retired_clients; c; c = c->retired_next)
        if (c->client_id == client_id) return c;
    return NULL;
}
static __thread int            g_client_count = 0;
static __thread client_conn_t *g_opening_client = NULL;
static __thread client_conn_t *g_pending_client = NULL;
static __thread pending_op_t   g_pending_op = PENDING_NONE;

typedef struct {
    uint64_t epoll_calls, epoll_wait_ms, epoll_wait_max_ms;
    uint64_t epoll_wakeups, epoll_timeouts;
    uint64_t tls_rx_calls, tls_rx_bytes, tls_rx_eagain;
    uint64_t ssh_rx_bytes, ssh_rx_eagain;
    uint64_t s2c_read_calls, s2c_read_bytes, s2c_read_eagain;
    uint64_t s2c_read_ns, ssh_recv_cb_ns, ssh_recv_s2c_cb_ns;
    uint64_t ssh_recv_syscall_ns, socks_tx_ns;
    uint64_t ssh_recv_cb_calls, ssh_recv_s2c_cb_calls;
    uint64_t ssh_recv_syscall_calls, socks_tx_flush_calls;
    uint64_t socks_tx_calls, socks_tx_bytes, socks_tx_eagain, socks_tx_partial;
    uint64_t c2s_rx_bytes, c2s_ssh_write_bytes;
    uint64_t c2s_post_eof_rx_bytes, c2s_post_eof_ssh_write_bytes;
    uint64_t c2s_post_eof_window_blocked;
    uint64_t window_waiter_retry_count, window_waiter_upstream_events;
    uint64_t epoll_ctl_add_fail, epoll_ctl_mod_fail;
    int epoll_ctl_last_errno;
    uint64_t s2c_full, libssh2_eagain, pending_blocks;
} perf_stats_t;

static __thread perf_stats_t g_perf_stats;
static __thread unsigned int g_perf_s2c_read_depth = 0;
static __thread int g_log_perf = 0;
static __thread long long g_perf_window_start_ms = 0;

static void clear_pending_operation(void) {
    g_pending_client = NULL;
    g_pending_op = PENDING_NONE;
}
static void set_pending_operation(client_conn_t *c, pending_op_t op) {
    g_pending_client = c;
    g_pending_op = op;
}

static int parse_socks_listen_addr(const char *text,
                                     struct sockaddr_storage *out,
                                     socklen_t *out_len,
                                     char *host_out, size_t host_out_sz,
                                     int *port_out, int *loopback_out) {
    if (!text || !*text || !out || !out_len || !host_out ||
        host_out_sz == 0 || !port_out || !loopback_out) return -1;
    const char *spec = text;
    const char *port_text = NULL;
    size_t host_len = 0;
    int bracketed = (spec[0] == '[');
    if (bracketed) {
        const char *close_bracket = strchr(spec, ']');
        if (!close_bracket) return -1;
        host_len = (size_t)(close_bracket - spec + 1);
        if (close_bracket[1] == ':') port_text = close_bracket + 2;
        else if (close_bracket[1] != '\0') return -1;
    } else {
        const char *colon = strrchr(spec, ':');
        if (colon) {
            if (memchr(spec, ':', (size_t)(colon - spec))) return -1;
            host_len = (size_t)(colon - spec);
            port_text = colon + 1;
        } else host_len = strlen(spec);
    }
    long port = 1080;
    if (port_text) {
        char *end = NULL;
        errno = 0;
        port = strtol(port_text, &end, 10);
        if (errno || end == port_text || *end != '\0' || port < 1 || port > 65535)
            return -1;
    }
    const char *host_start = spec + (bracketed ? 1 : 0);
    if (bracketed) host_len -= 2;
    if (host_len == 0 || host_len >= host_out_sz || host_len >= INET6_ADDRSTRLEN + 1)
        return -1;
    char host[INET6_ADDRSTRLEN + 1];
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';
    memset(out, 0, sizeof(*out));
    struct sockaddr_in a4;
    memset(&a4, 0, sizeof(a4));
    if (!bracketed && inet_pton(AF_INET, host, &a4.sin_addr) == 1) {
        a4.sin_family = AF_INET;
        a4.sin_port = htons((uint16_t)port);
        memcpy(out, &a4, sizeof(a4));
        *out_len = sizeof(a4);
        *loopback_out = (ntohl(a4.sin_addr.s_addr) >> 24) == 127U;
    } else {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        if (!bracketed || inet_pton(AF_INET6, host, &a6.sin6_addr) != 1) return -1;
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons((uint16_t)port);
        memcpy(out, &a6, sizeof(a6));
        *out_len = sizeof(a6);
        *loopback_out = IN6_IS_ADDR_LOOPBACK(&a6.sin6_addr) ? 1 : 0;
    }
    snprintf(host_out, host_out_sz, "%s", host);
    *port_out = (int)port;
    return 0;
}

static int relay_idle_timeout_due(const client_conn_t *c, int timeout_sec,
                                  long long now_msec) {
    if (!c || c->state != ST_RELAY || c->abort_on_pending ||
        timeout_sec <= 0 || c->last_activity_ms <= 0) {
        return 0;
    }
    return now_msec - c->last_activity_ms >= (long long)timeout_sec * 1000LL;
}

/* A reset peer has no remaining consumer or useful C2S stream. Close promptly.
 * A graceful EOF is different: queued C2S bytes must reach SSH before the
 * channel can be released, even when the local descriptor has been detached. */
static int client_dead_ready_to_close(const client_conn_t *c) {
    return c && c->client_dead && c->client_reset && !c->hup_pending;
}

static int client_eof_ready_to_close(const client_conn_t *c) {
    return c && c->client_dead && !c->client_reset && c->client_eof &&
           !c->hup_pending && c->c2s.used == 0 && !c->write_pending &&
           !c->need_send_eof;
}

static int client_cleanup_timeout_due(const client_conn_t *c, long long now_msec) {
    if (!c || c->cleanup_deadline_ms <= 0 ||
        (!c->abort_on_pending && c->state != ST_CLOSING)) return 0;
    return now_msec >= c->cleanup_deadline_ms;
}

/* Active writes retain the caller's buffer until the same channel_write call
 * completes. A zero-window wait has not created a packet and is safe to drop.
 * A channel in ST_CLOSING may still have a channel_free retry to finish. */
static int has_pending_libssh2_work_for_shutdown(void) {
    if (g_pending_op != PENDING_NONE || g_opening_client != NULL) return 1;
    for (const client_conn_t *c = g_clients; c; c = c->next) {
        if ((c->write_pending && !c->write_waiting_window) ||
            (c->state == ST_CLOSING && c->channel != NULL)) return 1;
    }
    return 0;
}

/* ============================================================
 * RING BUFFER (ZERO MEMMOVE, LAZY ALLOCATION)
 * ============================================================ */
static __thread uint64_t g_rb_generation = 1;
static uint64_t rb_next_generation(void) {
    g_rb_generation++;
    if (g_rb_generation == 0) g_rb_generation++;
    return g_rb_generation;
}
static int rb_state_valid(const rb_t *r) {
    if (!r || !r->data || r->cap == 0) return 0;
    if (r->head >= r->cap || r->tail >= r->cap || r->used > r->cap) return 0;
    size_t until_wrap = r->cap - r->head;
    size_t expected_tail = r->used < until_wrap ? r->head + r->used : r->used - until_wrap;
    if (expected_tail == r->cap) expected_tail = 0;
    return expected_tail == r->tail;
}
static int rb_init(rb_t *r, size_t cap) {
    if (!r || cap == 0) return -1;
    if (r->data) return rb_state_valid(r) ? 0 : -1;
    uint8_t *data = malloc(cap);
    if (!data) return -1;
    r->data = data;
    r->cap = cap;
    r->head = r->tail = r->used = 0;
    r->generation = rb_next_generation();
    return 0;
}
static void rb_free(rb_t *r) {
    if (!r) return;
    free(r->data);
    r->data = NULL;
    r->cap = r->head = r->tail = r->used = 0;
    r->generation = rb_next_generation();
}
static int rb_clear(rb_t *r) {
    if (!rb_state_valid(r)) return -1;
    r->head = 0;
    r->tail = 0;
    r->used = 0;
    r->generation = rb_next_generation();
    return rb_state_valid(r) ? 0 : -1;
}
static inline size_t rb_free_space(const rb_t *r) {
    return rb_state_valid(r) ? r->cap - r->used : 0;
}
static uint8_t *rb_write_slice(rb_t *r, size_t *avail) {
    if (!avail) return NULL;
    *avail = 0;
    if (!rb_state_valid(r) || r->used == r->cap) return NULL;
    *avail = r->tail >= r->head ? r->cap - r->tail : r->head - r->tail;
    return *avail ? r->data + r->tail : NULL;
}
static const uint8_t *rb_read_slice(const rb_t *r, size_t *avail) {
    if (!avail) return NULL;
    *avail = 0;
    if (!rb_state_valid(r) || r->used == 0) return NULL;
    *avail = r->head < r->tail ? r->tail - r->head : r->cap - r->head;
    return *avail ? r->data + r->head : NULL;
}
static const uint8_t *rb_read_slice_pinned(const rb_t *r, size_t head,
                                           uint64_t generation, size_t len) {
    size_t avail = 0;
    if (!rb_state_valid(r) || r->generation != generation || r->head != head || len == 0)
        return NULL;
    const uint8_t *ptr = rb_read_slice(r, &avail);
    return ptr && len <= avail ? ptr : NULL;
}
static int rb_commit_write(rb_t *r, size_t n) {
    if (!rb_state_valid(r) || n > r->cap - r->used) return -1;
    size_t contiguous = r->tail >= r->head ? r->cap - r->tail : r->head - r->tail;
    if (n > contiguous) return -1;
    r->tail = (r->tail + n) % r->cap;
    r->used += n;
    return rb_state_valid(r) ? 0 : -1;
}
static int rb_commit_read(rb_t *r, size_t n, int keep_pos) {
    if (!rb_state_valid(r) || n > r->used) return -1;
    size_t contiguous = r->head < r->tail ? r->tail - r->head : r->cap - r->head;
    if (n > contiguous) return -1;
    r->head = (r->head + n) % r->cap;
    r->used -= n;
    if (r->used == 0 && !keep_pos) r->head = r->tail = 0;
    return rb_state_valid(r) ? 0 : -1;
}
static int rb_push(rb_t *r, const uint8_t *src, size_t len) {
    if (len == 0) return 0;
    if (!src || !rb_state_valid(r) || rb_free_space(r) < len) return -1;
    size_t left = len;
    const uint8_t *p = src;
    while (left > 0) {
        size_t avail = 0;
        uint8_t *dst = rb_write_slice(r, &avail);
        if (!dst || avail == 0) return -1;
        size_t take = left < avail ? left : avail;
        memcpy(dst, p, take);
        if (rb_commit_write(r, take) < 0) return -1;
        p += take;
        left -= take;
    }
    return 0;
}

/* ============================================================
 * LOGGER & MARKERS
 * ============================================================ */
static void log_raw(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    char line[2200];
    if (g_worker_count > 1)
        snprintf(line, sizeof(line), "[worker %d/%d] %s",
                 g_worker_id + 1, g_worker_count, buf);
    else
        snprintf(line, sizeof(line), "%s", buf);
    pthread_mutex_lock(&g_log_mutex);
    if (!g_log_path || strcmp(g_log_path, "-") == 0) {
        printf("%s\n", line);
        fflush(stdout);
        pthread_mutex_unlock(&g_log_mutex);
        return;
    }
    FILE *f = fopen(g_log_path, "a");
    if (f) {
        fprintf(f, "%s\n", line);
        fclose(f);
    }
    pthread_mutex_unlock(&g_log_mutex);
}

static void fmt_now(char *out, size_t sz) {
    time_t t = time(NULL);
    struct tm tm_now;
    localtime_r(&t, &tm_now);
    strftime(out, sz, "%Y-%m-%d %H:%M:%S", &tm_now);
}

static void log_blue(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<span color=\"#3C86AB\">[%s] %s</span>", ts, msg);
}

static void log_yellow(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<font color=\"#FFFF00\">[%s] %s</font>", ts, msg);
}

static void log_red(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<font color=\"#FF0000\">[%s] %s</font>", ts, msg);
}

static void note_c2s_buffer_peak(client_conn_t *c) {
    if (!g_log_backpressure) return;
    if (c && c->c2s.used > c->c2s_peak_used)
        c->c2s_peak_used = c->c2s.used;
}

static void note_s2c_buffer_peak(client_conn_t *c) {
    if (!g_log_backpressure || !c) return;
    if (c->s2c.used > c->s2c_peak_used)
        c->s2c_peak_used = c->s2c.used;
    if (!c->s2c_saturated && c->s2c.cap > 0 && c->s2c.used == c->s2c.cap) {
        c->s2c_saturated = 1;
        log_yellow("SSH channel s2c buffer full; local client is applying backpressure (%s:%u; queued=%zu/%zu)",
                   c->target_host, (unsigned)c->target_port, c->s2c.used, c->s2c.cap);
    }
}

static void log_s2c_buffer_final(client_conn_t *c) {
    if (!g_log_backpressure || !c || !c->s2c_saturated || c->s2c_final_logged) return;
    note_s2c_buffer_peak(c);
    if (c->s2c.used == 0) {
        log_blue("SSH channel s2c buffer drained after client resumed reading (%s:%u; queued=0/%zu; peak=%zu/%zu)",
                 c->target_host, (unsigned)c->target_port,
                 c->s2c.cap, c->s2c_peak_used, c->s2c.cap);
    } else {
        log_yellow("SSH channel s2c buffer not drained at close (%s:%u; queued=%zu/%zu; peak=%zu/%zu)",
                   c->target_host, (unsigned)c->target_port,
                   c->s2c.used, c->s2c.cap, c->s2c_peak_used, c->s2c.cap);
    }
    c->s2c_final_logged = 1;
}

/* Keep diagnostic state separate from write_waiting_window, which is reset
 * whenever inbound SSH traffic allows the relay loop to retry a blocked write. */
static void note_channel_window_blocked(client_conn_t *c, int eagain_zero) {
    if (!g_log_backpressure || !c) return;
    if (eagain_zero && !c->write_window_eagain_logged) {
        c->write_window_eagain_logged = 1;
        if (c->write_window_log_active) {
            log_yellow("SSH channel zero-window confirmed by EAGAIN (write_window=0) (%s:%u)",
                       c->target_host, (unsigned)c->target_port);
        }
    }
    if (c->write_window_log_active) return;
    c->write_window_log_active = 1;
    c->write_window_log_seen = 1;
    if (eagain_zero) {
        if (c->ssh_eof) {
            log_yellow("SSH C2S window=0 after remote EOF; waiting for WINDOW_ADJUST (%s:%u; c2s_pending=%zu; write_window=%lu)",
                       c->target_host, (unsigned)c->target_port, c->c2s.used,
                       c->channel ? libssh2_channel_window_write_ex(c->channel, NULL) : 0UL);
        } else {
            log_yellow("SSH channel window penuh (EAGAIN; write_window=0); menunggu window-adjust (%s:%u)",
                       c->target_host, (unsigned)c->target_port);
        }
    } else {
        log_yellow("SSH channel window penuh; menunggu window-adjust (%s:%u)",
                   c->target_host, (unsigned)c->target_port);
    }
}

static void note_channel_window_recovered(client_conn_t *c) {
    if (!g_log_backpressure || !c || !c->write_window_log_active) return;
    if (c->ssh_eof) {
        log_blue("SSH C2S window recovered after remote EOF; write resumed (%s:%u; c2s_pending=%zu/%zu)",
                 c->target_host, (unsigned)c->target_port, c->c2s.used, c->c2s.cap);
    } else {
        log_blue("SSH channel window recovered; write resumed (%s:%u; c2s_pending=%zu/%zu)",
                 c->target_host, (unsigned)c->target_port, c->c2s.used, c->c2s.cap);
    }
    c->write_window_log_active = 0;
}

static void log_channel_buffer_final(client_conn_t *c) {
    if (!g_log_backpressure || !c || !c->write_window_log_seen || c->write_window_final_logged) return;
    note_c2s_buffer_peak(c);
    if (!c->write_window_log_active && c->c2s.used == 0) {
        log_blue("SSH channel buffer drained after window recovery (%s:%u; queued=0/%zu; peak=%zu/%zu)",
                 c->target_host, (unsigned)c->target_port,
                 c->c2s.cap, c->c2s_peak_used, c->c2s.cap);
    } else {
        log_yellow("SSH channel buffer not drained at close (%s:%u; queued=%zu/%zu; peak=%zu/%zu; window_blocked=%d)",
                   c->target_host, (unsigned)c->target_port,
                   c->c2s.used, c->c2s.cap, c->c2s_peak_used, c->c2s.cap,
                   c->write_window_log_active);
    }
    c->write_window_final_logged = 1;
}

static void write_marker(const char *path, const char *msg) {
    pthread_mutex_lock(&g_marker_mutex);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", msg ? msg : "");
        fclose(f);
    }
    pthread_mutex_unlock(&g_marker_mutex);
}

/* ============================================================
 * ENV, STRICT PARSING & PAYLOAD TRANSLATION
 * ============================================================ */
typedef struct {
    char transport[16];
    char host[256];
    char host_port[16];
    char username[128];
    char password[256];
    char proxy[256];
    char proxy_port[16];
    char sni[256];
    int  delay_ms;
    int  fix_crlf;
    char socks_addr[128];
    int  keepalive_sec;
    int  verify_tls;
    int  tls_diag;
    int  allow_remote_socks;
    int  allow_http_200_tunnel;
    int  idle_timeout_sec;
    char hostkey_fp[128]; /* Opsional: SHA256:<base64> atau 64-hex untuk pin host key */
    int  max_clients;
    int  log_backpressure;
    int  log_perf;
} app_cfg_t;

static void trim_ws(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static int parse_int_range(const char *s, int min_val, int max_val, int *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    long value = strtol(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0' ||
        value < min_val || value > max_val) return -1;
    *out = (int)value;
    return 0;
}

static int parse_strict_dec_size(const char *s, size_t *out, size_t max_val) {
    if (!s || !isdigit((unsigned char)s[0])) return -1;
    size_t val = 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return -1;
        size_t d = (size_t)(*p - '0');
        if (d > max_val || val > (max_val - d) / 10U) return -1;
        val = val * 10U + d;
    }
    *out = val;
    return 0;
}

static int parse_strict_hex_size(const char *s, size_t *out, size_t max_val) {
    if (!s || !isxdigit((unsigned char)s[0]) || !out) return -1;
    size_t val = 0;
    for (const char *p = s; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (!isxdigit(ch)) return -1;
        size_t d;
        if (ch >= '0' && ch <= '9') d = (size_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') d = (size_t)(ch - 'a' + 10);
        else d = (size_t)(ch - 'A' + 10);
        if (d > max_val || val > (max_val - d) / 16U) return -1;
        val = val * 16U + d;
    }
    *out = val;
    return 0;
}

static int load_env(const char *path, app_cfg_t *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) { log_red("Gagal membuka env file: %s", path); return -1; }
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        trim_ws(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        trim_ws(k); trim_ws(v);
        size_t vlen = strlen(v);
        if (vlen >= 2 && ((v[0] == '\'' && v[vlen-1] == '\'') ||
                          (v[0] == '"' && v[vlen-1] == '"'))) { v[vlen-1] = '\0'; v++; }
        int n = 0;
        if (!strcmp(k,"TRANSPORT")) snprintf(cfg->transport,sizeof(cfg->transport),"%s",v);
        else if (!strcmp(k,"HOST")) snprintf(cfg->host,sizeof(cfg->host),"%s",v);
        else if (!strcmp(k,"HOST_PORT")) snprintf(cfg->host_port,sizeof(cfg->host_port),"%s",v);
        else if (!strcmp(k,"USERNAME")) {
            if (strlen(v) >= sizeof(cfg->username)) {
                log_red("USERNAME melebihi batas %zu byte; nilai ditolak tanpa dipotong",
                        sizeof(cfg->username) - 1U);
                fclose(f);
                return -1;
            }
            snprintf(cfg->username,sizeof(cfg->username),"%s",v);
        } else if (!strcmp(k,"PASSWORD")) {
            if (strlen(v) >= sizeof(cfg->password)) {
                log_red("PASSWORD melebihi batas %zu byte; nilai ditolak tanpa dipotong",
                        sizeof(cfg->password) - 1U);
                fclose(f);
                return -1;
            }
            snprintf(cfg->password,sizeof(cfg->password),"%s",v);
        }
        else if (!strcmp(k,"PROXY")) snprintf(cfg->proxy,sizeof(cfg->proxy),"%s",v);
        else if (!strcmp(k,"PROXY_PORT")) snprintf(cfg->proxy_port,sizeof(cfg->proxy_port),"%s",v);
        else if (!strcmp(k,"SNI")) snprintf(cfg->sni,sizeof(cfg->sni),"%s",v);
        else if (!strcmp(k,"SOCKS_ADDR")) snprintf(cfg->socks_addr,sizeof(cfg->socks_addr),"%s",v);
        else if (!strcmp(k,"HOSTKEY")) snprintf(cfg->hostkey_fp,sizeof(cfg->hostkey_fp),"%s",v);
        else if (!strcmp(k,"DELAY")) {
            if(parse_int_range(v,0,600000,&n)==0) cfg->delay_ms=n; else log_yellow("DELAY tidak valid; diabaikan");
        } else if (!strcmp(k,"KEEPALIVE")) {
            if(parse_int_range(v,0,3600,&n)==0) cfg->keepalive_sec=n; else log_yellow("KEEPALIVE tidak valid; diabaikan");
        } else if (!strcmp(k,"FIX_CRLF")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->fix_crlf=n; else log_yellow("FIX_CRLF harus 0 atau 1");
        } else if (!strcmp(k,"VERIFY_TLS")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->verify_tls=n; else log_yellow("VERIFY_TLS harus 0 atau 1");
        } else if (!strcmp(k,"TLS_DIAG")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->tls_diag=n;
            else log_yellow("TLS_DIAG harus 0 atau 1; diagnostik pesan TLS dinonaktifkan");
        } else if (!strcmp(k,"ALLOW_REMOTE_SOCKS")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->allow_remote_socks=n; else log_yellow("ALLOW_REMOTE_SOCKS harus 0 atau 1");
        } else if (!strcmp(k,"HTTP_200_TUNNEL")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->allow_http_200_tunnel=n; else log_yellow("HTTP_200_TUNNEL harus 0 atau 1");
        } else if (!strcmp(k,"IDLE_TIMEOUT")) {
            if(parse_int_range(v,0,86400,&n)==0) cfg->idle_timeout_sec=n; else log_yellow("IDLE_TIMEOUT harus 0..86400");
        } else if (!strcmp(k,"MAX_CLIENTS")) {
            if(parse_int_range(v,1,MAX_CLIENTS_LIMIT,&n)==0) cfg->max_clients=n;
            else log_yellow("MAX_CLIENTS harus 1..%d",MAX_CLIENTS_LIMIT);
        } else if (!strcmp(k,"LOG_BACKPRESSURE")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->log_backpressure=n;
            else log_yellow("LOG_BACKPRESSURE harus 0 atau 1; diagnostik dinonaktifkan");
        } else if (!strcmp(k,"LOG_PERF")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->log_perf=n;
            else log_yellow("LOG_PERF harus 0 atau 1; diagnostik performa dinonaktifkan");
        }
    }
    fclose(f);
    return 0;
}

static char *read_entire_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    int    failed;
} sbuf_t;

static int sbuf_append(sbuf_t *sb, const char *s, size_t n) {
    if (!sb || (!s && n != 0U)) {
        errno = EINVAL;
        return -1;
    }
    if (sb->failed) {
        errno = ENOMEM;
        return -1;
    }
    if (n == 0U) return 0;
    if (n > SIZE_MAX - sb->len - 1U) {
        sb->failed = 1;
        errno = EOVERFLOW;
        return -1;
    }
    size_t needed = sb->len + n + 1U;
    if (needed > sb->cap) {
        size_t ncap = sb->cap ? sb->cap : 4096U;
        while (ncap < needed) {
            if (ncap > SIZE_MAX / 2U) {
                ncap = needed;
                break;
            }
            ncap *= 2U;
        }
        char *p = realloc(sb->data, ncap);
        if (!p) {
            sb->failed = 1;
            errno = ENOMEM;
            return -1;
        }
        sb->data = p;
        sb->cap = ncap;
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return 0;
}

static char *replace_all_str(const char *src, const char *find, const char *repl) {
    size_t flen = strlen(find);
    size_t rlen = strlen(repl);
    sbuf_t sb = {0};
    const char *p = src;
    while (*p) {
        const char *hit = strstr(p, find);
        if (!hit) {
            sbuf_append(&sb, p, strlen(p));
            break;
        }
        sbuf_append(&sb, p, (size_t)(hit - p));
        sbuf_append(&sb, repl, rlen);
        p = hit + flen;
    }
    if (sb.failed) {
        free(sb.data);
        return NULL;
    }
    if (!sb.data) sb.data = strdup("");
    return sb.data;
}

static char *unescape_backslashes(const char *src) {
    sbuf_t sb = {0};
    for (const char *p = src; *p; p++) {
        if (p[0] == '\\' && p[1] != '\0') {
            if (p[1] == '\\') { sbuf_append(&sb, "\\", 1); p++; continue; }
            if (p[1] == 'r')  { sbuf_append(&sb, "\r", 1); p++; continue; }
            if (p[1] == 'n')  { sbuf_append(&sb, "\n", 1); p++; continue; }
        }
        sbuf_append(&sb, p, 1);
    }
    if (!sb.data) sb.data = strdup("");
    return sb.data;
}

static int gen_ws_key(char out[32]) {
    uint8_t rnd[16];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) return -1;
    if (EVP_EncodeBlock((unsigned char *)out, rnd, 16) != 24) return -1;
    return 0;
}
static int rand_idx(int max) {
    if (max <= 1) return 0;
    uint32_t v = 0;
    if (RAND_bytes((unsigned char *)&v, sizeof(v)) != 1) return -1;
    return (int)(v % (uint32_t)max);
}

static char *translate_payload(const char *raw, const app_cfg_t *cfg, int is_tls, int *embedded_banner_out) {
    *embedded_banner_out = 0;
    if (!raw || !*raw) return strdup("");

    char *cur = NULL;
    if (cfg->fix_crlf) {
        char *tmp = replace_all_str(raw, "\\r\\n", "\\n");
        if (!tmp) return NULL;
        cur = replace_all_str(tmp, "\\n", "\\r\\n");
        free(tmp);
    } else {
        cur = strdup(raw);
    }
    if (!cur) return NULL;

    sbuf_t exp_sb = {0};
    const char *p = cur;
    while (*p) {
        if (*p == '[') {
            const char *star = strchr(p + 1, '*');
            const char *endb = strchr(p + 1, ']');
            if (star && endb && star < endb) {
                int valid_tok = 1;
                for (const char *c = p + 1; c < star; c++) {
                    if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-') { valid_tok = 0; break; }
                }
                int valid_num = (star + 1 < endb);
                for (const char *c = star + 1; c < endb; c++) {
                    if (!isdigit((unsigned char)*c)) { valid_num = 0; break; }
                }
                if (valid_tok && valid_num) {
                    size_t num_len=(size_t)(endb-(star+1)); char num_buf[32]; int cnt=0;
                    if(num_len==0||num_len>=sizeof(num_buf)) valid_num=0;
                    else { memcpy(num_buf,star+1,num_len); num_buf[num_len]='\0';
                           if(parse_int_range(num_buf,0,INT_MAX,&cnt)<0)valid_num=0; }
                    if(valid_num) {
                        if (cnt < 1) cnt = 1;
                        if (cnt > 100) cnt = 100;
                        size_t tlen=(size_t)(star-(p+1));
                        for(int i=0;i<cnt;i++){sbuf_append(&exp_sb,"[",1);sbuf_append(&exp_sb,p+1,tlen);sbuf_append(&exp_sb,"]",1);}
                        p=endb+1; continue;
                    }
                }
            }
        }
        sbuf_append(&exp_sb, p, 1);
        p++;
    }
    free(cur);
    if (exp_sb.failed) {
        free(exp_sb.data);
        return NULL;
    }
    cur = exp_sb.data ? exp_sb.data : strdup("");
    if (!cur) return NULL;

    char *unesc = unescape_backslashes(cur);
    free(cur);
    cur = unesc;
    if (!cur) return NULL;

    const char *port = cfg->host_port[0] ? cfg->host_port : (is_tls ? "443" : "80");
    const char *pport = cfg->proxy_port[0] ? cfg->proxy_port : (is_tls ? "443" : "80");
    char host_port[300];
    snprintf(host_port, sizeof(host_port), "%s:%s", cfg->host, port);

    const char *pairs[][2] = {
        {"[crlf]", "\r\n"},
        {"[lf]", "\n"},
        {"[cr]", "\r"},
        {"[protocol]", "HTTP/1.1"},
        {"[ua]", DEFAULT_UA},
        {"[proxy]", cfg->proxy},
        {"[proxy_host]", cfg->proxy},
        {"[proxy_port]", pport},
        {"[sni]", cfg->sni},
        {"[sni_host]", cfg->sni},
        {"[sni_port]", "443"},
        {"[host]", cfg->host},
        {"[server]", cfg->host},
        {"[ssh]", cfg->host},
        {"[ssh_host]", cfg->host},
        {"[ip]", cfg->host},
        {"[host_no_port]", cfg->host},
        {"[port]", port},
        {"[ssh_port]", port},
        {"[host_port]", host_port},
        {"[ip_port]", host_port},
        {"[method]", "GET"},
        {NULL, NULL}
    };
    for (int i = 0; pairs[i][0]; i++) {
        char *next = replace_all_str(cur, pairs[i][0], pairs[i][1]);
        free(cur);
        cur = next;
        if (!cur) return NULL;
    }

    const char *raw_tags[4] = {"[raw]", "[real_raw]", "[realData]", "[netData]"};
    for (int t = 0; t < 4; t++) {
        char *hit;
        while ((hit = strstr(cur, raw_tags[t])) != NULL) {
            const char *repl = (*embedded_banner_out == 0) ? (SSH_CLIENT_BANNER "\r\n") : "";
            *embedded_banner_out = 1;
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, (size_t)(hit - cur));
            sbuf_append(&sb, repl, strlen(repl));
            sbuf_append(&sb, hit + strlen(raw_tags[t]), strlen(hit + strlen(raw_tags[t])));
            if (sb.failed) {
                free(sb.data);
                free(cur);
                return NULL;
            }
            if (!sb.data) sb.data = strdup("");
            if (!sb.data) {
                free(cur);
                return NULL;
            }
            free(cur);
            cur = sb.data;
        }
    }

    const char *ws_tags[2] = {"[ws_key]", "[ws-key]"};
    for (int t = 0; t < 2; t++) {
        char *hit;
        while ((hit = strstr(cur, ws_tags[t])) != NULL) {
            char key[32];
            if(gen_ws_key(key)<0){log_red("RAND_bytes gagal saat membuat WebSocket key");free(cur);return NULL;}
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, (size_t)(hit - cur));
            sbuf_append(&sb, key, strlen(key));
            sbuf_append(&sb, hit + strlen(ws_tags[t]), strlen(hit + strlen(ws_tags[t])));
            if (sb.failed) {
                free(sb.data);
                free(cur);
                return NULL;
            }
            free(cur);
            cur = sb.data;
        }
    }

    int base_rotate_idx = 0;
    int rotate_loaded = 0;
    int rotate_tag_no = 0;

    for (int mode = 0; mode < 2; mode++) {
        const char *tag = (mode == 0) ? "[rotate=" : "[random=";
        char *scan = cur;
        char *hit;
        while (scan && (hit = strstr(scan, tag)) != NULL) {
            char *endb = strchr(hit + strlen(tag), ']');
            if (!endb) break;
            size_t prefix_len = (size_t)(hit - cur);
            size_t list_len = (size_t)(endb - (hit + strlen(tag)));
            char *list = malloc(list_len + 1U);
            if (!list) {
                log_red("Memori tidak cukup saat memproses payload %s", tag);
                free(cur);
                return NULL;
            }
            memcpy(list, hit + strlen(tag), list_len);
            list[list_len] = '\0';

            char *items[64];
            int nitems = 0;
            char *sp = list;
            while (nitems < 64) {
                char *semi = strchr(sp, ';');
                if (!semi) { items[nitems++] = sp; break; }
                *semi = '\0';
                items[nitems++] = sp;
                sp = semi + 1;
            }
            const char *chosen = "";
            if (nitems > 0) {
                if (mode == 0) {
                    if (!rotate_loaded) {
                        pthread_mutex_lock(&g_rotate_mutex);
                        FILE *rf = fopen(ROTATE_STATE_FILE, "r");
                        if (rf) {
                            if (fscanf(rf, "%d", &base_rotate_idx) != 1 || base_rotate_idx < 0)
                                base_rotate_idx = 0;
                            fclose(rf);
                        }
                        rotate_loaded = 1;
                        int next_idx = (base_rotate_idx >= 1000000) ? 0 : (base_rotate_idx + 1);
                        FILE *wf = fopen(ROTATE_STATE_FILE, "w");
                        if (wf) { fprintf(wf, "%d", next_idx); fclose(wf); }
                        pthread_mutex_unlock(&g_rotate_mutex);
                    }
                    int sel = (base_rotate_idx + rotate_tag_no) % nitems;
                    if (sel < 0) sel = 0;
                    chosen = items[sel];
                    rotate_tag_no++;
                } else {
                    int idx = rand_idx(nitems);
                    if (idx < 0) {
                        log_red("RAND_bytes gagal saat memilih payload random");
                        free(list);
                        free(cur);
                        return NULL;
                    }
                    chosen = items[idx];
                }
            }

            size_t chosen_len = strlen(chosen);
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, prefix_len);
            sbuf_append(&sb, chosen, chosen_len);
            sbuf_append(&sb, endb + 1, strlen(endb + 1));
            free(list);
            if (sb.failed) {
                free(sb.data);
                free(cur);
                return NULL;
            }
            if (!sb.data) {
                sb.data = strdup("");
                if (!sb.data) {
                    free(cur);
                    return NULL;
                }
            }
            free(cur);
            cur = sb.data;
            /* Do not parse a replacement recursively. Continue after it. */
            scan = cur + prefix_len + chosen_len;
        }
    }
    return cur;
}

static int starts_with_http_request(const char *s) {
    while (*s == '\r' || *s == '\n' || *s == ' ') s++;
    static const char *methods[] = {
        "GET ", "POST ", "CONNECT ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", NULL
    };
    for (int i = 0; methods[i]; i++) {
        if (strncasecmp(s, methods[i], strlen(methods[i])) == 0) return 1;
    }
    return 0;
}

static int starts_with_connect_request(const char *s) {
    while (*s == '\r' || *s == '\n' || *s == ' ') s++;
    return strncasecmp(s, "CONNECT ", 8) == 0;
}

/* ============================================================
 * SSH HOST KEY DIAGNOSTICS & OPTIONAL SHA-256 PINNING
 * ============================================================ */
static int b64_val(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static int hex_nibble(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int parse_sha256_fp(const char *in, uint8_t out[32]) {
    if (!in || !*in) return -1;
    const char *p = in;
    if (strncasecmp(p, "SHA256:", 7) == 0) p += 7;
    size_t len = strlen(p);

    if (len == 64 || len == 95) {
        uint8_t tmp[32];
        size_t i = 0, j = 0;
        int ok = 1;
        while (i < len && j < 32) {
            int hi = hex_nibble((unsigned char)p[i]);
            int lo = (i + 1 < len) ? hex_nibble((unsigned char)p[i + 1]) : -1;
            if (hi < 0 || lo < 0) { ok = 0; break; }
            tmp[j++] = (uint8_t)((hi << 4) | lo);
            i += 2;
            if (len == 95 && j < 32) {
                if (p[i] != ':') { ok = 0; break; }
                i++;
            }
        }
        if (ok && i == len && j == 32) {
            memcpy(out, tmp, 32);
            return 0;
        }
    }

    if (len == 44 && p[43] == '=') len = 43;
    if (len != 43) return -1;

    int v[43];
    for (size_t i = 0; i < 43; i++) {
        v[i] = b64_val((unsigned char)p[i]);
        if (v[i] < 0) return -1;
    }
    size_t j = 0;
    for (size_t i = 0; i < 40; i += 4) {
        out[j++] = (uint8_t)((v[i] << 2) | (v[i + 1] >> 4));
        out[j++] = (uint8_t)(((v[i + 1] & 0x0F) << 4) | (v[i + 2] >> 2));
        out[j++] = (uint8_t)(((v[i + 2] & 0x03) << 6) | v[i + 3]);
    }
    if ((v[42] & 0x03) != 0) return -1;
    out[30] = (uint8_t)((v[40] << 2) | (v[41] >> 4));
    out[31] = (uint8_t)(((v[41] & 0x0F) << 4) | (v[42] >> 2));
    return 0;
}

static void format_sha256_fp(const uint8_t digest[32], char *out, size_t out_sz) {
    char b64[48];
    int elen = EVP_EncodeBlock((unsigned char *)b64, digest, 32);
    if (elen > 0 && b64[elen - 1] == '=') b64[elen - 1] = '\0';
    snprintf(out, out_sz, "SHA256:%s", b64);
}

static int verify_ssh_hostkey(LIBSSH2_SESSION *session, const app_cfg_t *cfg) {
    size_t hk_len = 0;
    int hk_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *hk = libssh2_session_hostkey(session, &hk_len, &hk_type);
    if (!hk || hk_len == 0) {
        log_red("SSH Host Key tidak tersedia dari server");
        write_marker(KEX_FAILED_FILE, "missing hostkey");
        return -1;
    }

    uint8_t digest[32];
    unsigned int dlen = 0;
    if (EVP_Digest(hk, hk_len, digest, &dlen, EVP_sha256(), NULL) != 1 || dlen != 32) {
        log_red("Gagal menghitung SHA-256 host key SSH");
        write_marker(KEX_FAILED_FILE, "hostkey hash error");
        return -1;
    }

    char fp_str[64];
    format_sha256_fp(digest, fp_str, sizeof(fp_str));

    const char *tname = "unknown";
    switch (hk_type) {
        case LIBSSH2_HOSTKEY_TYPE_RSA:       tname = "ssh-rsa";             break;
#ifdef LIBSSH2_HOSTKEY_TYPE_DSS
        case LIBSSH2_HOSTKEY_TYPE_DSS:       tname = "ssh-dss";             break;
#endif
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: tname = "ecdsa-sha2-nistp256"; break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: tname = "ecdsa-sha2-nistp384"; break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: tname = "ecdsa-sha2-nistp521"; break;
#ifdef LIBSSH2_HOSTKEY_TYPE_ED25519
        case LIBSSH2_HOSTKEY_TYPE_ED25519:   tname = "ssh-ed25519";         break;
#endif
        default: break;
    }
    log_blue("SSH Host Key (%s): %s", tname, fp_str);

    if (cfg->hostkey_fp[0]) {
        uint8_t expected[32];
        if (parse_sha256_fp(cfg->hostkey_fp, expected) < 0) {
            log_red("Format HOSTKEY tidak valid: %s (gunakan SHA256:<base64> atau 64-hex)", cfg->hostkey_fp);
            write_marker(KEX_FAILED_FILE, "invalid hostkey config");
            return -1;
        }
        if (CRYPTO_memcmp(digest, expected, 32) != 0) {
            log_red("SSH Host Key MISMATCH! Server=%s, Diharapkan=%s", fp_str, cfg->hostkey_fp);
            write_marker(KEX_FAILED_FILE, "hostkey mismatch");
            return -1;
        }
        log_blue("SSH Host Key terverifikasi (SHA-256 pin)");
    } else {
        log_yellow("SSH Host Key tidak dipin (opsional: set HOSTKEY=%s untuk anti-MITM)", fp_str);
    }
    return 0;
}

/* ============================================================
 * SOCKET, POLL & RESUMABLE HTTP RESPONSE STRIPPER (NON-BLOCKING)
 * ============================================================ */
static int set_nonblock(int fd, int nb) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static void tune_tcp_socket(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* High-resolution elapsed-time clock used only by LOG_PERF instrumentation. */
static uint64_t perf_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
           (uint64_t)ts.tv_nsec;
}

static void perf_begin(long long now) {
    if (!g_log_perf) return;
    memset(&g_perf_stats, 0, sizeof(g_perf_stats));
    g_perf_window_start_ms = now;
}

static void perf_log_interval(long long now, LIBSSH2_SESSION *diag_session) {
    if (!g_log_perf) return;
    if (g_perf_window_start_ms <= 0) {
        perf_begin(now);
        return;
    }
    long long span_ms = now - g_perf_window_start_ms;
    if (span_ms < 1000) return;

    LIBSSH2_DIAG_TIMING libssh2_diag;
    memset(&libssh2_diag, 0, sizeof(libssh2_diag));
    if (diag_session)
        (void)libssh2_session_diag_timing_snapshot(
            diag_session, &libssh2_diag, 1);
    uint64_t libssh2_transport_other_ns =
        libssh2_diag.transport_read_ns >=
            (libssh2_diag.decrypt_path_ns + g_perf_stats.ssh_recv_s2c_cb_ns)
        ? libssh2_diag.transport_read_ns -
            libssh2_diag.decrypt_path_ns - g_perf_stats.ssh_recv_s2c_cb_ns : 0;
    uint64_t libssh2_channel_accounted_ns =
        libssh2_diag.transport_read_ns + libssh2_diag.packet_drain_ns;
    uint64_t libssh2_channel_other_ns =
        g_perf_stats.s2c_read_ns >= libssh2_channel_accounted_ns
        ? g_perf_stats.s2c_read_ns - libssh2_channel_accounted_ns : 0;

    unsigned int relay_clients = 0;
    unsigned int s2c_nonempty_clients = 0;
    unsigned int epollout_armed_clients = 0;
    unsigned int s2c_epollout_missing = 0;
    unsigned int c2s_nonempty_clients = 0;
    unsigned int c2s_window_waiters = 0;
    unsigned int ssh_eof_clients = 0;
    unsigned int ssh_eof_c2s_pending = 0;
    size_t s2c_used_sum = 0, s2c_used_max = 0;
    size_t c2s_used_sum = 0, c2s_used_max = 0;
    for (const client_conn_t *c = g_clients; c; c = c->next) {
        if (c->state != ST_RELAY) continue;
        relay_clients++;
        c2s_used_sum += c->c2s.used;
        if (c->c2s.used > c2s_used_max) c2s_used_max = c->c2s.used;
        if (c->c2s.used > 0) c2s_nonempty_clients++;
        if (c->write_waiting_window) c2s_window_waiters++;
        if (c->ssh_eof) {
            ssh_eof_clients++;
            if (c->c2s.used > 0 || c->write_pending) ssh_eof_c2s_pending++;
        }
        s2c_used_sum += c->s2c.used;
        if (c->s2c.used > s2c_used_max) s2c_used_max = c->s2c.used;
        if (c->s2c.used > 0) {
            s2c_nonempty_clients++;
            if (c->fd >= 0 && (c->epoll_events & EPOLLOUT)) {
                epollout_armed_clients++;
            } else if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
                s2c_epollout_missing++;
            }
        }
    }

    uint64_t s2c_internal_ns =
        g_perf_stats.s2c_read_ns >= g_perf_stats.ssh_recv_s2c_cb_ns
        ? g_perf_stats.s2c_read_ns - g_perf_stats.ssh_recv_s2c_cb_ns : 0;

    log_raw("[PERF] span_ms=%lld clients=%d relay=%u "
            "ep_calls=%llu ep_wait_ms=%llu ep_wait_max_ms=%llu ep_wakeups=%llu ep_timeouts=%llu "
            "tls_rx_calls=%llu tls_rx_bytes=%llu tls_rx_eagain=%llu ssh_rx_bytes=%llu ssh_rx_eagain=%llu "
            "s2c_read_calls=%llu s2c_read_bytes=%llu s2c_read_eagain=%llu "
            "socks_tx_calls=%llu socks_tx_bytes=%llu socks_tx_eagain=%llu socks_tx_partial=%llu "
            "c2s_rx_bytes=%llu c2s_ssh_write_bytes=%llu c2s_post_eof_rx_bytes=%llu c2s_post_eof_ssh_write_bytes=%llu "
            "c2s_post_eof_window_blocked=%llu window_waiter_retries=%llu window_waiter_upstream_events=%llu "
            "epoll_ctl_add_fail=%llu epoll_ctl_mod_fail=%llu epoll_ctl_errno=%d "
            "c2s_used_sum=%zu c2s_used_max=%zu c2s_nonempty=%u c2s_window_waiters=%u ssh_eof_clients=%u ssh_eof_c2s_pending=%u "
            "s2c_used_sum=%zu s2c_used_max=%zu s2c_nonempty=%u epollout_armed=%u s2c_epollout_missing=%u "
            "s2c_full=%llu libssh2_eagain=%llu pend_blk=%llu "
            "perf_s2c_read_us=%llu perf_ssh_recv_cb_us=%llu "
            "perf_ssh_recv_s2c_cb_us=%llu perf_s2c_internal_us=%llu "
            "perf_ssh_recv_syscall_us=%llu perf_socks_tx_us=%llu "
            "ssh_recv_cb_calls=%llu ssh_recv_s2c_cb_calls=%llu "
            "ssh_recv_syscall_calls=%llu socks_tx_flush_calls=%llu "
            "libssh2_decrypt_path_us=%llu libssh2_decrypt_path_calls=%llu "
            "libssh2_decrypt_path_bytes=%llu libssh2_transport_read_us=%llu "
            "libssh2_transport_other_us=%llu libssh2_transport_read_calls=%llu "
            "libssh2_packet_drain_us=%llu libssh2_packet_drain_calls=%llu "
            "libssh2_packet_drain_bytes=%llu libssh2_packet_drain_removed=%llu "
            "libssh2_channel_other_us=%llu "
            "libssh2_packet_queue_current_packets=%llu "
            "libssh2_packet_queue_current_bytes=%llu "
            "libssh2_packet_queue_peak_packets=%llu "
            "libssh2_packet_queue_peak_bytes=%llu "
            "libssh2_packet_queue_enqueued_packets=%llu "
            "libssh2_packet_queue_enqueued_bytes=%llu",
            span_ms, g_client_count, relay_clients,
            (unsigned long long)g_perf_stats.epoll_calls,
            (unsigned long long)g_perf_stats.epoll_wait_ms,
            (unsigned long long)g_perf_stats.epoll_wait_max_ms,
            (unsigned long long)g_perf_stats.epoll_wakeups,
            (unsigned long long)g_perf_stats.epoll_timeouts,
            (unsigned long long)g_perf_stats.tls_rx_calls,
            (unsigned long long)g_perf_stats.tls_rx_bytes,
            (unsigned long long)g_perf_stats.tls_rx_eagain,
            (unsigned long long)g_perf_stats.ssh_rx_bytes,
            (unsigned long long)g_perf_stats.ssh_rx_eagain,
            (unsigned long long)g_perf_stats.s2c_read_calls,
            (unsigned long long)g_perf_stats.s2c_read_bytes,
            (unsigned long long)g_perf_stats.s2c_read_eagain,
            (unsigned long long)g_perf_stats.socks_tx_calls,
            (unsigned long long)g_perf_stats.socks_tx_bytes,
            (unsigned long long)g_perf_stats.socks_tx_eagain,
            (unsigned long long)g_perf_stats.socks_tx_partial,
            (unsigned long long)g_perf_stats.c2s_rx_bytes,
            (unsigned long long)g_perf_stats.c2s_ssh_write_bytes,
            (unsigned long long)g_perf_stats.c2s_post_eof_rx_bytes,
            (unsigned long long)g_perf_stats.c2s_post_eof_ssh_write_bytes,
            (unsigned long long)g_perf_stats.c2s_post_eof_window_blocked,
            (unsigned long long)g_perf_stats.window_waiter_retry_count,
            (unsigned long long)g_perf_stats.window_waiter_upstream_events,
            (unsigned long long)g_perf_stats.epoll_ctl_add_fail,
            (unsigned long long)g_perf_stats.epoll_ctl_mod_fail,
            g_perf_stats.epoll_ctl_last_errno,
            c2s_used_sum, c2s_used_max, c2s_nonempty_clients, c2s_window_waiters,
            ssh_eof_clients, ssh_eof_c2s_pending,
            s2c_used_sum, s2c_used_max, s2c_nonempty_clients,
            epollout_armed_clients, s2c_epollout_missing,
            (unsigned long long)g_perf_stats.s2c_full,
            (unsigned long long)g_perf_stats.libssh2_eagain,
            (unsigned long long)g_perf_stats.pending_blocks,
            (unsigned long long)(g_perf_stats.s2c_read_ns / 1000U),
            (unsigned long long)(g_perf_stats.ssh_recv_cb_ns / 1000U),
            (unsigned long long)(g_perf_stats.ssh_recv_s2c_cb_ns / 1000U),
            (unsigned long long)(s2c_internal_ns / 1000U),
            (unsigned long long)(g_perf_stats.ssh_recv_syscall_ns / 1000U),
            (unsigned long long)(g_perf_stats.socks_tx_ns / 1000U),
            (unsigned long long)g_perf_stats.ssh_recv_cb_calls,
            (unsigned long long)g_perf_stats.ssh_recv_s2c_cb_calls,
            (unsigned long long)g_perf_stats.ssh_recv_syscall_calls,
            (unsigned long long)g_perf_stats.socks_tx_flush_calls,
            (unsigned long long)(libssh2_diag.decrypt_path_ns / 1000U),
            (unsigned long long)libssh2_diag.decrypt_path_calls,
            (unsigned long long)libssh2_diag.decrypt_path_bytes,
            (unsigned long long)(libssh2_diag.transport_read_ns / 1000U),
            (unsigned long long)(libssh2_transport_other_ns / 1000U),
            (unsigned long long)libssh2_diag.transport_read_calls,
            (unsigned long long)(libssh2_diag.packet_drain_ns / 1000U),
            (unsigned long long)libssh2_diag.packet_drain_calls,
            (unsigned long long)libssh2_diag.packet_drain_bytes,
            (unsigned long long)libssh2_diag.packet_drain_removed,
            (unsigned long long)(libssh2_channel_other_ns / 1000U),
            (unsigned long long)libssh2_diag.packet_queue_packets_current,
            (unsigned long long)libssh2_diag.packet_queue_bytes_current,
            (unsigned long long)libssh2_diag.packet_queue_packets_peak,
            (unsigned long long)libssh2_diag.packet_queue_bytes_peak,
            (unsigned long long)libssh2_diag.packet_queue_enqueued_packets,
            (unsigned long long)libssh2_diag.packet_queue_enqueued_bytes);

    memset(&g_perf_stats, 0, sizeof(g_perf_stats));
    g_perf_window_start_ms = now;
}

static int poll_fd_until(int fd, short events, long long deadline_ms) {
    while (!stop_requested()) {
        long long rem = deadline_ms - now_ms();
        if (rem <= 0) return 0;
        int to = (rem > 60000) ? 60000 : (int)rem;
        struct pollfd pfd = { .fd = fd, .events = events };
        int rc = poll(&pfd, 1, to);
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
            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                           &socket_error, &error_len) < 0) return -1;
            errno = socket_error ? socket_error : EIO;
            return -1;
        }
        if (pfd.revents & POLLHUP) {
            if (events & POLLIN) return 1;
            errno = EPIPE;
            return -1;
        }
        if (pfd.revents & events) return 1;
        if (pfd.revents != 0) {
            errno = EIO;
            return -1;
        }
    }
    return -1;
}

/* Called after g_stop: ignore the signal flag, but never exceed the deadline. */
static int poll_fd_until_shutdown(int fd, short events, long long deadline_ms) {
    for (;;) {
        long long rem = deadline_ms - now_ms();
        if (rem <= 0) return 0;
        int to = (rem > 60000) ? 60000 : (int)rem;
        struct pollfd pfd = { .fd = fd, .events = events };
        int rc = poll(&pfd, 1, to);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) continue;
        if (pfd.revents & POLLNVAL) return -1;
        if (pfd.revents & events) return 1;
        if ((pfd.revents & POLLHUP) && (events & POLLIN)) return 1;
        if (pfd.revents & (POLLERR | POLLHUP)) return -1;
        return -1;
    }
}

static int wait_upstream_event(upstream_ctx_t *u, short socket_events,
                               long long deadline_ms, int shutdown_mode) {
    int fd = u ? u->fd : -1;
    short events = socket_events;
    if (u && u->tls) {
        fd = tls_engine_notify_fd(u->tls);
        events = POLLIN;
    }
    if (fd < 0) { errno = EBADF; return -1; }
    int rc = shutdown_mode ? poll_fd_until_shutdown(fd, events, deadline_ms)
                           : poll_fd_until(fd, events, deadline_ms);
    if (rc > 0 && u && u->tls) tls_engine_drain_notify(u->tls);
    return rc;
}

static __thread unsigned int g_tls_diag_message_count = 0;

static const char *tls_handshake_message_name(unsigned int type) {
    switch (type) {
        case 0: return "HelloRequest";
        case 1: return "ClientHello";
        case 2: return "ServerHello";
        case 4: return "NewSessionTicket";
        case 8: return "EncryptedExtensions";
        case 11: return "Certificate";
        case 12: return "ServerKeyExchange";
        case 13: return "CertificateRequest";
        case 14: return "ServerHelloDone";
        case 15: return "CertificateVerify";
        case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        case 24: return "KeyUpdate";
        default: return "OtherHandshake";
    }
}

static void tls_diag_log(upstream_ctx_t *u, int warning,
                           const char *fmt, ...) {
    char msg[1536], timestamp[32], line[2200], colored[1900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(timestamp, sizeof(timestamp));
    snprintf(colored, sizeof(colored), warning
        ? "<font color=\"#FFFF00\">[%s] %s</font>"
        : "<span color=\"#3C86AB\">[%s] %s</span>", timestamp, msg);
    if (u && u->log_worker_count > 1)
        snprintf(line, sizeof(line), "[worker %d/%d] %s",
                 u->log_worker_id + 1, u->log_worker_count, colored);
    else
        snprintf(line, sizeof(line), "%s", colored);
    const char *path = (u && u->log_path) ? u->log_path : DEFAULT_LOG_PATH;
    pthread_mutex_lock(&g_log_mutex);
    if (strcmp(path, "-") == 0) {
        printf("%s\n", line);
        fflush(stdout);
    } else {
        FILE *f = fopen(path, "a");
        if (f) { fprintf(f, "%s\n", line); fclose(f); }
    }
    pthread_mutex_unlock(&g_log_mutex);
}

static void tls_message_callback(int write_p, int version, int content_type,
                                 const void *buf, size_t len,
                                 SSL *ssl, void *arg) {
    int saved_errno = errno;
    upstream_ctx_t *u = (upstream_ctx_t *)arg;
    (void)ssl;
    if (!buf || len == 0 || g_tls_diag_message_count >= 32) {
        errno = saved_errno;
        return;
    }
    const unsigned char *bytes = (const unsigned char *)buf;
    if (content_type == SSL3_RT_HANDSHAKE) {
        tls_diag_log(u, 0, "[TLS-DIAG] %s %s version=0x%04x message_len=%zu",
                     write_p ? "TX" : "RX",
                     tls_handshake_message_name(bytes[0]), version, len);
        g_tls_diag_message_count++;
    } else if (content_type == SSL3_RT_ALERT && len >= 2) {
        tls_diag_log(u, 1, "[TLS-DIAG] %s alert level=%s description=%s version=0x%04x",
                     write_p ? "TX" : "RX",
                     SSL_alert_type_string_long(bytes[0]),
                     SSL_alert_desc_string_long(bytes[1]), version);
        g_tls_diag_message_count++;
    }
    errno = saved_errno;
}

static int raw_write_all_nb(upstream_ctx_t *u, const void *data,
                            size_t len, int timeout_ms) {
    const uint8_t *p = (const uint8_t *)data;
    size_t left = len;
    long long deadline = now_ms() + timeout_ms;
    while (left > 0 && !stop_requested()) {
        if (u->tls) {
            ssize_t n = tls_engine_send(u->tls, p, left);
            if (n > 0) {
                u->last_activity_ms = now_ms();
                p += (size_t)n;
                left -= (size_t)n;
                continue;
            }
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            if (wait_upstream_event(u, POLLIN, deadline, 0) <= 0) return -1;
        } else {
            ssize_t n = send(u->fd, p, left, MSG_NOSIGNAL);
            if (n > 0) {
                u->last_activity_ms = now_ms();
                p += (size_t)n;
                left -= (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (poll_fd_until(u->fd, POLLOUT, deadline) <= 0) return -1;
                continue;
            }
            return -1;
        }
    }
    return left == 0 ? 0 : -1;
}

static const uint8_t *find_bytes(const uint8_t *hay, size_t hlen, const char *needle, size_t nlen) {
    if (hlen < nlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return NULL;
}

/* Return: >0 bytes read, 0 EOF, -2 EAGAIN, -1 error */
static ssize_t pre_read_more(upstream_ctx_t *u) {
    if (u->pre_off > 0 && u->pre_off < u->pre_len) {
        memmove(u->pre_buf, u->pre_buf + u->pre_off, u->pre_len - u->pre_off);
        u->pre_len -= u->pre_off;
        u->pre_off = 0;
    } else if (u->pre_off >= u->pre_len) {
        u->pre_off = 0;
        u->pre_len = 0;
    }
    if (u->pre_len >= sizeof(u->pre_buf)) return -1;
    size_t space = sizeof(u->pre_buf) - u->pre_len;

    if (u->tls) {
        ssize_t n = tls_engine_recv(u->tls, u->pre_buf + u->pre_len, space);
        if (n > 0) {
            u->pre_len += (size_t)n;
            u->last_activity_ms = now_ms();
            return n;
        }
        if (n == 0) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;
        log_red("TLS Engine receive error while reading HTTP response: %s",
                strerror(errno ? errno : EIO));
        return -1;
    }

    ssize_t n;
    do {
        n = recv(u->fd, u->pre_buf + u->pre_len, space, 0);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        u->pre_len += (size_t)n;
        u->last_activity_ms = now_ms();
        return n;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    if (n < 0) log_red("recv error: %s", strerror(errno));
    return n == 0 ? 0 : -1;
}

static void delay_wait_and_drain(upstream_ctx_t *u, int delay_ms) {
    if (delay_ms <= 0) return;
    long long deadline = now_ms() + delay_ms;
    while (!stop_requested()) {
        long long remaining = deadline - now_ms();
        if (remaining <= 0) break;
        int timeout = remaining > DELAY_WAIT_POLL_MAX_MS
            ? DELAY_WAIT_POLL_MAX_MS : (int)remaining;
        long long slice = now_ms() + timeout;
        if (slice > deadline) slice = deadline;
        if (u->pre_len >= sizeof(u->pre_buf)) {
            (void)poll(NULL, 0, timeout);
            continue;
        }
        int rc = wait_upstream_event(u, POLLIN, slice, 0);
        if (rc < 0) break;
        if (rc == 0) continue;
        ssize_t r = pre_read_more(u);
        if (r == 0 || r == -1) break;
    }
}

/* Return: 0 selesai 1 respons (atau masuk tunnel), -2 EAGAIN, -1 error */
static int http_header_has_token(const char *value,const char *token) {
    size_t token_len=strlen(token); const char *p=value;
    while(p&&*p){while(*p==' '||*p=='\t'||*p==',')p++;const char *end=p;while(*end&&*end!=',')end++;
        const char *trim=end;while(trim>p&&(trim[-1]==' '||trim[-1]=='\t'))trim--;
        if((size_t)(trim-p)==token_len&&strncasecmp(p,token,token_len)==0)return 1;
        p=*end?end+1:end;
    } return 0;
}
/* 0 parsed/non-tunnel, -2 EAGAIN, -1 malformed or closed. */
static int http_chunk_total_add(upstream_ctx_t *u, size_t chunk_size) {
    if (!u || u->http_chunk_total > MAX_HTTP_SKIP_BODY ||
        chunk_size > MAX_HTTP_SKIP_BODY - u->http_chunk_total) return -1;
    u->http_chunk_total += chunk_size;
    return 0;
}

static int socks5_reserved_valid(const uint8_t *request, size_t len) {
    return request && len >= 3 && request[2] == 0;
}

static int socks5_domain_valid(const uint8_t *request, size_t request_len) {
    if (!request || request_len < 5) return 0;
    size_t domain_len = request[4];
    if (domain_len == 0 || request_len < 5U + domain_len + 2U) return 0;
    return memchr(request + 5, '\0', domain_len) == NULL;
}

static int consume_one_http_response(upstream_ctx_t *u,int allow_non_tunnel) {
    if(u->tunnel_established)return 0;
    while(1){
        if(u->http_close_delimited){u->pre_off=u->pre_len;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
        if(u->http_skip_remaining){
            while(u->http_skip_remaining){size_t a=u->pre_len-u->pre_off;if(a){size_t n=a<u->http_skip_remaining?a:u->http_skip_remaining;u->pre_off+=n;u->http_skip_remaining-=n;}
                else{ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;}}
            if(u->http_pending_tunnel){u->http_pending_tunnel=0;u->tunnel_established=1;}return 0;
        }
        if(u->http_in_chunked){
            if(u->http_chunk_state==0){
                const uint8_t *nl=find_bytes(u->pre_buf+u->pre_off,u->pre_len-u->pre_off,"\n",1);
                if(!nl){if(u->pre_len-u->pre_off>1024)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                size_t len=(size_t)(nl-(u->pre_buf+u->pre_off));if(len>=256)return -1;
                char line[256];memcpy(line,u->pre_buf+u->pre_off,len);line[len]='\0';if(len&&line[len-1]=='\r')line[len-1]='\0';
                char *semi=strchr(line,';');if(semi)*semi='\0';trim_ws(line);
                size_t chunk=0;if(parse_strict_hex_size(line,&chunk,MAX_HTTP_SKIP_BODY)<0)return -1;
                if(chunk>0 && http_chunk_total_add(u,chunk)<0)return -1;
                u->pre_off+=len+1;if(chunk==0)u->http_chunk_state=3;else{u->http_chunk_rem=chunk;u->http_chunk_state=1;}
            } else if(u->http_chunk_state==1){
                size_t a=u->pre_len-u->pre_off;if(a){size_t n=a<u->http_chunk_rem?a:u->http_chunk_rem;u->pre_off+=n;u->http_chunk_rem-=n;if(!u->http_chunk_rem)u->http_chunk_state=2;}
                else{ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;}
            } else if(u->http_chunk_state==2){
                size_t a=u->pre_len-u->pre_off;if(!a){ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                if(u->pre_buf[u->pre_off]=='\r'){if(a<2){ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}if(u->pre_buf[u->pre_off+1]!='\n')return -1;u->pre_off+=2;}
                else if (u->pre_buf[u->pre_off] == '\n') {
                    u->pre_off++;
                } else {
                    return -1;
                }
                u->http_chunk_state = 0;
            } else {
                const uint8_t *nl=find_bytes(u->pre_buf+u->pre_off,u->pre_len-u->pre_off,"\n",1);
                if(!nl){if(u->pre_len-u->pre_off>4096)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                size_t len=(size_t)(nl-(u->pre_buf+u->pre_off));int empty=!len||(len==1&&u->pre_buf[u->pre_off]=='\r');u->pre_off+=len+1;
                if(empty){u->http_in_chunked=0;u->http_chunk_state=0;u->http_chunk_total=0;if(u->http_pending_tunnel){u->http_pending_tunnel=0;u->tunnel_established=1;}return 0;}
            } continue;
        }
        while(1){
            size_t a=u->pre_len-u->pre_off;const uint8_t *cur=u->pre_buf+u->pre_off;
            if(a){size_t n=a<5?a:5;if(memcmp(cur,"HTTP/",n)!=0){
                if(!allow_non_tunnel && u->last_http_code >= 100 && u->last_http_code < 300) return -1;
                if(!allow_non_tunnel&&u->last_http_code>=300){size_t sn=a<4?a:4;if(memcmp(cur,"SSH-",sn)!=0)return -1;if(a>=4){u->tunnel_established=1;return 0;}}
                else{u->tunnel_established=1;return 0;}
            }else if(a>=5)break;}
            ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r==0){if(u->pre_len>u->pre_off&&(allow_non_tunnel||u->last_http_code==0)){u->tunnel_established=1;return 0;}return -1;}if(r<0)return -1;
        }
        const uint8_t *start=u->pre_buf+u->pre_off;size_t avail=u->pre_len-u->pre_off,delim=0;
        const uint8_t *endp=find_bytes(start,avail,"\r\n\r\n",4);if(endp)delim=4;else{endp=find_bytes(start,avail,"\n\n",2);if(endp)delim=2;}
        if(!endp){if(avail>MAX_HTTP_HEADER)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
        size_t hlen=(size_t)(endp-start);if(hlen>MAX_HTTP_HEADER)return -1;char hdr[MAX_HTTP_HEADER+1];memcpy(hdr,start,hlen);hdr[hlen]='\0';u->pre_off+=hlen+delim;
        char status[256]={0};char *eol=strpbrk(hdr,"\r\n");size_t slen=eol?(size_t)(eol-hdr):strlen(hdr);
        if (!slen || slen >= sizeof(status)) return -1;
        memcpy(status, hdr, slen);
        /* Only accept syntactically valid HTTP/1.0 and HTTP/1.1 status lines. */
        if (strncmp(status, "HTTP/1.", 7) != 0 ||
            (status[7] != '0' && status[7] != '1') || status[8] != ' ') return -1;
        if(strcmp(u->last_status,status)){snprintf(u->last_status, sizeof(u->last_status), "%.127s", status);log_yellow("%s",status);}
        char *sp = status + 8;
        if (!isdigit((unsigned char)sp[1]) || !isdigit((unsigned char)sp[2]) ||
            !isdigit((unsigned char)sp[3]) || (sp[4] != '\0' && sp[4] != ' ')) return -1;
        int code=(sp[1]-'0')*100+(sp[2]-'0')*10+(sp[3]-'0');if(code<100||code>599)return -1;u->last_http_code=code;
        if(u->expect_connect_resp&&code>=200&&code<=299){u->tunnel_established=1;return 0;}
        int has_cl=0,has_te=0,chunked=0,upgrade=0,connection_upgrade=0;size_t body=0;
        char *p=eol?eol+1:hdr+hlen;
        while(*p){while(*p=='\r'||*p=='\n')p++;if(!*p)break;char *next=strpbrk(p,"\r\n");if(next)*next='\0';char *colon=strchr(p,':');if(!colon)return -1;*colon='\0';char *name=p,*val=colon+1;trim_ws(name);trim_ws(val);
            if(!strcasecmp(name,"content-length")){size_t n=0;if(parse_strict_dec_size(val,&n,MAX_HTTP_SKIP_BODY)<0)return -1;if(has_cl&&n!=body)return -1;has_cl=1;body=n;}
            else if(!strcasecmp(name,"transfer-encoding")){has_te=1;const char *last=strrchr(val,',');last=last?last+1:val;while(*last==' '||*last=='\t')last++;size_t n=strlen(last);while(n&&(last[n-1]==' '||last[n-1]=='\t'))n--;if(n!=7||strncasecmp(last,"chunked",7))return -1;chunked=1;}
            else if(!strcasecmp(name,"upgrade"))upgrade=(*val!='\0');
            else if(!strcasecmp(name,"connection"))connection_upgrade=http_header_has_token(val,"upgrade");
            if (!next) break;
            p = next + 1;
        }
        if(has_te&&has_cl)return -1;
        if(code==101){if(!upgrade||!connection_upgrade)return -1;u->tunnel_established=1;return 0;}
        if((code>=100&&code<200)||code==204||code==304)return 0;

        /* Legacy payloads may use a non-CONNECT 200 as the tunnel marker.
         * When explicitly enabled, consume framed HTTP bodies first so they
         * never leak into the SSH stream. */
        int legacy_200_tunnel=(code==200&&u->allow_http_200_tunnel);
        if(chunked){
            u->http_chunk_total=0;
            u->http_in_chunked=1;
            u->http_chunk_state=0;
            u->http_pending_tunnel=legacy_200_tunnel;
            continue;
        }
        if(has_cl){
            if(body==0){
                if(legacy_200_tunnel)u->tunnel_established=1;
                return 0;
            }
            u->http_skip_remaining=body;
            u->http_pending_tunnel=legacy_200_tunnel;
            continue;
        }
        if (legacy_200_tunnel) {
            u->tunnel_established = 1;
            return 0;
        }
        if (code == 200) {
            /* Do not mistake a raw SSH tunnel for a close-delimited HTTP body. */
            return -1;
        }
        /* Other ordinary HTTP responses may be close-delimited and end at EOF. */
        u->http_close_delimited=1;
    }
}

static ssize_t mark_upstream_rx_terminal(upstream_ctx_t *u, ssize_t result) {
    if (!u) return result < 0 ? result : -EIO;
    u->rx_terminal = 1;
    u->rx_terminal_rc = (int)result;
    u->hup_seen = 1;
    u->upstream_epoll_detached = !u->tls || u->tx_terminal ||
                                 tls_engine_tx_terminal(u->tls, NULL);
    return u->rx_flush_eagain ? -EAGAIN : result;
}

static ssize_t ssh_recv_cb_impl(libssh2_socket_t sock, void *buffer, size_t length,
                                int flags, void **abstract) {
    (void)flags;
    upstream_ctx_t *u = (upstream_ctx_t *)(*abstract);
    if (!u) return -EIO;
    if (length == 0) return 0;
    while (!u->tunnel_established) {
        int rc = consume_one_http_response(u, 0);
        if (rc == -2) return -EAGAIN;
        if (rc < 0) return -EIO;
    }
    if (u->pre_off < u->pre_len) {
        size_t available = u->pre_len - u->pre_off;
        size_t take = available < length ? available : length;
        if (g_log_perf) g_perf_stats.ssh_rx_bytes += take;
        memcpy(buffer, u->pre_buf + u->pre_off, take);
        u->pre_off += take;
        if (u->pre_off == u->pre_len) { u->pre_off = 0; u->pre_len = 0; }
        u->last_activity_ms = now_ms();
        u->rx_seq++;
        return (ssize_t)take;
    }
    if (u->rx_terminal) {
        if (g_log_perf && u->rx_flush_eagain) g_perf_stats.ssh_rx_eagain++;
        return u->rx_flush_eagain ? -EAGAIN : (ssize_t)u->rx_terminal_rc;
    }
    if (u->tls) {
        size_t read_length = length > 32768U ? 32768U : length;
        ssize_t r = tls_engine_recv(u->tls, buffer, read_length);
        if (g_log_perf) g_perf_stats.tls_rx_calls++;
        if (r > 0) {
            if (g_log_perf) {
                g_perf_stats.tls_rx_bytes += (uint64_t)r;
                g_perf_stats.ssh_rx_bytes += (uint64_t)r;
            }
            u->last_activity_ms = now_ms();
            u->rx_seq++;
            return r;
        }
        if (r == 0) return mark_upstream_rx_terminal(u, 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (g_log_perf) {
                g_perf_stats.tls_rx_eagain++;
                g_perf_stats.ssh_rx_eagain++;
            }
            return -EAGAIN;
        }
        int err = errno ? errno : EIO;
        return mark_upstream_rx_terminal(u, -(ssize_t)err);
    }
    ssize_t r;
    do {
        uint64_t recv_started_ns = g_log_perf ? perf_now_ns() : 0;
        r = recv(sock, buffer, length, 0);
        if (g_log_perf) {
            g_perf_stats.ssh_recv_syscall_calls++;
            if (recv_started_ns != 0) {
                uint64_t recv_ended_ns = perf_now_ns();
                if (recv_ended_ns >= recv_started_ns)
                    g_perf_stats.ssh_recv_syscall_ns +=
                        recv_ended_ns - recv_started_ns;
            }
        }
    } while (r < 0 && errno == EINTR);
    if (r > 0) {
        if (g_log_perf) g_perf_stats.ssh_rx_bytes += (uint64_t)r;
        u->last_activity_ms = now_ms();
        u->rx_seq++;
        return r;
    }
    int recv_error = errno;
    if (r < 0 && (recv_error == EAGAIN || recv_error == EWOULDBLOCK)) {
        if (g_log_perf) g_perf_stats.ssh_rx_eagain++;
        return -EAGAIN;
    }
    if (r == 0) return mark_upstream_rx_terminal(u, 0);
    return mark_upstream_rx_terminal(u, -(ssize_t)(recv_error ? recv_error : EIO));
}

/* Time the callback and its subset nested inside an S2C channel read. */
static ssize_t ssh_recv_cb(libssh2_socket_t sock, void *buffer, size_t length,
                           int flags, void **abstract) {
    uint64_t started_ns = g_log_perf ? perf_now_ns() : 0;
    int nested_in_s2c = g_log_perf && g_perf_s2c_read_depth > 0;
    if (g_log_perf) {
        g_perf_stats.ssh_recv_cb_calls++;
        if (nested_in_s2c) g_perf_stats.ssh_recv_s2c_cb_calls++;
    }

    ssize_t rc = ssh_recv_cb_impl(sock, buffer, length, flags, abstract);
    if (started_ns != 0) {
        uint64_t ended_ns = perf_now_ns();
        if (ended_ns >= started_ns) {
            uint64_t elapsed_ns = ended_ns - started_ns;
            g_perf_stats.ssh_recv_cb_ns += elapsed_ns;
            if (nested_in_s2c)
                g_perf_stats.ssh_recv_s2c_cb_ns += elapsed_ns;
        }
    }
    return rc;
}

static ssize_t ssh_send_cb(libssh2_socket_t sock, const void *buffer, size_t length,
                           int flags, void **abstract) {
    (void)flags;
    upstream_ctx_t *u = (upstream_ctx_t *)(*abstract);
    if (!u) return -EIO;
    if (length == 0) return 0;
    if (u->skip_ssh_banner_bytes > 0) {
        size_t take = length < u->skip_ssh_banner_bytes ? length : u->skip_ssh_banner_bytes;
        u->skip_ssh_banner_bytes -= take;
        u->last_activity_ms = now_ms();
        return (ssize_t)take;
    }
    if (u->tls) {
        size_t write_length = length > 32768U ? 32768U : length;
        ssize_t r = tls_engine_send(u->tls, buffer, write_length);
        if (r > 0) {
            u->last_activity_ms = now_ms();
            return r;
        }
        if (r == 0 || errno == EAGAIN || errno == EWOULDBLOCK) return -EAGAIN;
        int err = errno ? errno : EIO;
        u->tx_terminal = 1;
        u->hup_seen = 1;
        if (tls_engine_tx_terminal(u->tls, NULL)) u->upstream_epoll_detached = 1;
        return -err;
    }
    ssize_t r;
    do { r = send(sock, buffer, length, MSG_NOSIGNAL); } while (r < 0 && errno == EINTR);
    if (r > 0) {
        u->last_activity_ms = now_ms();
        return r;
    }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -EAGAIN;
    if (r < 0) {
        u->tx_terminal = 1;
        u->hup_seen = 1;
        u->upstream_epoll_detached = 1;
    }
    return r < 0 ? -errno : 0;
}

static int auth_method_offered(const char *methods, const char *wanted) {
    if (!methods || !wanted || !*wanted) return 0;
    size_t wanted_len = strlen(wanted);
    const char *p = methods;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t token_len = end ? (size_t)(end - p) : strlen(p);
        if (token_len == wanted_len && memcmp(p, wanted, wanted_len) == 0)
            return 1;
        if (!end) break;
        p = end + 1;
    }
    return 0;
}

static void kbd_auth_cb(const char *name, int name_len, const char *instruction, int instruction_len,
                        int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                        LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract) {
    (void)name; (void)name_len; (void)instruction; (void)instruction_len;
    (void)prompts; (void)abstract;
    for (int i = 0; i < num_prompts; i++) {
        responses[i].text = strdup(g_kbd_password);
        responses[i].length = (unsigned int)strlen(g_kbd_password);
    }
}

static int tls_buffered_input_pending(const upstream_ctx_t *u) {
    return u && u->tls && tls_engine_rx_pending(u->tls) > 0;
}
static int wait_ssh_nb(LIBSSH2_SESSION *session, upstream_ctx_t *u,
                       long long deadline_ms) {
    if (now_ms() >= deadline_ms) return 0;
    if (u && u->rx_terminal) return 1;
    if (tls_buffered_input_pending(u)) return 1;
    if (u && u->tls) return wait_upstream_event(u, POLLIN, deadline_ms, 0);
    short events = 0;
    int dirs = libssh2_session_block_directions(session);
    if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) events |= POLLIN;
    if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) events |= POLLOUT;
    if (events == 0) events = POLLIN;
    return poll_fd_until(u->fd, events, deadline_ms);
}
/* ============================================================
 * DIAL UPSTREAM
 *
 * Resolve IPv4 and IPv6 separately. On musl, an AF_UNSPEC lookup can
 * combine A/AAAA resolver failures; a broken AAAA response must not
 * suppress a usable A record. Addresses within one family are raced
 * concurrently, bounded by a four-second family deadline.
 * ============================================================ */
typedef struct {
    int fd;
    const struct addrinfo *ai;
    char address[INET6_ADDRSTRLEN + 24];
} tcp_connect_candidate_t;

static void tcp_format_address(const struct sockaddr *sa,
                               char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!sa) return;

    char ip[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)sa;
        if (!inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof(ip))) return;
        snprintf(out, out_size, "%s:%u", ip, (unsigned)ntohs(a4->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)sa;
        if (!inet_ntop(AF_INET6, &a6->sin6_addr, ip, sizeof(ip))) return;
        snprintf(out, out_size, "[%s]:%u", ip, (unsigned)ntohs(a6->sin6_port));
    }
}

static const char *tcp_family_name(int family) {
    return family == AF_INET ? "IPv4/A" : "IPv6/AAAA";
}

static void close_connect_fd(int *fd) {
    if (!fd || *fd < 0) return;
    int old_fd = *fd;
    *fd = -1;
    (void)close(old_fd);
}

static int tcp_address_is_excluded(const char *address,
                                   const char *const *excluded_addresses,
                                   size_t excluded_count) {
    if (!address || !excluded_addresses) return 0;
    for (size_t i = 0; i < excluded_count; i++) {
        if (excluded_addresses[i] &&
            strcmp(address, excluded_addresses[i]) == 0) return 1;
    }
    return 0;
}

static int tcp_connect_addrinfo_list(const struct addrinfo *res, int family,
                                     long long deadline_ms,
                                     const char *const *excluded_addresses,
                                     size_t excluded_count,
                                     char *connected_address,
                                     size_t connected_address_size,
                                     int *last_errno_out) {
    tcp_connect_candidate_t candidates[TCP_CONNECT_MAX_ADDRS];
    struct pollfd pfds[TCP_CONNECT_MAX_ADDRS];
    size_t count = 0;
    size_t active = 0;
    int last_error = EHOSTUNREACH;

    for (size_t i = 0; i < TCP_CONNECT_MAX_ADDRS; i++) {
        candidates[i].fd = -1;
        candidates[i].ai = NULL;
        candidates[i].address[0] = '\0';
        pfds[i].fd = -1;
        pfds[i].events = POLLOUT;
        pfds[i].revents = 0;
    }

    for (const struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family != family) continue;
        if (count >= TCP_CONNECT_MAX_ADDRS) {
            if (g_tcp_dial_debug)
                log_yellow("[TCP-DIAL] %s candidate list truncated at %d addresses",
                           tcp_family_name(family), TCP_CONNECT_MAX_ADDRS);
            break;
        }

        char address[INET6_ADDRSTRLEN + 24] = {0};
        tcp_format_address(rp->ai_addr, address, sizeof(address));
        if (tcp_address_is_excluded(address, excluded_addresses, excluded_count)) {
            if (g_tcp_dial_debug)
                log_yellow("[TCP-DIAL] skipping previously failed TLS endpoint %s", address);
            continue;
        }

        candidates[count].ai = rp;
        snprintf(candidates[count].address, sizeof(candidates[count].address),
                 "%s", address);
        count++;
    }

    if (count == 0) {
        last_error = EADDRNOTAVAIL;
        if (last_errno_out) *last_errno_out = last_error;
        errno = last_error;
        if (connected_address && connected_address_size) connected_address[0] = '\0';
        return -1;
    }

    if (g_tcp_dial_debug)
        log_blue("[TCP-DIAL] racing %zu %s address(es), timeout=%d ms",
                 count, tcp_family_name(family), TCP_CONNECT_FAMILY_TIMEOUT_MS);

    for (size_t index = 0; index < count; index++) {
        const struct addrinfo *rp = candidates[index].ai;
        const char *target = candidates[index].address;
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            last_error = errno;
            log_yellow("[TCP-DIAL] socket %s failed: %s (%d)",
                       target, strerror(last_error), last_error);
            continue;
        }

        tune_tcp_socket(fd);
        if (set_nonblock(fd, 1) < 0) {
            last_error = errno;
            log_yellow("[TCP-DIAL] nonblock %s failed: %s (%d)",
                       target, strerror(last_error), last_error);
            close(fd);
            continue;
        }

        int cr = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (cr == 0) {
            for (size_t j = 0; j < count; j++) {
                if (j != index) close_connect_fd(&candidates[j].fd);
            }
            if (connected_address && connected_address_size)
                snprintf(connected_address, connected_address_size, "%s", target);
            if (last_errno_out) *last_errno_out = 0;
            errno = 0;
            return fd;
        }

        int connect_error = errno;
        if (connect_error == EINPROGRESS || connect_error == EALREADY ||
            connect_error == EINTR || connect_error == EWOULDBLOCK) {
            candidates[index].fd = fd;
            pfds[index].fd = fd;
            active++;
        } else {
            last_error = connect_error;
            log_yellow("[TCP-DIAL] connect %s failed: %s (%d)",
                       target, strerror(last_error), last_error);
            close(fd);
        }
    }

    if (active > 0) {
        for (;;) {
            long long remaining = deadline_ms - now_ms();
            if (remaining <= 0) { last_error = ETIMEDOUT; break; }
            int timeout_ms = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int rc = poll(pfds, (nfds_t)count, timeout_ms);
            if (rc < 0) {
                if (errno == EINTR) continue;
                last_error = errno;
                break;
            }
            if (rc == 0) { last_error = ETIMEDOUT; break; }

            for (size_t i = 0; i < count; i++) {
                if (candidates[i].fd < 0 || pfds[i].revents == 0) continue;

                int candidate_error = 0;
                socklen_t error_size = sizeof(candidate_error);
                if (pfds[i].revents & POLLNVAL) {
                    candidate_error = EBADF;
                } else if (getsockopt(candidates[i].fd, SOL_SOCKET, SO_ERROR,
                                      &candidate_error, &error_size) < 0) {
                    candidate_error = errno;
                } else if (candidate_error == 0 &&
                           (pfds[i].revents & POLLOUT) &&
                           !(pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                    int winner = candidates[i].fd;
                    candidates[i].fd = -1;
                    for (size_t j = 0; j < count; j++)
                        close_connect_fd(&candidates[j].fd);
                    if (connected_address && connected_address_size)
                        snprintf(connected_address, connected_address_size, "%s",
                                 candidates[i].address);
                    if (last_errno_out) *last_errno_out = 0;
                    errno = 0;
                    return winner;
                } else if (candidate_error == 0) {
                    candidate_error = ECONNRESET;
                }

                last_error = candidate_error;
                log_yellow("[TCP-DIAL] connect %s failed: %s (%d)",
                           candidates[i].address, strerror(last_error), last_error);
                close_connect_fd(&candidates[i].fd);
                pfds[i].fd = -1;
                pfds[i].revents = 0;
                active--;
            }
            if (active == 0) break;
        }
    }

    if (last_error == ETIMEDOUT) {
        for (size_t i = 0; i < count; i++) {
            if (candidates[i].fd >= 0)
                log_yellow("[TCP-DIAL] connect %s timed out after %d ms",
                           candidates[i].address, TCP_CONNECT_FAMILY_TIMEOUT_MS);
        }
    }
    for (size_t i = 0; i < count; i++)
        close_connect_fd(&candidates[i].fd);

    if (last_errno_out) *last_errno_out = last_error;
    errno = last_error;
    if (connected_address && connected_address_size) connected_address[0] = '\0';
    return -1;
}

static int tcp_connect_host_excluding(const char *host, const char *port,
                                      const char *const *excluded_addresses,
                                      size_t excluded_count,
                                      char *connected_address_out,
                                      size_t connected_address_out_size) {
    const int families[] = {AF_INET, AF_INET6};
    const char *family_names[] = {"A/IPv4", "AAAA/IPv6"};
    int last_error = EHOSTUNREACH;
    long long total_started = now_ms();

    if (connected_address_out && connected_address_out_size)
        connected_address_out[0] = '\0';

    for (size_t family_index = 0; family_index < 2 && !stop_requested(); family_index++) {
        int family = families[family_index];
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;

        long long dns_started = now_ms();
        int rc = g_tcp_getaddrinfo(host, port, &hints, &res);
        long long dns_elapsed = now_ms() - dns_started;
        if (rc != 0 || !res) {
            if (rc == EAI_SYSTEM && errno != 0) last_error = errno;
            log_yellow("[TCP-DIAL] DNS %s lookup for %s:%s failed after %lld ms: %s (%d)",
                       family_names[family_index], host, port, dns_elapsed,
                       rc != 0 ? gai_strerror(rc) : "empty address list", rc);
            if (res) freeaddrinfo(res);
            continue;
        }

        size_t addresses = 0;
        for (struct addrinfo *rp = res; rp; rp = rp->ai_next)
            if (rp->ai_family == family) addresses++;

        if (g_tcp_dial_debug)
            log_blue("[TCP-DIAL] DNS %s returned %zu address(es) for %s:%s in %lld ms",
                     family_names[family_index], addresses, host, port, dns_elapsed);

        char family_connected_address[INET6_ADDRSTRLEN + 24] = {0};
        int family_error = 0;
        long long connect_started = now_ms();
        int fd = tcp_connect_addrinfo_list(
            res, family, connect_started + TCP_CONNECT_FAMILY_TIMEOUT_MS,
            excluded_addresses, excluded_count,
            family_connected_address, sizeof(family_connected_address), &family_error);
        long long connect_elapsed = now_ms() - connect_started;
        freeaddrinfo(res);

        if (fd >= 0) {
            char local_address[INET6_ADDRSTRLEN + 24] = "unknown";
            struct sockaddr_storage local_sa;
            socklen_t local_len = sizeof(local_sa);
            if (getsockname(fd, (struct sockaddr *)&local_sa, &local_len) == 0)
                tcp_format_address((struct sockaddr *)&local_sa, local_address, sizeof(local_address));
            if (connected_address_out && connected_address_out_size)
                snprintf(connected_address_out, connected_address_out_size, "%s",
                         family_connected_address);
            if (g_tcp_dial_debug)
                log_blue("[TCP-DIAL] connected family=%s remote=%s local=%s connect=%lld ms total=%lld ms",
                         family_names[family_index],
                         family_connected_address[0] ? family_connected_address : host,
                         local_address, connect_elapsed, now_ms() - total_started);
            errno = 0;
            return fd;
        }

        last_error = family_error ? family_error : (errno ? errno : EHOSTUNREACH);
        log_red("[TCP-DIAL] %s candidates for %s:%s failed after %lld ms; last error: %s (%d)",
                family_names[family_index], host, port, connect_elapsed,
                strerror(last_error), last_error);
    }

    errno = last_error;
    log_red("[TCP-DIAL] failed to connect %s:%s after %lld ms; final error: %s (%d)",
            host, port, now_ms() - total_started, strerror(last_error), last_error);
    return -1;
}

static int tcp_connect_host(const char *host, const char *port) {
    return tcp_connect_host_excluding(host, port, NULL, 0, NULL, 0);
}

/* ============================================================
 * SOCKS5 & EPOLL MULTIPLEXER
 * ============================================================ */
static void update_epoll(int epfd, int fd, void *ptr, uint32_t *cur_ev, uint32_t want_ev) {
    if (fd < 0 || *cur_ev == want_ev) return;
    struct epoll_event ev = { .events = want_ev, .data.ptr = ptr };
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) == 0) {
        *cur_ev = want_ev;
    }
}

static void update_client_epoll(int epfd, client_conn_t *c, uint32_t want_ev) {
    if (c->fd < 0) return;
    struct epoll_event ev = { .events = want_ev,
                               .data.u64 = client_event_token_encode(c->client_id) };
    if (!c->in_epoll) {
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ev) == 0) {
            c->in_epoll = 1;
            c->epoll_events = want_ev;
        } else if (g_log_perf) {
            g_perf_stats.epoll_ctl_add_fail++;
            g_perf_stats.epoll_ctl_last_errno = errno;
        }
    } else if (c->epoll_events != want_ev) {
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) == 0) {
            c->epoll_events = want_ev;
        } else if (g_log_perf) {
            g_perf_stats.epoll_ctl_mod_fail++;
            g_perf_stats.epoll_ctl_last_errno = errno;
        }
    }
}

static void suspend_client_epoll(int epfd, client_conn_t *c) {
    if (c->fd >= 0 && c->in_epoll) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        c->in_epoll = 0;
        c->epoll_events = 0;
    }
}

static void detach_client_fd(int epfd, client_conn_t *c) {
    if (c->fd >= 0) {
        if (c->in_epoll) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
            c->in_epoll = 0;
        }
        c->epoll_events = 0;
        /* Both directions may hold tasks against this same descriptor. */
        if (c->lifetime.worker_refs != 0U) {
            c->fd_close_pending = 1;
        } else {
            close(c->fd);
            c->fd = -1;
            c->fd_close_pending = 0;
        }
    }
    c->close_after_ctrl = 0;
    c->ctrl_len = 0;
    c->ctrl_off = 0;
    c->ctrl_close_deadline_ms = 0;
}

static void set_client_cleanup_deadline(client_conn_t *c) {
    if (c && c->cleanup_deadline_ms == 0)
        c->cleanup_deadline_ms = now_ms() + SSH_CHANNEL_CLEANUP_TIMEOUT_MS;
}

static void unlink_client_from_active_list(client_conn_t *c) {
    if (c->prev) c->prev->next = c->next;
    else g_clients = c->next;
    if (c->next) c->next->prev = c->prev;
    c->prev = NULL;
    c->next = NULL;
    if (g_client_count > 0) g_client_count--;
    release_client_slot();
}

static int free_client_storage(client_conn_t *c) {
    if (!c) {
        errno = EINVAL;
        return -1;
    }

    /* Callers must finalize before detaching the FD or releasing storage. */
    if (!c->lifetime.finalized) {
        errno = EBUSY;
        return -1;
    }

    rb_free(&c->c2s);
    rb_free(&c->s2c);
    free(c);
    return 0;
}

/* Retired clients are reaped only by the SSH Owner after all task references
 * have been released by their completion records. A failed finalization
 * leaves the complete object (including its FD and rings) on the retired list. */
static void reap_retired_clients(int epfd) {
    client_conn_t **link = &g_retired_clients;
    while (*link) {
        client_conn_t *c = *link;
        if (c->lifetime.worker_refs != 0U) {
            link = &c->retired_next;
            continue;
        }
        if (client_lifetime_finalize(&c->lifetime) < 0) {
            link = &c->retired_next;
            continue;
        }

        *link = c->retired_next;
        c->retired_next = NULL;
        detach_client_fd(epfd, c);
        rb_free(&c->c2s);
        rb_free(&c->s2c);
        free(c);
    }
}

static void remove_client(int epfd, client_conn_t *c) {
    if (!c) return;
    if (g_opening_client == c) g_opening_client = NULL;
    if (g_pending_client == c) clear_pending_operation();

    if (!c->lifetime.close_requested)
        (void)client_lifetime_request_close(&c->lifetime);

    /* Unlink first: no further epoll event may resolve this client as active. */
    unlink_client_from_active_list(c);
    if (c->lifetime.worker_refs != 0U) {
        /* Keep the FD and both rings alive until every worker acknowledges. */
        if (c->fd >= 0 && c->in_epoll) {
            (void)epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
            c->in_epoll = 0;
            c->epoll_events = 0;
        }
        c->retired_next = g_retired_clients;
        g_retired_clients = c;
        return;
    }

    if (client_lifetime_finalize(&c->lifetime) < 0) {
        /* Retired objects must never remain registered in epoll: their
         * identity is no longer active, and a stale FD event must not spin. */
        if (c->fd >= 0 && c->in_epoll) {
            (void)epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
            c->in_epoll = 0;
            c->epoll_events = 0;
        }
        c->retired_next = g_retired_clients;
        g_retired_clients = c;
        return;
    }
    detach_client_fd(epfd, c);
    (void)free_client_storage(c);
}

static void start_closing_client(int epfd, client_conn_t *c) {
    if (!c) return;
    if (!c->lifetime.close_requested)
        (void)client_lifetime_request_close(&c->lifetime);
    /* A pending channel OPEN follows SSH_OPEN_HARD_TO_MS, not the shorter
     * channel cleanup budget. Keep retrying the same open until it resolves
     * or the existing 30-second hard deadline restarts the session. */
    if (c == g_opening_client && c == g_pending_client &&
        g_pending_op == PENDING_OPEN) {
        c->abort_on_open = 1;
        c->cleanup_deadline_ms = 0;
        detach_client_fd(epfd, c);
        return;
    }
    if (c == g_pending_client && g_pending_op != PENDING_NONE) {
        c->abort_on_pending = 1;
        set_client_cleanup_deadline(c);
        detach_client_fd(epfd, c);
        return;
    }
    /* libssh2 channel_write may have built a packet before an SSL callback
     * returned WANT_READ. Its buffer must remain pinned until the same write
     * succeeds; only the explicit zero-window wait is safe to discard. */
    if (c->channel && c->write_pending && !c->write_waiting_window) {
        c->abort_on_pending = 1;
        set_client_cleanup_deadline(c);
        detach_client_fd(epfd, c);
        return;
    }
    if (c == g_opening_client && !c->channel) {
        /* The channel-open hard timeout owns this lifetime (30 seconds). */
        c->abort_on_open = 1;
        detach_client_fd(epfd, c);
        return;
    }
    /* A channel read EAGAIN and a zero-window write wait do not retain an
     * application buffer in libssh2. Active writes are pinned by the guard
     * above even when their TLS callback is waiting for inbound readiness. */
    detach_client_fd(epfd, c);
    if (c->channel) {
        c->write_pending = 0;
        c->write_pending_head = 0;
        c->write_pending_generation = 0;
        c->write_pending_len = 0;
        c->write_waiting_window = 0;
        c->write_wait_rx_seq = 0;
        log_channel_buffer_final(c);
        log_s2c_buffer_final(c);
    }
    if (c->lifetime.worker_refs == 0U) {
        rb_free(&c->c2s);
        rb_free(&c->s2c);
    }
    set_client_cleanup_deadline(c);
    c->state = ST_CLOSING;
}

static int client_read_epoll_allowed(const client_conn_t *c) {
    return c && c->fd >= 0 && !c->client_eof && !c->client_dead &&
           !c->hup_pending && !c->rdhup_pending &&
           !c->c2s_worker_inflight && rb_free_space(&c->c2s) > 0U;
}

static uint32_t client_rdhup_flag(const client_conn_t *c) {
    return (!c->client_eof && !c->rdhup_pending && !c->hup_pending && !c->client_dead)
               ? EPOLLRDHUP
               : 0U;
}

static int queue_ctrl_send(int epfd, client_conn_t *c, const uint8_t *data, size_t len) {
    ssize_t sent = 0;
    if (c->ctrl_len == 0) {
        do {
            sent = send(c->fd, data, len, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent == (ssize_t)len) return 0;
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            sent = 0;
        }
    }
    size_t rem = len - (size_t)sent;
    if (c->ctrl_len - c->ctrl_off + rem > sizeof(c->ctrl_buf)) return -1;
    if (c->ctrl_off > 0 && c->ctrl_off < c->ctrl_len) {
        memmove(c->ctrl_buf, c->ctrl_buf + c->ctrl_off, c->ctrl_len - c->ctrl_off);
        c->ctrl_len -= c->ctrl_off;
        c->ctrl_off = 0;
    } else if (c->ctrl_off >= c->ctrl_len) {
        c->ctrl_off = 0;
        c->ctrl_len = 0;
    }
    memcpy(c->ctrl_buf + c->ctrl_len, data + (size_t)sent, rem);
    c->ctrl_len += rem;
    if (!c->hup_pending && !c->client_dead) {
        update_client_epoll(epfd, c, c->epoll_events | EPOLLOUT);
    }
    return 0;
}

static int flush_ctrl_send(int epfd, client_conn_t *c) {
    while (c->ctrl_off < c->ctrl_len) {
        ssize_t n = send(c->fd, c->ctrl_buf + c->ctrl_off, c->ctrl_len - c->ctrl_off, MSG_NOSIGNAL);
        if (n > 0) {
            c->ctrl_off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return -1;
        }
    }
    c->ctrl_off = 0;
    c->ctrl_len = 0;
    if (c->close_after_ctrl) {
        return 2;
    }
    uint32_t want;
    if (c->state == ST_SOCKS_GREETING || c->state == ST_SOCKS_REQUEST) {
        want = EPOLLIN | client_rdhup_flag(c);
    } else {
        want = (c->epoll_events & ~(uint32_t)EPOLLOUT);
        if (c->state == ST_RELAY && c->s2c.used > 0)
            want |= EPOLLOUT;
    }
    if (!c->hup_pending && !c->client_dead) {
        update_client_epoll(epfd, c, want);
    }
    return 1;
}

static void send_ctrl_err_and_close(int epfd, client_conn_t *c, const uint8_t *msg, size_t len) {
    if (c->fd < 0 || c->hup_pending || c->client_dead) {
        start_closing_client(epfd, c);
        return;
    }
    if (queue_ctrl_send(epfd, c, msg, len) < 0 || c->ctrl_len == 0) {
        start_closing_client(epfd, c);
        return;
    }
    c->close_after_ctrl = 1;
    c->ctrl_close_deadline_ms = now_ms() + 3000;
    update_client_epoll(epfd, c, EPOLLOUT | client_rdhup_flag(c));
}

static void send_socks_err_and_close(int epfd, client_conn_t *c, uint8_t rep_code) {
    uint8_t err_rep[10] = {0x05, rep_code, 0x00, 0x01, 0,0,0,0, 0,0};
    send_ctrl_err_and_close(epfd, c, err_rep, sizeof(err_rep));
}

static void reject_nonrelay_clients_on_upstream_hup(int epfd) {
    static const uint8_t no_methods[2] = {0x05, 0xFF};

    for (client_conn_t *c = g_clients, *next = NULL; c; c = next) {
        next = c->next;
        if (c->fd < 0 || c->close_after_ctrl || c->client_dead) continue;

        if (c->state == ST_SOCKS_GREETING) {
            if (c->req_len >= 2 && c->req_buf[0] == 0x05)
                send_ctrl_err_and_close(epfd, c, no_methods, sizeof(no_methods));
            else
                start_closing_client(epfd, c);
            continue;
        }

        if (c->state == ST_SOCKS_REQUEST) {
            send_socks_err_and_close(epfd, c, 0x05);
            continue;
        }

        if (c->state == ST_SSH_OPENING &&
            !(c == g_pending_client && g_pending_op == PENDING_OPEN)) {
            c->abort_on_open = 1;
            if (g_opening_client == c) g_opening_client = NULL;
            send_socks_err_and_close(epfd, c, 0x05);
        }
    }
}

static int send_from_rb(int fd, rb_t *r, int keep_pos) {
    while (r->used > 0) {
        size_t avail = 0;
        const uint8_t *ptr = rb_read_slice(r, &avail);
        if (!ptr || avail == 0) break;
        ssize_t n = send(fd, ptr, avail, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (g_log_perf) g_perf_stats.socks_tx_calls++;
        if (n > 0) {
            if (g_log_perf) g_perf_stats.socks_tx_bytes += (uint64_t)n;
            if (rb_commit_read(r, (size_t)n, keep_pos) < 0) return -1;
            if ((size_t)n < avail) {
                if (g_log_perf) g_perf_stats.socks_tx_partial++;
                break;
            }
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (g_log_perf) g_perf_stats.socks_tx_eagain++;
            return 0;
        } else {
            return -1;
        }
    }
    return 1;
}

/* Kuras socket sampai buffer penuh, EOF (n == 0), atau EAGAIN */
static int recv_to_rb(int fd, rb_t *r, int *eof_out, int *would_block_out) {
    *eof_out = 0;
    *would_block_out = 0;
    while (rb_free_space(r) > 0) {
        size_t avail = 0;
        uint8_t *ptr = rb_write_slice(r, &avail);
        if (!ptr || avail == 0) break;
        ssize_t n = recv(fd, ptr, avail, 0);
        if (n > 0) {
            if (rb_commit_write(r, (size_t)n) < 0) return -1;
            continue;
        }
        if (n == 0) {
            *eof_out = 1;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *would_block_out = 1;
            break;
        }
        return -1;
    }
    return 0;
}

/* Kuras sisa socket untuk koneksi yang sebelumnya mengalami HUP/RDHUP saat c2s penuh */
static int drain_pending_eof_to_c2s(int epfd, client_conn_t *c) {
    if (!(c->hup_pending || c->rdhup_pending) || c->client_eof || c->fd < 0 ||
        c->c2s_worker_inflight) return 0;
    if (rb_free_space(&c->c2s) == 0) return 0;
    size_t before = c->c2s.used;
    int eof_hit = 0, would_block = 0;
    int rc = recv_to_rb(c->fd, &c->c2s, &eof_hit, &would_block);
    note_c2s_buffer_peak(c);
    if (c->c2s.used > before) {
        size_t received = c->c2s.used - before;
        c->last_activity_ms = now_ms();
        if (g_log_perf) {
            g_perf_stats.c2s_rx_bytes += received;
            if (c->ssh_eof) g_perf_stats.c2s_post_eof_rx_bytes += received;
        }
        if (c->ssh_eof && g_log_backpressure)
            log_blue("C2S bytes received after remote EOF (%s:%u; added=%zu queued=%zu; client_eof=%d)",
                     c->target_host, (unsigned)c->target_port, received,
                     c->c2s.used, c->client_eof);
    }
    if (rc < 0) {
        c->client_eof = 1; c->need_send_eof = 1; c->client_dead = 1;
        c->client_reset = 1;
        c->hup_pending = 0; c->rdhup_pending = 0;
        detach_client_fd(epfd, c);
    } else if (eof_hit) {
        c->client_eof = 1; c->need_send_eof = 1;
        if (c->hup_pending) {
            c->client_dead = 1;
            detach_client_fd(epfd, c);
        }
        c->hup_pending = 0; c->rdhup_pending = 0;
    } else if (would_block) {
        /* EAGAIN preserves pending drain, it is not EOF. */
    }
    return (c->c2s.used > before || c->client_eof) ? 1 : 0;
}

static void settle_c2s_hup_eagain(int epfd, client_conn_t *c) {
    if (!c || c->client_eof ||
        (!c->hup_pending && !c->rdhup_pending)) return;
    c->client_eof = 1;
    c->need_send_eof = 1;
    if (c->hup_pending) {
        c->client_dead = 1;
        detach_client_fd(epfd, c);
    }
    c->hup_pending = 0;
    c->rdhup_pending = 0;
}

static uint64_t allocate_io_task_id(void) {
    uint64_t id = g_next_io_task_id++;
    if (id == 0U) id = g_next_io_task_id++;
    return id;
}

/* Owner pins the FD/client lifetime before publishing a copied socket-read task. */
/* Roll back the Owner-side task/lifetime transaction when publication
 * fails. Never silently discard either invariant failure: retaining a
 * reference is safer than freeing a client that may still be referenced. */
static int rollback_io_worker_registration(
    client_conn_t *c,
    io_worker_completion_tracker_t *tracker,
    const io_worker_task_ref_t *ref)
{
    if (io_worker_completion_tracker_cancel(tracker, ref) < 0) {
        int saved_errno = errno;
        log_red("[IO worker] task registration rollback failed task=%llu: %s",
                (unsigned long long)ref->task_id, strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
    if (client_lifetime_release(&c->lifetime, ref->client_id,
                                ref->generation) < 0) {
        int saved_errno = errno;
        log_red("[IO worker] lifetime rollback failed task=%llu: %s",
                (unsigned long long)ref->task_id, strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int submit_c2s_worker_read(io_worker_pool_t *pool,
                                  io_worker_completion_tracker_t *tracker,
                                  client_conn_t *c) {
    if (!pool || !tracker || !c || c->fd < 0 || c->c2s_worker_inflight ||
        c->client_eof || rb_free_space(&c->c2s) == 0U) {
        errno = EINVAL;
        return -1;
    }
    uint32_t worker_id = 0U;
    if (io_worker_pool_select_worker(pool, &worker_id) < 0)
        return errno == EAGAIN ? 1 : -1;

    size_t contiguous = 0U;
    (void)rb_write_slice(&c->c2s, &contiguous);
    if (contiguous == 0U) return 1;
    if (contiguous > IO_WORKER_POOL_PAYLOAD_SIZE) contiguous = IO_WORKER_POOL_PAYLOAD_SIZE;

    io_worker_task_t task;
    memset(&task, 0, sizeof(task));
    task.task_id = allocate_io_task_id();
    task.client_id = c->client_id;
    task.generation = c->generation;
    task.opcode = IO_WORKER_OP_SOCKET_READ;
    task.payload_len = 8U;
    int32_t fd_value = (int32_t)c->fd;
    uint32_t length = (uint32_t)contiguous;
    memcpy(task.payload, &fd_value, sizeof(fd_value));
    memcpy(task.payload + sizeof(fd_value), &length, sizeof(length));

    io_worker_task_ref_t ref = {
        .task_id = task.task_id,
        .client_id = task.client_id,
        .generation = task.generation,
        .worker_id = worker_id
    };
    /* Required transaction: lifetime acquire -> tracker register -> publish. */
    if (client_lifetime_acquire(&c->lifetime, c->client_id, c->generation) < 0)
        return -1;
    if (io_worker_completion_tracker_register(tracker, &ref) < 0) {
        if (client_lifetime_release(&c->lifetime, ref.client_id, ref.generation) < 0)
            log_red("[IO worker] lifetime release after tracker registration failure: %s",
                    strerror(errno));
        return -1;
    }
    if (io_worker_pool_submit_to_worker(pool, &task, worker_id) < 0) {
        int saved_errno = errno;
        if (rollback_io_worker_registration(c, tracker, &ref) < 0)
            return -1;
        errno = saved_errno;
        return saved_errno == EAGAIN ? 1 : -1;
    }
    c->c2s_worker_task_id = task.task_id;
    c->c2s_worker_inflight = 1;
    return 0;
}

/*
 * S2C is drained by the single SSH Owner. The accepted client socket is
 * nonblocking and EPOLLOUT is armed while bytes remain, so this path never
 * waits for socket capacity and avoids a worker submit/completion round-trip
 * for every small payload. send_from_rb() drains at most the bounded S2C
 * ring capacity before returning on EAGAIN.
 */
static int flush_s2c_to_client(int epfd, client_conn_t *c) {
    (void)epfd;
    if (!c || c->fd < 0 || c->ctrl_len > 0U || c->s2c.used == 0U)
        return 0;

    size_t before = c->s2c.used;
    uint64_t tx_started_ns = g_log_perf ? perf_now_ns() : 0;
    int tx_rc = send_from_rb(c->fd, &c->s2c, 0);
    if (g_log_perf) {
        g_perf_stats.socks_tx_flush_calls++;
        if (tx_started_ns != 0) {
            uint64_t tx_ended_ns = perf_now_ns();
            if (tx_ended_ns >= tx_started_ns)
                g_perf_stats.socks_tx_ns += tx_ended_ns - tx_started_ns;
        }
    }
    if (tx_rc < 0) return -1;

    if (c->s2c.used < before)
        c->last_activity_ms = now_ms();
    if (c->s2c.used == 0U && c->ssh_eof)
        (void)shutdown(c->fd, SHUT_WR);
    return 0;
}

static int drain_socks_req_buf(client_conn_t *c, int *eof_out) {
    *eof_out = 0;
    while (c->req_len < sizeof(c->req_buf)) {
        ssize_t n = recv(c->fd, c->req_buf + c->req_len, sizeof(c->req_buf) - c->req_len, 0);
        if (n > 0) {
            c->req_len += (size_t)n;
            continue;
        }
        if (n == 0) {
            *eof_out = 1;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }
    return 0;
}

static void handle_client_io(int epfd, client_conn_t *c, uint32_t events) {
    if (c->state == ST_CLOSING || c->fd < 0) return;

    if ((events & EPOLLOUT) && c->ctrl_len > 0) {
        int frc = flush_ctrl_send(epfd, c);
        if (frc < 0 || frc == 2) {
            start_closing_client(epfd, c);
            return;
        }
    }

    if (c->close_after_ctrl) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            start_closing_client(epfd, c);
        } else if ((events & EPOLLRDHUP) && c->state != ST_SSH_OPENING) {
            start_closing_client(epfd, c);
        } else if (events & EPOLLRDHUP) {
            c->rdhup_pending = 1;
            update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U));
        }
        return;
    }

    if (c->state == ST_SOCKS_GREETING) {
        int eof_hit = 0;
        if (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) {
            if (drain_socks_req_buf(c, &eof_hit) < 0) {
                remove_client(epfd, c);
                return;
            }
            if (c->req_len >= 2) {
                if (c->req_buf[0] != 0x05 || c->req_buf[1] == 0) {
                    remove_client(epfd, c);
                    return;
                }
                size_t need = 2 + (size_t)c->req_buf[1];
                if (c->req_len >= need) {
                    int has_noauth = 0;
                    for (size_t i = 2; i < need; i++) {
                        if (c->req_buf[i] == 0x00) { has_noauth = 1; break; }
                    }
                    if (!has_noauth) {
                        uint8_t deny[2] = {0x05, 0xFF};
                        send_ctrl_err_and_close(epfd, c, deny, sizeof(deny));
                        return;
                    }
                    uint8_t reply[2] = {0x05, 0x00};
                    if (queue_ctrl_send(epfd, c, reply, 2) < 0) {
                        remove_client(epfd, c);
                        return;
                    }
                    if (c->req_len > need) {
                        memmove(c->req_buf, c->req_buf + need, c->req_len - need);
                        c->req_len -= need;
                    } else {
                        c->req_len = 0;
                    }
                    c->state = ST_SOCKS_REQUEST;
                }
            }
        }
        if (c->state == ST_SOCKS_GREETING && (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)))) {
            remove_client(epfd, c);
            return;
        }
    }

    if (c->state == ST_SOCKS_REQUEST) {
        int eof_hit = 0;
        if ((events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) && c->req_len < sizeof(c->req_buf)) {
            if (drain_socks_req_buf(c, &eof_hit) < 0) {
                remove_client(epfd, c);
                return;
            }
        }
        if (c->req_len < 4) {
            if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
            return;
        }
        if (c->req_buf[0] != 0x05 || c->req_buf[1] != 0x01) {
            send_socks_err_and_close(epfd, c, 0x07);
            return;
        }
        if (!socks5_reserved_valid(c->req_buf, c->req_len)) {
            send_socks_err_and_close(epfd, c, 0x01);
            return;
        }
        uint8_t atyp = c->req_buf[3];
        size_t need = 0;
        if (atyp == 0x01) {
            need = 10;
        } else if (atyp == 0x03) {
            if (c->req_len < 5) {
                if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
                return;
            }
            if (c->req_buf[4] == 0) {
                send_socks_err_and_close(epfd, c, 0x01);
                return;
            }
            need = 5 + (size_t)c->req_buf[4] + 2;
        } else if (atyp == 0x04) {
            need = 22;
        } else {
            send_socks_err_and_close(epfd, c, 0x08);
            return;
        }

        if (c->req_len < need) {
            if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
            return;
        }

        if (atyp == 0x03 && !socks5_domain_valid(c->req_buf, c->req_len)) {
            send_socks_err_and_close(epfd, c, 0x01);
            return;
        }

        if (events & (EPOLLERR | EPOLLHUP)) {
            remove_client(epfd, c);
            return;
        }

        if (atyp == 0x01) {
            inet_ntop(AF_INET, c->req_buf + 4, c->target_host, sizeof(c->target_host));
            c->target_port = (uint16_t)(((unsigned)c->req_buf[8] << 8) | (unsigned)c->req_buf[9]);
        } else if (atyp == 0x03) {
            size_t dlen = c->req_buf[4];
            memcpy(c->target_host, c->req_buf + 5, dlen);
            c->target_host[dlen] = '\0';
            c->target_port = (uint16_t)(((unsigned)c->req_buf[5 + dlen] << 8) | (unsigned)c->req_buf[6 + dlen]);
        } else {
            inet_ntop(AF_INET6, c->req_buf + 4, c->target_host, sizeof(c->target_host));
            c->target_port = (uint16_t)(((unsigned)c->req_buf[20] << 8) | (unsigned)c->req_buf[21]);
        }

        if (c->target_port == 0) {
            send_socks_err_and_close(epfd, c, 0x01);
            return;
        }

        if (c->req_len > need) {
            size_t rem = c->req_len - need;
            if (rem > sizeof(c->early_buf)) rem = sizeof(c->early_buf);
            memcpy(c->early_buf, c->req_buf + need, rem);
            c->early_len = rem;
        }
        c->req_len = 0;
        c->state = ST_SSH_OPENING;
        c->open_started_ms = 0;
        if (eof_hit) {
            c->client_eof = 1;
            c->need_send_eof = 1;
            c->rdhup_pending = 0;
        } else if (events & EPOLLRDHUP) {
            c->rdhup_pending = 1;
        }
        update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U) | client_rdhup_flag(c));
        return;
    }

    if (c->state == ST_SSH_OPENING) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            start_closing_client(epfd, c);
            return;
        }
        if (events & EPOLLRDHUP) {
            if (!c->client_eof) c->rdhup_pending = 1;
            update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U));
        }
        return;
    }

    if (c->state == ST_RELAY) {
        int eof_hit = 0;
        int would_block = 0;
        int recv_rc = 0;
        if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) &&
            !c->client_eof && !c->c2s_worker_inflight &&
            rb_free_space(&c->c2s) > 0) {
            if (events & (EPOLLHUP | EPOLLERR)) c->hup_pending = 1;
            else if (events & EPOLLRDHUP) c->rdhup_pending = 1;
            int submit_rc = submit_c2s_worker_read(g_io_pool, g_io_tracker, c);
            if (submit_rc == 1) {
                /* Only temporary queue pressure may use the bounded Owner fallback. */
                size_t c2s_before = c->c2s.used;
                recv_rc = recv_to_rb(c->fd, &c->c2s, &eof_hit, &would_block);
                note_c2s_buffer_peak(c);
                if (recv_rc < 0) {
                    c->client_eof = 1;
                    c->need_send_eof = 1;
                    c->client_dead = 1;
                    c->client_reset = 1;
                    c->hup_pending = 0;
                    c->rdhup_pending = 0;
                    detach_client_fd(epfd, c);
                } else if (eof_hit) {
                    c->client_eof = 1;
                    c->need_send_eof = 1;
                    c->hup_pending = 0;
                    c->rdhup_pending = 0;
                }
                if (c->c2s.used > c2s_before) {
                    size_t received = c->c2s.used - c2s_before;
                    c->last_activity_ms = now_ms();
                    if (g_log_perf) {
                        g_perf_stats.c2s_rx_bytes += received;
                        if (c->ssh_eof) g_perf_stats.c2s_post_eof_rx_bytes += received;
                    }
                }
            } else if (submit_rc < 0) {
                log_red("[IO worker] fatal C2S submit invariant: %s", strerror(errno));
                c->client_dead = 1;
                c->client_reset = 1;
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            }
        }

        if (c->fd >= 0 && (events & EPOLLOUT) && c->ctrl_len == 0 &&
            c->s2c.used > 0) {
            if (flush_s2c_to_client(epfd, c) < 0) {
                c->client_dead = 1;
                c->client_reset = 1;
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            }
        }

        if (c->fd >= 0 && (events & (EPOLLERR | EPOLLHUP)) && !c->client_dead) {
            if (c->client_eof || eof_hit || recv_rc < 0) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->client_dead = 1;
                if (recv_rc < 0) c->client_reset = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            } else {
                /* Buffer c2s penuh saat HUP/ERR: cabut fd dari epoll agar tidak CPU spin,
                 * tetapi pertahankan fd tetap terbuka untuk dikuras di pump_ssh_channels. */
                c->hup_pending = 1;
                c->rdhup_pending = 0;
                suspend_client_epoll(epfd, c);
            }
        } else if (c->fd >= 0 && (events & EPOLLRDHUP) && !c->client_eof) {
            if (eof_hit || recv_rc < 0) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->rdhup_pending = 0;
            } else {
                c->rdhup_pending = 1;
            }
        }

        if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
            uint32_t want = client_rdhup_flag(c);
            if (client_read_epoll_allowed(c)) want |= EPOLLIN;
            if ((c->s2c.used > 0) ||
                c->ctrl_len > 0) want |= EPOLLOUT;
            update_client_epoll(epfd, c, want);
        }

        if (client_dead_ready_to_close(c)) {
            c->need_send_eof = 0;
            start_closing_client(epfd, c);
            return;
        }
        if (c->client_eof && c->ssh_eof && c->c2s.used == 0 &&
            c->s2c.used == 0 && !c->need_send_eof) {
            start_closing_client(epfd, c);
            return;
        }
    }
}

static int drain_io_worker_completions(int epfd,
                                          io_worker_pool_t *pool,
                                          io_worker_completion_tracker_t *tracker) {
    if (!pool || !tracker) return 0;
    uint32_t workers = io_worker_pool_worker_count(pool);
    io_worker_completion_t completions[32];
    for (uint32_t worker_id = 0U; worker_id < workers; worker_id++) {
        for (;;) {
            size_t count = io_worker_pool_drain_completions(
                pool, worker_id, completions,
                sizeof(completions) / sizeof(completions[0]));
            if (count == 0U) break;
            for (size_t i = 0U; i < count; i++) {
                io_worker_completion_t *completion = &completions[i];
                io_worker_task_ref_t ref;
                if (io_worker_completion_tracker_take(tracker, completion, &ref) < 0) {
                    int tracker_error = errno;
                    if (tracker_error == ENOENT) {
                        /* A duplicate completion was already consumed. */
                        log_yellow("[IO worker] ignored duplicate/stale completion task=%llu",
                                   (unsigned long long)completion->task_id);
                        continue;
                    }
                    log_red("[IO worker] completion identity invariant failed task=%llu: %s",
                            (unsigned long long)completion->task_id,
                            strerror(tracker_error));
                    return -1;
                }
                client_conn_t *c = find_client_any_by_id(ref.client_id);
                if (!c || c->generation != ref.generation) {
                    log_red("[IO worker] accepted task has no retained client: task=%llu client=%llu generation=%llu; stopping",
                            (unsigned long long)ref.task_id,
                            (unsigned long long)ref.client_id,
                            (unsigned long long)ref.generation);
                    return -1;
                }

                int current = client_lifetime_completion_current(
                    &c->lifetime, ref.client_id, ref.generation);
                int release_rc = client_lifetime_release(
                    &c->lifetime, ref.client_id, ref.generation);
                if (release_rc < 0) {
                    int release_error = errno;
                    log_red("[IO worker] lifetime release invariant failed task=%llu: %s",
                            (unsigned long long)ref.task_id, strerror(release_error));
                    return -1;
                }
                if (c->lifetime.worker_refs == 0U && c->fd_close_pending)
                    detach_client_fd(epfd, c);

                if (c->c2s_worker_task_id == ref.task_id) {
                    c->c2s_worker_task_id = 0U;
                c->c2s_worker_inflight = 0;
                if (!current || c->state != ST_RELAY || c->fd < 0 ||
                    c->fd_close_pending || c->client_dead)
                    continue;

                if (completion->status == 0) {
                    if (completion->result_len > 0U) {
                        if (completion->result_len > IO_WORKER_POOL_PAYLOAD_SIZE ||
                            completion->result_len > rb_free_space(&c->c2s) ||
                            rb_push(&c->c2s, completion->result,
                                    completion->result_len) < 0) {
                            c->client_dead = 1;
                            c->client_reset = 1;
                            c->client_eof = 1;
                            c->need_send_eof = 1;
                            detach_client_fd(epfd, c);
                        } else {
                            c->last_activity_ms = now_ms();
                            note_c2s_buffer_peak(c);
                            if (g_log_perf) {
                                g_perf_stats.c2s_rx_bytes += completion->result_len;
                                if (c->ssh_eof)
                                    g_perf_stats.c2s_post_eof_rx_bytes += completion->result_len;
                            }
                        }
                    } else {
                        c->client_eof = 1;
                        c->need_send_eof = 1;
                        if (c->hup_pending) {
                            c->client_dead = 1;
                            detach_client_fd(epfd, c);
                        }
                        c->hup_pending = 0;
                        c->rdhup_pending = 0;
                    }
                } else if (completion->status != EAGAIN &&
                           completion->status != EWOULDBLOCK) {
                    c->client_eof = 1;
                    c->need_send_eof = 1;
                    c->client_dead = 1;
                    c->client_reset = 1;
                    c->hup_pending = 0;
                    c->rdhup_pending = 0;
                    detach_client_fd(epfd, c);
                }

                if (completion->status == EAGAIN ||
                    completion->status == EWOULDBLOCK)
                    settle_c2s_hup_eagain(epfd, c);

                if (c->fd >= 0 && c->state == ST_RELAY) {
                    if ((c->hup_pending || c->rdhup_pending) &&
                        completion->status == 0 && completion->result_len > 0U &&
                        !c->client_eof && rb_free_space(&c->c2s) > 0U) {
                        handle_client_io(epfd, c, EPOLLIN |
                            (c->hup_pending ? EPOLLHUP : EPOLLRDHUP));
                    } else {
                        uint32_t want = client_rdhup_flag(c);
                        if (client_read_epoll_allowed(c)) want |= EPOLLIN;
                        if ((c->s2c.used > 0U) ||
                            c->ctrl_len > 0U)
                            want |= EPOLLOUT;
                        update_client_epoll(epfd, c, want);
                    }
                }
                } else {
                    log_red("[IO worker] completion task has no matching direction task=%llu; stopping",
                            (unsigned long long)ref.task_id);
                    return -1;
                }
            }
        }
    }
    reap_retired_clients(epfd);
    return 0;
}

static int is_libssh2_socket_fatal(int err) {
    return (err == LIBSSH2_ERROR_SOCKET_RECV ||
            err == LIBSSH2_ERROR_SOCKET_SEND ||
            err == LIBSSH2_ERROR_SOCKET_DISCONNECT);
}

static void note_upstream_rx_progress(upstream_ctx_t *u, uint64_t rx_before,
                                      int *did_ssh_read) {
    if (u && u->rx_seq != rx_before && did_ssh_read)
        *did_ssh_read = 1;
}

static int tls_want_requires_serial_retry(const upstream_ctx_t *u) {
    (void)u;
    return 0;
}
static void tls_begin_libssh2_call(upstream_ctx_t *u) { (void)u; }
static void tls_finish_libssh2_call(upstream_ctx_t *u, int returned_eagain) {
    (void)u; (void)returned_eagain;
}
/* When RX is terminal, make libssh2 see EAGAIN from its receive callback
 * during a channel read. This lets _libssh2_channel_read() inspect already
 * queued session packets instead of aborting before its packet-list scan.
 * It does not bypass a failed WINDOW_ADJUST send, which happens earlier. */
static ssize_t channel_read_with_rx_flush(upstream_ctx_t *u,
                                          LIBSSH2_CHANNEL *channel,
                                          char *buffer, size_t length) {
    uint64_t read_started_ns = g_log_perf ? perf_now_ns() : 0;
    if (g_log_perf) {
        g_perf_stats.s2c_read_calls++;
        g_perf_s2c_read_depth++;
    }
    int previous = u->rx_flush_eagain;
    u->rx_flush_eagain = 1;
    tls_begin_libssh2_call(u);
    ssize_t rc = libssh2_channel_read(channel, buffer, length);
    if (g_log_perf) {
        if (read_started_ns != 0) {
            uint64_t read_ended_ns = perf_now_ns();
            if (read_ended_ns >= read_started_ns)
                g_perf_stats.s2c_read_ns += read_ended_ns - read_started_ns;
        }
        if (g_perf_s2c_read_depth > 0) g_perf_s2c_read_depth--;
    }
    tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
    u->rx_flush_eagain = previous;
    if (g_log_perf) {
        if (rc > 0) g_perf_stats.s2c_read_bytes += (uint64_t)rc;
        else if (rc == LIBSSH2_ERROR_EAGAIN) g_perf_stats.s2c_read_eagain++;
    }
    return rc;
}

static int keepalive_can_start(const upstream_ctx_t *u, pending_op_t pending_op) {
    (void)u; return pending_op == PENDING_NONE;
}
static int shutdown_io_pending(const upstream_ctx_t *u) {
    (void)u; return has_pending_libssh2_work_for_shutdown();
}

static uint32_t upstream_epoll_interest(const upstream_ctx_t *u,
                                        pending_op_t pending_op,
                                        int agg_dirs,
                                        int *idle_rx_paused,
                                        int opening_client,
                                        int readable_channel,
                                        int window_waiter) {
    if (u && u->upstream_epoll_detached) return 0;
    if (u && u->tls) return EPOLLIN;
    uint32_t want = (u && u->hup_seen) ? 0U : EPOLLRDHUP;
    if (!idle_rx_paused) return want;
    if (pending_op != PENDING_NONE) {
        if (agg_dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) want |= EPOLLOUT;
        if (agg_dirs & LIBSSH2_SESSION_BLOCK_INBOUND) want |= EPOLLIN;
        if (window_waiter) want |= EPOLLIN;
        if ((want & (EPOLLIN | EPOLLOUT)) == 0) want |= EPOLLOUT;
    } else {
        int need_read = !*idle_rx_paused || opening_client || readable_channel ||
                        window_waiter || (agg_dirs & LIBSSH2_SESSION_BLOCK_INBOUND);
        if (need_read) {
            *idle_rx_paused = 0;
            want |= EPOLLIN;
        }
        if (agg_dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) want |= EPOLLOUT;
    }
    return want;
}

static int pending_op_requires_serial_retry(pending_op_t op, const client_conn_t *c,
                                            int dirs, int tls_want_serial) {
    int need_out = (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) || tls_want_serial;
    if (need_out || op == PENDING_KEEPALIVE || op == PENDING_SEND_EOF)
        return 1;
    if (op == PENDING_WRITE && c && c->write_pending &&
        !c->write_waiting_window) return 1;
    return 0;
}

static void record_eagain(LIBSSH2_SESSION *session, upstream_ctx_t *u,
                          client_conn_t *c, pending_op_t op,
                          int *agg_dirs_out, int *stop_loop_out) {
    if (g_log_perf) g_perf_stats.libssh2_eagain++;
    int d = libssh2_session_block_directions(session);
    *agg_dirs_out |= d;
    if (pending_op_requires_serial_retry(op, c, d,
                                         tls_want_requires_serial_retry(u))) {
        if (g_log_perf) g_perf_stats.pending_blocks++;
        if (g_log_backpressure) {
            unsigned long write_window = (c && c->channel)
                ? libssh2_channel_window_write_ex(c->channel, NULL) : 0UL;
            log_yellow("[SSH pending] serial retry op=%d dirs=%d client=%llu "
                       "c2s=%zu s2c=%zu write_window=%lu write_pending=%d "
                       "window_wait=%d c2s_worker=%d",
                       (int)op, d,
                       (unsigned long long)(c ? c->client_id : 0U),
                       c ? c->c2s.used : 0U, c ? c->s2c.used : 0U,
                       write_window, c ? c->write_pending : 0,
                       c ? c->write_waiting_window : 0,
                       c ? c->c2s_worker_inflight : 0);
        }
        set_pending_operation(c, op);
        *stop_loop_out = 1;
    }
}

static int finish_open_channel(int epfd, client_conn_t *c, LIBSSH2_CHANNEL *ch) {
    g_opening_client = NULL;
    /* Any deadline attached to an aborted in-flight OPEN ends with that OPEN.
     * If the resulting channel must close, start a fresh channel-free budget. */
    c->cleanup_deadline_ms = 0;
    c->channel = ch;
    if (c->close_after_ctrl && c->fd >= 0 && c->ctrl_len > 0) {
        c->abort_on_open = 0;
        c->abort_on_pending = 0;
        update_client_epoll(epfd, c, EPOLLOUT);
        return 1;
    }
    if (c->abort_on_open || c->abort_on_pending || c->close_after_ctrl || c->fd < 0) {
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return 1;
    }
    if (rb_init(&c->c2s, C2S_RELAY_BUF_SIZE) < 0 || rb_init(&c->s2c, S2C_RELAY_BUF_SIZE) < 0) {
        start_closing_client(epfd, c);
        return 1;
    }
    if (c->early_len > 0) {
        (void)rb_push(&c->c2s, c->early_buf, c->early_len);
        note_c2s_buffer_peak(c);
        c->early_len = 0;
    }
    uint8_t ok_rep[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    if (rb_push(&c->s2c, ok_rep, 10) < 0) {
        start_closing_client(epfd, c);
        return 1;
    }
    c->state = ST_RELAY;

    if (c->rdhup_pending && !c->client_eof) {
        drain_pending_eof_to_c2s(epfd, c);
    }

    if (c->fd >= 0 && c->ctrl_len == 0) {
        if (flush_s2c_to_client(epfd, c) < 0) {
            c->client_dead = 1;
            c->client_reset = 1;
            c->client_eof = 1;
            c->need_send_eof = 1;
            c->hup_pending = 0;
            c->rdhup_pending = 0;
            start_closing_client(epfd, c);
            return 1;
        }
    }

    if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
        uint32_t want = client_rdhup_flag(c);
        if (client_read_epoll_allowed(c)) want |= EPOLLIN;
        if ((c->s2c.used > 0) ||
            c->ctrl_len > 0) want |= EPOLLOUT;
        update_client_epoll(epfd, c, want);
    }
    return 1;
}

/* Return: 1 progres nyata, 2 pending dilepas tanpa progres data (lanjut scan),
 * 0 masih tertahan EAGAIN di op yang sama, -1 session fatal. */
/* Only EAGAIN leaves a libssh2 keepalive operation active. A terminal
 * socket/session result must release the serialized-operation slot before
 * the main loop enters shutdown; otherwise shutdown falsely treats a dead
 * keepalive as an operation that still needs a retry. */
static void mark_channel_upstream_drained(client_conn_t *c) {
    if (!c) return;
    if (!c->ssh_eof && g_log_backpressure) {
        log_blue("SSH remote EOF received; keep local C2S half open (%s:%u; c2s_pending=%zu; write_window=%lu; client_eof=%d)",
                 c->target_host, (unsigned)c->target_port, c->c2s.used,
                 c->channel ? libssh2_channel_window_write_ex(c->channel, NULL) : 0UL,
                 c->client_eof);
    }
    c->upstream_read_drained = 1;
    c->upstream_read_stalled = 0;
    c->ssh_eof = 1;
    if (c->fd >= 0 && c->s2c.used == 0 && c->ctrl_len == 0)
        shutdown(c->fd, SHUT_WR);
}

/* A terminal read is only clean when libssh2 confirms channel EOF and its
 * complete-packet queue is empty. read_avail > 0 or missing EOF means this
 * channel can no longer be drained safely through the public API. */
static int settle_terminal_channel_read(client_conn_t *c,
                                        upstream_ctx_t *u) {
    if (!c || !c->channel) return 0;
    unsigned long read_avail = 0;
    (void)libssh2_channel_window_read_ex(c->channel, &read_avail, NULL);
    int channel_eof = libssh2_channel_eof(c->channel);
    if (read_avail == 0 && channel_eof) {
        mark_channel_upstream_drained(c);
        return 1;
    }
    if (u && u->hup_seen) {
        if (!c->upstream_read_stalled) {
            log_yellow("S2C drain forced: channel EOF=%d libssh2 queued=%lu bytes",
                       channel_eof, read_avail);
        }
        c->upstream_read_stalled = 1;
        return -1;
    }
    return 0;
}

static int settle_pending_keepalive_result(int rc) {
    if (rc == LIBSSH2_ERROR_EAGAIN) return 0;
    clear_pending_operation();
    return rc == 0 ? 1 : -1;
}

static int resume_pending_op(int epfd, LIBSSH2_SESSION *session, upstream_ctx_t *u,
                             int *agg_dirs_out, int *did_ssh_read_out,
                             client_conn_t **retried_open_out) {
    *retried_open_out = NULL;
    client_conn_t *c = g_pending_client;
    pending_op_t op = g_pending_op;

    if (u->hup_seen && op == PENDING_FREE && c) {
        c->channel = NULL;
        clear_pending_operation();
        remove_client(epfd, c);
        return 1;
    }

    if (op == PENDING_KEEPALIVE) {
        int next_sec = 0;
        tls_begin_libssh2_call(u);
        int rc = libssh2_keepalive_send(session, &next_sec);
        tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
        int settled = settle_pending_keepalive_result(rc);
        if (settled > 0) {
            u->last_activity_ms = now_ms();
            if (g_log_backpressure) log_blue("SSH keepalive sent");
            return 1;
        }
        if (settled == 0) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        if (u->hup_seen) {
            clear_pending_operation();
            return 1;
        }
        log_red("SSH keepalive retry failed: %d", rc);
        return -1;
    }

    if (!c) {
        clear_pending_operation();
        return 2;
    }

    if (op == PENDING_OPEN) {
        tls_begin_libssh2_call(u);
        LIBSSH2_CHANNEL *ch = libssh2_channel_direct_tcpip_ex(
            session, c->target_host, c->target_port, "127.0.0.1", 1080);
        int open_err = ch ? 0 : libssh2_session_last_errno(session);
        tls_finish_libssh2_call(u, !ch && open_err == LIBSSH2_ERROR_EAGAIN);
        if (ch) {
            clear_pending_operation();
            if (u->hup_seen) {
                g_opening_client = NULL;
                c->channel = ch;
                start_closing_client(epfd, c);
                return 1;
            }
            return finish_open_channel(epfd, c, ch);
        }
        int err = open_err;
        if (err == LIBSSH2_ERROR_EAGAIN) {
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            *did_ssh_read_out = 1;
            if ((d & LIBSSH2_SESSION_BLOCK_OUTBOUND) || tls_want_requires_serial_retry(u)) {
                return 0;
            }
            if (c->abort_on_pending) {
                c->abort_on_open = 1;
                c->abort_on_pending = 0;
                c->cleanup_deadline_ms = 0;
            }
            clear_pending_operation();
            *retried_open_out = c;
            return 2;
        }
        clear_pending_operation();
        g_opening_client = NULL;
        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {
            send_socks_err_and_close(epfd, c, 0x05);
        } else if (!c->close_after_ctrl || c->fd < 0) {
            c->abort_on_pending = 0;
            remove_client(epfd, c);
        } else {
            c->abort_on_pending = 0;
        }
        return (is_libssh2_socket_fatal(err) && !u->hup_seen) ? -1 : 1;
    }

    if (op == PENDING_WRITE) {
        size_t wlen = c->write_pending ? c->write_pending_len : 0;
        const uint8_t *ptr = c->write_pending
            ? rb_read_slice_pinned(&c->c2s, c->write_pending_head, c->write_pending_generation, wlen)
            : rb_read_slice(&c->c2s, &wlen);
        if (c->write_pending && !ptr) {
            log_red("C2S pending write buffer identity changed before retry");
            clear_pending_operation();
            return -1;
        }
        tls_begin_libssh2_call(u);
        ssize_t w = (ptr && wlen > 0) ? libssh2_channel_write(c->channel, (const char *)ptr, wlen) : 0;
        tls_finish_libssh2_call(u, w == LIBSSH2_ERROR_EAGAIN);
        if (w > 0) {
            if ((size_t)w > wlen || rb_commit_read(&c->c2s, (size_t)w, 0) < 0) {
                log_red("C2S ring commit rejected after pending write");
                clear_pending_operation();
                return -1;
            }
            if (g_log_perf) {
                g_perf_stats.c2s_ssh_write_bytes += (uint64_t)w;
                if (c->ssh_eof) g_perf_stats.c2s_post_eof_ssh_write_bytes += (uint64_t)w;
            }
            if (c->ssh_eof && g_log_backpressure)
                log_blue("C2S write progressed after remote EOF (%s:%u; bytes=%lld; buffer_before_commit=%zu)",
                         c->target_host, (unsigned)c->target_port, (long long)w, c->c2s.used);
            note_channel_window_recovered(c);
            c->last_activity_ms=now_ms();
            c->write_pending = 0;
            c->write_pending_head = 0;
            c->write_pending_generation = 0;
            c->write_pending_len = 0;
            c->write_waiting_window = 0;
            c->write_wait_rx_seq = 0;
            clear_pending_operation();
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            } else if (upstream_client_write_allowed(u)) {
                drain_pending_eof_to_c2s(epfd, c);
            }
            return 1;
        }
        if (w == 0) {
            int d=libssh2_session_block_directions(session);*agg_dirs_out|=d;
            c->write_pending = (ptr && wlen > 0);
            if (c->write_pending) {
                c->write_pending_head = c->c2s.head;
                c->write_pending_generation = c->c2s.generation;
                c->write_pending_len = wlen;
            }
            c->write_waiting_window=1;c->write_wait_rx_seq=u->rx_seq;
            if (ptr && wlen > 0) note_channel_window_blocked(c, 0);
            clear_pending_operation();
            if(c->abort_on_pending){c->abort_on_pending=0;start_closing_client(epfd,c);return 1;}
            return 2;
        }
        if (w == LIBSSH2_ERROR_EAGAIN) {
            unsigned long write_window = libssh2_channel_window_write_ex(c->channel, NULL);
            if (write_window == 0) {
                c->write_waiting_window = 1;
                c->write_wait_rx_seq = u->rx_seq;
                note_channel_window_blocked(c, 1);
            } else {
                c->write_waiting_window = 0;
                c->write_wait_rx_seq = 0;
            }
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            int need_out = (d & LIBSSH2_SESSION_BLOCK_OUTBOUND) ||
                           tls_want_requires_serial_retry(u);
            /* With a nonzero window, libssh2 has created the channel packet.
             * Retain the exact buffer and retry this same write even when TLS
             * asks for inbound readiness (SSL_write WANT_READ). */
            if (write_window != 0 || need_out) return 0;

            /* A depleted channel window is the sole write EAGAIN that occurs
             * before packet creation; this is only a WINDOW_ADJUST wait. */
            clear_pending_operation();
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                return 1;
            }
            return 2;
        }
        c->write_pending = 0;
        c->write_pending_head = 0;
        c->write_pending_generation = 0;
        c->write_pending_len = 0;
        c->write_waiting_window = 0;
        c->write_wait_rx_seq = 0;
        clear_pending_operation();
        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {
            if (c->c2s.used) rb_clear(&c->c2s);
            c->need_send_eof = 0;
            c->abort_on_pending = 0;
            return 1;
        }
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return is_libssh2_socket_fatal((int)w) ? -1 : 1;
    }

    if (op == PENDING_SEND_EOF) {
        tls_begin_libssh2_call(u);
        int rc = libssh2_channel_send_eof(c->channel);
        tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
        if (rc == 0) {
            c->need_send_eof = 0;
            clear_pending_operation();
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        clear_pending_operation();
        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {
            c->need_send_eof = 0;
            c->abort_on_pending = 0;
            return 1;
        }
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return is_libssh2_socket_fatal(rc) ? -1 : 1;
    }

    if (op == PENDING_READ) {
        uint8_t discard[4096];
        size_t rlen = 0;
        int discard_output = c->client_dead || c->fd < 0;
        uint8_t *ptr = discard_output ? discard : rb_write_slice(&c->s2c, &rlen);
        if (discard_output) rlen = sizeof(discard);
        if (!ptr || rlen == 0) {
            log_red("S2C pending read has no writable ring space");
            return -1;
        }

        ssize_t r = channel_read_with_rx_flush(u, c->channel,
                                                (char *)ptr, rlen);

        if (r > 0) {
            if (!discard_output) {
                if ((size_t)r > rlen || rb_commit_write(&c->s2c, (size_t)r) < 0) {
                    log_red("S2C ring commit rejected after pending read");
                    clear_pending_operation();
                    return -1;
                }
                if (g_log_perf && c->s2c.used == c->s2c.cap)
                    g_perf_stats.s2c_full++;
                note_s2c_buffer_peak(c);
                c->last_activity_ms = now_ms();
            }
            *did_ssh_read_out = 1;
            clear_pending_operation();
            if (discard_output) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                return 1;
            }
            int send_failed = c->fd >= 0 && c->ctrl_len == 0 &&
                              flush_s2c_to_client(epfd, c) < 0;
            if (send_failed) c->client_reset = 1;
            if (c->abort_on_pending || send_failed) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }

        if (r == 0) {
            if (!discard_output)
                (void)settle_terminal_channel_read(c, u);
            clear_pending_operation();
            if (c->abort_on_pending || discard_output) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }

        if (r == LIBSSH2_ERROR_EAGAIN) {
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            *did_ssh_read_out = 1;
            if (u->rx_terminal) {
                if (!discard_output)
                    (void)settle_terminal_channel_read(c, u);
                clear_pending_operation();
                if (discard_output || c->abort_on_pending) {
                    c->abort_on_pending = 0;
                    start_closing_client(epfd, c);
                }
                return 1;
            }
            if ((d & LIBSSH2_SESSION_BLOCK_OUTBOUND) ||
                tls_want_requires_serial_retry(u)) return 0;
            clear_pending_operation();
            if (discard_output || c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                return 1;
            }
            return 2;
        }

        clear_pending_operation();
        if (!discard_output && u->hup_seen &&
            is_libssh2_socket_fatal((int)r)) {
            (void)settle_terminal_channel_read(c, u);
            c->abort_on_pending = 0;
            return 1;
        }
        if (u->hup_seen || u->rx_terminal || is_libssh2_socket_fatal((int)r)) {
            if (!discard_output)
                (void)settle_terminal_channel_read(c, u);
            c->abort_on_pending = 0;
            if (discard_output) start_closing_client(epfd, c);
            return 1;
        }
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return is_libssh2_socket_fatal((int)r) ? -1 : 1;
    }

    if (op == PENDING_FREE) {
        tls_begin_libssh2_call(u);
        int rc = libssh2_channel_free(c->channel);
        tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        c->channel = NULL;
        clear_pending_operation();
        remove_client(epfd, c);
        return 1;
    }

    clear_pending_operation();
    return 2;
}

/* Return: 1 ada progres nyata, 2 wire bytes ditarik libssh2 (ulangi pass), 0 idle/EAGAIN, -1 session fatal */
static int pump_ssh_channels(int epfd, LIBSSH2_SESSION *session, upstream_ctx_t *u,
                             int *agg_dirs_out, int *did_ssh_read_out) {
    int any_progress = 0;
    int agg_dirs = 0;
    int did_ssh_read = 0;
    int stop_loop = 0;
    uint64_t rx_before = u->rx_seq;
    client_conn_t *just_retried_open = NULL;

    if (g_pending_op != PENDING_NONE) {
        int pr = resume_pending_op(epfd, session, u, &agg_dirs, &did_ssh_read, &just_retried_open);
        if (pr < 0) {
            *agg_dirs_out = agg_dirs;
            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
            *did_ssh_read_out = did_ssh_read;
            return -1;
        }
        if (pr == 0) {
            *agg_dirs_out = agg_dirs;
            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
            *did_ssh_read_out = did_ssh_read;
            return 0;
        }
        if (pr == 1) any_progress = 1;
    }

    client_conn_t *c = g_clients;
    while (c && !stop_loop) {
        client_conn_t *next = c->next;

        if (c->state == ST_SSH_OPENING) {
            int opening_already_started = (g_opening_client == c);
            if ((opening_already_started ||
                 (!u->hup_seen && g_opening_client == NULL &&
                  !c->close_after_ctrl &&
                  !c->abort_on_open &&
                  !c->abort_on_pending)) &&
                c != just_retried_open) {
                g_opening_client = c;
                if (c->open_started_ms == 0) c->open_started_ms = now_ms();
                tls_begin_libssh2_call(u);
                LIBSSH2_CHANNEL *ch = libssh2_channel_direct_tcpip_ex(
                    session, c->target_host, c->target_port, "127.0.0.1", 1080);
                int open_err = ch ? 0 : libssh2_session_last_errno(session);
                tls_finish_libssh2_call(u, !ch && open_err == LIBSSH2_ERROR_EAGAIN);
                if (ch) {
                    if (u->hup_seen) {
                        g_opening_client = NULL;
                        c->channel = ch;
                        start_closing_client(epfd, c);
                        any_progress = 1;
                    } else {
                        any_progress = finish_open_channel(epfd, c, ch);
                    }
                } else {
                    int err = open_err;
                    if (err == LIBSSH2_ERROR_EAGAIN) {
                        did_ssh_read = 1;
                        record_eagain(session, u, c, PENDING_OPEN, &agg_dirs, &stop_loop);
                    } else {
                        g_opening_client = NULL;
                        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {
                            send_socks_err_and_close(epfd, c, 0x05);
                        } else if (!c->close_after_ctrl || c->fd < 0) {
                            c->abort_on_pending = 0;
                            remove_client(epfd, c);
                        } else {
                            c->abort_on_pending = 0;
                        }
                        if (is_libssh2_socket_fatal(err) && !u->hup_seen) {
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                    }
                }
            }
        } else if (c->state == ST_RELAY) {
            if (client_dead_ready_to_close(c)) {
                c->need_send_eof = 0;
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                c = next;
                continue;
            }
            if (u->hup_seen && g_pending_op == PENDING_NONE) {
                /* A write buffer may be released only when no libssh2 call
                 * pins it, or when EAGAIN is solely a zero-window wait. */
                if (!c->write_pending || c->write_waiting_window) {
                    if (c->c2s.used) rb_clear(&c->c2s);
                    c->write_pending = 0;
                    c->write_pending_head = 0;
                    c->write_pending_generation = 0;
                    c->write_pending_len = 0;
                    c->write_waiting_window = 0;
                    c->write_wait_rx_seq = 0;
                }
                c->need_send_eof = 0;
            }
            if (upstream_client_write_allowed(u) && drain_pending_eof_to_c2s(epfd, c)) {
                any_progress = 1;
            }

            if (upstream_client_write_allowed(u) && c->c2s.used > 0 &&
                (!c->write_waiting_window || u->rx_seq != c->write_wait_rx_seq)) {
                if (c->write_waiting_window) c->write_waiting_window=0;
                const uint8_t *ptr = NULL;
                size_t avail = 0;
                if (c->write_pending) {
                    avail = c->write_pending_len;
                    ptr = rb_read_slice_pinned(&c->c2s, c->write_pending_head,
                                               c->write_pending_generation, avail);
                    if (!ptr) {
                        log_red("C2S ring slice identity mismatch in relay pump");
                        *agg_dirs_out = agg_dirs;
                        note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                        *did_ssh_read_out = did_ssh_read;
                        return -1;
                    }
                } else {
                    ptr = rb_read_slice(&c->c2s, &avail);
                }
                if (ptr && avail > 0) {
                    tls_begin_libssh2_call(u);
                    ssize_t w = libssh2_channel_write(c->channel, (const char *)ptr, avail);
                    tls_finish_libssh2_call(u, w == LIBSSH2_ERROR_EAGAIN);
                    if (w > 0) {
                        c->write_pending = 0;
                        c->write_pending_head = 0;
        c->write_pending_generation = 0;
                        c->write_pending_len = 0;
                        c->write_waiting_window = 0;
                        c->write_wait_rx_seq = 0;
                        c->last_activity_ms = now_ms();
                        if ((size_t)w > avail || rb_commit_read(&c->c2s, (size_t)w, 0) < 0) {
                            log_red("C2S ring commit rejected in relay pump");
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        if (g_log_perf) {
                            g_perf_stats.c2s_ssh_write_bytes += (uint64_t)w;
                            if (c->ssh_eof) g_perf_stats.c2s_post_eof_ssh_write_bytes += (uint64_t)w;
                        }
                        if (c->ssh_eof && g_log_backpressure)
                            log_blue("C2S write progressed after remote EOF (%s:%u; bytes=%lld; buffer_before_commit=%zu)",
                                     c->target_host, (unsigned)c->target_port, (long long)w, c->c2s.used);
                        note_channel_window_recovered(c);
                        any_progress = 1;
                        if (c->abort_on_pending) {
                            c->abort_on_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                        if (upstream_client_write_allowed(u))
                            (void)drain_pending_eof_to_c2s(epfd, c);
                    } else if (w == 0) {
                        int d=libssh2_session_block_directions(session);agg_dirs|=d;
                        c->write_pending = 1;
                        c->write_pending_head = c->c2s.head;
                        c->write_pending_generation = c->c2s.generation;
                        c->write_pending_len = avail;
                        c->write_waiting_window=1;c->write_wait_rx_seq=u->rx_seq;
                        note_channel_window_blocked(c, 0);
                        if(c->abort_on_pending){c->abort_on_pending=0;start_closing_client(epfd,c);c=next;continue;}
                    } else if (w == LIBSSH2_ERROR_EAGAIN) {
                        unsigned long write_window = libssh2_channel_window_write_ex(c->channel, NULL);
                        c->write_pending = 1;
                        c->write_pending_head = c->c2s.head;
                        c->write_pending_generation = c->c2s.generation;
                        c->write_pending_len = avail;
                        if (write_window == 0) {
                            /*
                             * libssh2 reports a depleted channel write window as EAGAIN
                             * when it has no inbound packet available to process. Query
                             * the channel window directly; the return code alone cannot
                             * distinguish this from socket-level EAGAIN.
                             */
                            c->write_waiting_window = 1;
                            c->write_wait_rx_seq = u->rx_seq;
                            if (c->ssh_eof && g_log_perf) g_perf_stats.c2s_post_eof_window_blocked++;
                            if (c->ssh_eof && g_log_backpressure && !c->c2s_post_eof_window_logged) {
                                c->c2s_post_eof_window_logged = 1;
                                log_yellow("C2S zero-window wait after remote EOF (%s:%u; c2s_pending=%zu; rx_seq=%llu)",
                                           c->target_host, (unsigned)c->target_port, c->c2s.used,
                                           (unsigned long long)u->rx_seq);
                            }
                            note_channel_window_blocked(c, 1);
                        } else {
                            c->write_waiting_window = 0;
                            c->write_wait_rx_seq = 0;
                        }
                        record_eagain(session, u, c, PENDING_WRITE, &agg_dirs, &stop_loop);
                        if (stop_loop) break;
                    } else {
                        c->write_pending = 0;
                        c->write_pending_head = 0;
        c->write_pending_generation = 0;
                        c->write_pending_len = 0;
                        c->write_waiting_window = 0;
                        c->write_wait_rx_seq = 0;
                        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {
                            if (c->c2s.used) rb_clear(&c->c2s);
                            c->need_send_eof = 0;
                            c->abort_on_pending = 0;
                            c = next;
                            continue;
                        }
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        if (w < 0 && is_libssh2_socket_fatal((int)w)) {
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        c = next;
                        continue;
                    }
                }
            }

            if (upstream_client_write_allowed(u) && c->need_send_eof && c->c2s.used == 0 && !c->write_pending) {
                tls_begin_libssh2_call(u);
                int rc = libssh2_channel_send_eof(c->channel);
                tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
                if (rc == 0) {
                    c->need_send_eof = 0;
                    any_progress = 1;
                    if (c->abort_on_pending) {
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        c = next;
                        continue;
                    }
                } else if (rc == LIBSSH2_ERROR_EAGAIN) {
                    record_eagain(session, u, c, PENDING_SEND_EOF, &agg_dirs, &stop_loop);
                    if (stop_loop) break;
                } else {
                    if (u->hup_seen || u->rx_terminal || u->tx_terminal) {
                        c->need_send_eof = 0;
                        c->abort_on_pending = 0;
                        c = next;
                        continue;
                    }
                    c->abort_on_pending = 0;
                    start_closing_client(epfd, c);
                    if (is_libssh2_socket_fatal(rc)) {
                        *agg_dirs_out = agg_dirs;
                        note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                        *did_ssh_read_out = did_ssh_read;
                        return -1;
                    }
                    c = next;
                    continue;
                }
            }

            /* A cleanly closed local peer may no longer consume S2C data, but
             * any bytes already queued C2S must be written and SSH EOF sent
             * before releasing the channel. Reset peers use the fast path above. */
            if (client_eof_ready_to_close(c)) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                c = next;
                continue;
            }

            if (!c->ssh_eof && !c->client_dead && !c->upstream_read_stalled &&
                rb_free_space(&c->s2c) > 0) {
                /* EAGAIN does not pin libssh2_channel_read()'s caller buffer.
                 * Always use the current contiguous writable area. */
                size_t avail = 0;
                uint8_t *ptr = rb_write_slice(&c->s2c, &avail);
                if (ptr && avail > 0) {
                    ssize_t r = channel_read_with_rx_flush(
                        u, c->channel, (char *)ptr, avail);
                    if (r > 0) {
                        if ((size_t)r > avail || rb_commit_write(&c->s2c, (size_t)r) < 0) {
                            log_red("S2C ring commit rejected in relay pump");
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        did_ssh_read = 1;
                        if (g_log_perf && c->s2c.used == c->s2c.cap)
                            g_perf_stats.s2c_full++;
                        note_s2c_buffer_peak(c);
                        c->last_activity_ms=now_ms();
                        any_progress = 1;
                        int client_send_failed = c->fd >= 0 && c->ctrl_len == 0 &&
                                                 flush_s2c_to_client(epfd, c) < 0;
                        if (client_send_failed) c->client_reset = 1;
                        if (c->abort_on_pending || client_send_failed) {
                            c->abort_on_pending = 0;
                            c->client_dead = 1;
                            c->client_eof = 1;
                            c->need_send_eof = 1;
                            c->hup_pending = 0;
                            c->rdhup_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                    } else if (r == 0) {
                        if (c->s2c.used == 0 && rb_clear(&c->s2c) < 0) {
                            log_red("S2C ring clear rejected after channel read");
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        if (settle_terminal_channel_read(c, u) != 0) {
                            did_ssh_read = 1;
                            any_progress = 1;
                        }
                        if (c->abort_on_pending) {
                            c->abort_on_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                    } else if (r == LIBSSH2_ERROR_EAGAIN) {
                        did_ssh_read = 1;
                        if (u->rx_terminal) {
                            (void)settle_terminal_channel_read(c, u);
                            any_progress = 1;
                        } else {
                            record_eagain(session, u, c, PENDING_READ, &agg_dirs, &stop_loop);
                            if (stop_loop) break;
                        }
                    } else {
                        if (u->hup_seen && !u->rx_terminal &&
                            is_libssh2_socket_fatal((int)r)) {
                            /* A failed WINDOW_ADJUST send does not prove that
                             * libssh2's already-queued channel packets were
                             * copied into s2c. Do not claim this channel drained. */
                            if (!c->upstream_read_stalled)
                                log_yellow("S2C drain stalled: libssh2 transport ended before channel EOF");
                            c->upstream_read_stalled = 1;
                            any_progress = 1;
                            c = next;
                            continue;
                        }
                        if (u->hup_seen || u->rx_terminal ||
                            is_libssh2_socket_fatal((int)r)) {
                            (void)settle_terminal_channel_read(c, u);
                            any_progress = 1;
                            c = next;
                            continue;
                        }
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        if (is_libssh2_socket_fatal((int)r) && !u->hup_seen) {
                            *agg_dirs_out = agg_dirs;
                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        c = next;
                        continue;
                    }
                }
            }

            if (c->client_eof && c->ssh_eof && c->c2s.used == 0 && c->s2c.used == 0 && !c->need_send_eof) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                c = next;
                continue;
            }

            if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
                uint32_t want = client_rdhup_flag(c);
                if (upstream_client_write_allowed(u) && client_read_epoll_allowed(c))
                    want |= EPOLLIN;
                if ((c->s2c.used > 0) ||
                    c->ctrl_len > 0) want |= EPOLLOUT;
                update_client_epoll(epfd, c, want);
            }
        } else if (c->state == ST_CLOSING) {
            if (u->hup_seen) {
                c->channel = NULL;
                remove_client(epfd, c);
                any_progress = 1;
                c = next;
                continue;
            }
            if (!c->channel) {
                remove_client(epfd, c);
                any_progress = 1;
                c = next;
                continue;
            }
            tls_begin_libssh2_call(u);
            int rc = libssh2_channel_free(c->channel);
            tls_finish_libssh2_call(u, rc == LIBSSH2_ERROR_EAGAIN);
            if (rc == LIBSSH2_ERROR_EAGAIN) {
                record_eagain(session, u, c, PENDING_FREE, &agg_dirs, &stop_loop);
                if (stop_loop) break;
            } else {
                if (rc < 0) log_yellow("libssh2_channel_free cleanup returned %d", rc);
                c->channel = NULL;
                remove_client(epfd, c);
                any_progress = 1;
            }
        }

        c = next;
    }

    *agg_dirs_out = agg_dirs;
    note_upstream_rx_progress(u, rx_before, &did_ssh_read);
    *did_ssh_read_out = did_ssh_read;
    if (any_progress) return 1;
    if (!stop_loop && g_pending_op == PENDING_NONE && u->rx_seq != rx_before) return 2;
    return 0;
}

static int has_readable_relay_channel(void) {
    for (client_conn_t *c = g_clients; c; c = c->next) {
        if (c->state == ST_RELAY && !c->ssh_eof && !c->client_dead &&
            !c->upstream_read_stalled && rb_free_space(&c->s2c) > 0) {
            return 1;
        }
    }
    return 0;
}

static int upstream_client_write_allowed(const upstream_ctx_t *u) {
    return u && !u->tx_terminal &&
           (!u->hup_seen || (u->tls && u->rx_terminal && u->rx_terminal_rc == 0));
}
static int has_window_waiter(void) {
    for (client_conn_t *c = g_clients; c; c = c->next) {
        if (c->state == ST_RELAY && c->c2s.used > 0 && c->write_waiting_window) {
            return 1;
        }
    }
    return 0;
}

static void retry_window_waiters(void) {
    for (client_conn_t *c = g_clients; c; c = c->next) {
        if (c->state == ST_RELAY && c->c2s.used > 0 && c->write_waiting_window) {
            c->write_waiting_window = 0;
            if (g_log_perf) g_perf_stats.window_waiter_retry_count++;
            if (c->ssh_eof && g_log_backpressure)
                log_blue("WINDOW_ADJUST/input activity woke C2S waiter after remote EOF (%s:%u; c2s_pending=%zu)",
                         c->target_host, (unsigned)c->target_port, c->c2s.used);
        }
    }
}

static void begin_upstream_drain(int epfd, int *listen_fd,
                                upstream_ctx_t *u) {
    if (!u || !u->hup_seen || u->drain_deadline_ms > 0) return;
    u->drain_deadline_ms = now_ms() + UPSTREAM_DRAIN_TIMEOUT_MS;
    if (listen_fd && *listen_fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, *listen_fd, NULL);
        close(*listen_fd);
        *listen_fd = -1;
    }
}

typedef enum {
    UPSTREAM_DRAIN_WAIT = 0,
    UPSTREAM_DRAIN_GRACEFUL,
    UPSTREAM_DRAIN_FORCED
} upstream_drain_result_t;

typedef struct {
    int output_pending;
    int read_drained;
    int read_stalled;
    int channel_present;
    int channel_eof;
    unsigned long read_avail;
} upstream_drain_channel_state_t;

/* Pure policy helper: every channel must have stopped producing data and all
 * user-space output must be sent before the drain can be classified. A channel
 * marked drained/stalled is not trusted unless libssh2 also reports channel
 * EOF and zero complete DATA packets still queued for it. */
static upstream_drain_result_t classify_upstream_drain(
    const upstream_ctx_t *u,
    const upstream_drain_channel_state_t *channels,
    size_t channel_count,
    int pending_operation,
    int opening_client,
    unsigned long *queued_bytes_out,
    unsigned int *stalled_channels_out,
    unsigned int *incomplete_channels_out) {
    unsigned long queued_bytes = 0;
    unsigned int stalled_channels = 0;
    unsigned int incomplete_channels = 0;

    if (queued_bytes_out) *queued_bytes_out = 0;
    if (stalled_channels_out) *stalled_channels_out = 0;
    if (incomplete_channels_out) *incomplete_channels_out = 0;

    if (!u || !u->hup_seen) return UPSTREAM_DRAIN_WAIT;
    if (pending_operation || opening_client) return UPSTREAM_DRAIN_WAIT;

    int forced = (!u->rx_terminal || u->rx_terminal_rc != 0);
    for (size_t i = 0; i < channel_count; i++) {
        const upstream_drain_channel_state_t *ch = &channels[i];
        if (ch->output_pending) return UPSTREAM_DRAIN_WAIT;
        if (!ch->channel_present) {
            forced = 1;
            incomplete_channels++;
            continue;
        }
        if (!ch->read_drained && !ch->read_stalled)
            return UPSTREAM_DRAIN_WAIT;

        if (ch->read_stalled) {
            stalled_channels++;
            forced = 1;
        }
        if (ULONG_MAX - queued_bytes < ch->read_avail)
            queued_bytes = ULONG_MAX;
        else
            queued_bytes += ch->read_avail;

        if (!ch->channel_present || !ch->channel_eof || ch->read_avail > 0) {
            forced = 1;
            incomplete_channels++;
        }
    }

    if (queued_bytes_out) *queued_bytes_out = queued_bytes;
    if (stalled_channels_out) *stalled_channels_out = stalled_channels;
    if (incomplete_channels_out) *incomplete_channels_out = incomplete_channels;
    return forced ? UPSTREAM_DRAIN_FORCED : UPSTREAM_DRAIN_GRACEFUL;
}

static upstream_drain_result_t upstream_drain_status(
    const upstream_ctx_t *u,
    unsigned long *queued_bytes_out,
    unsigned int *stalled_channels_out,
    unsigned int *incomplete_channels_out) {
    upstream_drain_channel_state_t channels[MAX_CLIENTS_LIMIT];
    size_t count = 0;

    if (!u || !u->hup_seen) return UPSTREAM_DRAIN_WAIT;
    if (g_pending_op != PENDING_NONE || g_opening_client != NULL)
        return UPSTREAM_DRAIN_WAIT;

    for (client_conn_t *c = g_clients; c; c = c->next) {
        /* Preserve queued SOCKS error replies for clients rejected on HUP,
         * even when they never reached ST_RELAY. */
        if (c->ctrl_len > 0 && c->fd >= 0 && !c->client_dead)
            return UPSTREAM_DRAIN_WAIT;
        if (c->state != ST_RELAY || c->client_dead || c->client_reset || c->fd < 0)
            continue;
        if (count >= MAX_CLIENTS_LIMIT)
            return UPSTREAM_DRAIN_FORCED;

        upstream_drain_channel_state_t *ch = &channels[count++];
        memset(ch, 0, sizeof(*ch));
        ch->output_pending = (c->s2c.used > 0 || c->ctrl_len > 0);
        ch->read_drained = c->upstream_read_drained;
        ch->read_stalled = c->upstream_read_stalled;
        ch->channel_present = (c->channel != NULL);
        if (c->channel) {
            (void)libssh2_channel_window_read_ex(c->channel, &ch->read_avail, NULL);
            ch->channel_eof = libssh2_channel_eof(c->channel);
        }
    }

    return classify_upstream_drain(u, channels, count, 0, 0,
                                   queued_bytes_out, stalled_channels_out,
                                   incomplete_channels_out);
}

static int upstream_drain_timed_out(const upstream_ctx_t *u, long long now) {
    return u && u->drain_deadline_ms > 0 && now >= u->drain_deadline_ms;
}

static int upstream_epoll_timeout_ms(const upstream_ctx_t *u,
                                     int force_next_tick, long long now) {
    if (force_next_tick) return 0;
    if (!u || !u->hup_seen) return 1000;

    int timeout = (g_pending_op != PENDING_NONE && u->upstream_epoll_detached)
                      ? UPSTREAM_DRAIN_POLL_MS : 1000;
    if (u->drain_deadline_ms > 0) {
        long long remaining = u->drain_deadline_ms - now;
        if (remaining <= 0) return 0;
        if (remaining < timeout) timeout = (int)remaining;
    }
    return timeout;
}

static int upstream_http_response_rejected(const upstream_ctx_t *u) {
    return u && !u->tunnel_established &&
           (u->last_http_code >= 200 || u->last_http_code == 101);
}

static int session_disconnect_with_deadline(LIBSSH2_SESSION *session,
                                             upstream_ctx_t *u,
                                             long long deadline_ms) {
    if (!session) return 0;
    while (now_ms() < deadline_ms) {
        int rc = libssh2_session_disconnect(session, "Normal shutdown");
        if (rc == 0) return 0;
        if (rc != LIBSSH2_ERROR_EAGAIN) return rc;
        int dirs = libssh2_session_block_directions(session);
        short events = 0;
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) events |= POLLIN;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) events |= POLLOUT;
        if (events == 0) events = POLLIN | POLLOUT;
        if (wait_upstream_event(u, events, deadline_ms, 1) <= 0) break;
    }
    return LIBSSH2_ERROR_EAGAIN;
}
static int session_free_with_deadline(LIBSSH2_SESSION **session,
                                       upstream_ctx_t *u,
                                       long long deadline_ms) {
    if (!session || !*session) return 0;
    while (now_ms() < deadline_ms) {
        int rc = libssh2_session_free(*session);
        if (rc == 0) { *session = NULL; return 0; }
        if (rc != LIBSSH2_ERROR_EAGAIN) return rc;
        int dirs = libssh2_session_block_directions(*session);
        short events = 0;
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) events |= POLLIN;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) events |= POLLOUT;
        if (events == 0) events = POLLIN | POLLOUT;
        if (wait_upstream_event(u, events, deadline_ms, 1) <= 0) break;
    }
    return LIBSSH2_ERROR_EAGAIN;
}

static void on_sig(int sig) {
    (void)sig;
    request_stop();
}

#ifndef SSH_CORE_PARSER_TEST
static int core_worker_run(int argc, char **argv) {
    app_cfg_t cfg = {
        .transport = "TCP",
        .host_port = "",
        .proxy_port = "",
        .delay_ms = 1000,
        .fix_crlf = 1,
        .socks_addr = "127.0.0.1:1080",
        .keepalive_sec = 15,
        .verify_tls = 1,
        .tls_diag = 0,
        .allow_remote_socks = 0,
        .allow_http_200_tunnel = 0,
        .idle_timeout_sec = DEFAULT_IDLE_TIMEOUT,
        .hostkey_fp = "",
        .max_clients = DEFAULT_MAX_CLIENTS,
        .log_backpressure = 0,
        .log_perf = 0
    };
    const char *env_file = NULL;
    const char *payload_file = NULL;
    const char *payload_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-env FILE] [-payload-file FILE] [-socks 127.0.0.1:1080] [-verify-tls 0|1] [-tls-diag 0|1] [-allow-remote-socks 0|1] [-http-200-tunnel 0|1] [-idle-timeout SEC] [-hostkey SHA256:...] [-max-clients 1..256] [-log-backpressure 0|1] [-log-perf 0|1] [-log FILE|-]\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-env") == 0 && i + 1 < argc) {
            env_file = argv[++i];
        } else if (strcmp(argv[i], "-log") == 0 && i + 1 < argc) {
            g_log_path = argv[++i];
        }
    }

    if (env_file && load_env(env_file, &cfg) < 0) return 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-env") == 0 && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-log") == 0 && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-workers") == 0 && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-payload-file") == 0 && i + 1 < argc) payload_file = argv[++i];
        else if (strcmp(argv[i], "-payload") == 0 && i + 1 < argc) payload_str = argv[++i];
        else if (strcmp(argv[i], "-transport") == 0 && i + 1 < argc) snprintf(cfg.transport, sizeof(cfg.transport), "%s", argv[++i]);
        else if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) snprintf(cfg.host, sizeof(cfg.host), "%s", argv[++i]);
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) snprintf(cfg.host_port, sizeof(cfg.host_port), "%s", argv[++i]);
        else if (strcmp(argv[i], "-user") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strlen(value) >= sizeof(cfg.username)) {
                log_red("-user melebihi batas %zu byte", sizeof(cfg.username) - 1U);
                return 1;
            }
            snprintf(cfg.username, sizeof(cfg.username), "%s", value);
        } else if (strcmp(argv[i], "-pass") == 0 && i + 1 < argc) {
            const char *value = argv[++i];
            if (strlen(value) >= sizeof(cfg.password)) {
                log_red("-pass melebihi batas %zu byte", sizeof(cfg.password) - 1U);
                return 1;
            }
            snprintf(cfg.password, sizeof(cfg.password), "%s", value);
        }
        else if (strcmp(argv[i], "-proxy") == 0 && i + 1 < argc) snprintf(cfg.proxy, sizeof(cfg.proxy), "%s", argv[++i]);
        else if (strcmp(argv[i], "-proxy-port") == 0 && i + 1 < argc) snprintf(cfg.proxy_port, sizeof(cfg.proxy_port), "%s", argv[++i]);
        else if (strcmp(argv[i], "-sni") == 0 && i + 1 < argc) snprintf(cfg.sni, sizeof(cfg.sni), "%s", argv[++i]);
        else if (strcmp(argv[i], "-socks") == 0 && i + 1 < argc) snprintf(cfg.socks_addr, sizeof(cfg.socks_addr), "%s", argv[++i]);
        else if (strcmp(argv[i], "-delay") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,600000,&cfg.delay_ms)<0){log_red("Nilai -delay tidak valid");return 1;} }
        else if (strcmp(argv[i], "-keepalive") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,3600,&cfg.keepalive_sec)<0){log_red("Nilai -keepalive tidak valid");return 1;} }
        else if (strcmp(argv[i], "-fix-crlf") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.fix_crlf)<0){log_red("Nilai -fix-crlf tidak valid");return 1;} }
        else if (strcmp(argv[i], "-verify-tls") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.verify_tls)<0){log_red("Nilai -verify-tls tidak valid");return 1;} }
        else if (strcmp(argv[i], "-tls-diag") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.tls_diag)<0){log_red("Nilai -tls-diag tidak valid");return 1;} }
        else if (strcmp(argv[i], "-allow-remote-socks") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.allow_remote_socks)<0){log_red("Nilai -allow-remote-socks tidak valid");return 1;} }
        else if (strcmp(argv[i], "-http-200-tunnel") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.allow_http_200_tunnel)<0){log_red("Nilai -http-200-tunnel tidak valid");return 1;} }
        else if (strcmp(argv[i], "-idle-timeout") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,86400,&cfg.idle_timeout_sec)<0){log_red("Nilai -idle-timeout tidak valid");return 1;} }
        else if (strcmp(argv[i], "-hostkey") == 0 && i + 1 < argc) snprintf(cfg.hostkey_fp,sizeof(cfg.hostkey_fp),"%s",argv[++i]);
        else if (strcmp(argv[i], "-max-clients") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],1,MAX_CLIENTS_LIMIT,&cfg.max_clients)<0){log_red("MAX_CLIENTS harus 1..%d",MAX_CLIENTS_LIMIT);return 1;} }
        else if (strcmp(argv[i], "-log-backpressure") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.log_backpressure)<0){log_red("LOG_BACKPRESSURE harus 0 atau 1");return 1;} }
        else if (strcmp(argv[i], "-log-perf") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.log_perf)<0){log_red("LOG_PERF harus 0 atau 1");return 1;} }
    }

    g_log_backpressure = cfg.log_backpressure;
    g_log_perf = cfg.log_perf;
    if (g_worker_id == 0) {
        log_blue("CPU topology: detected=%ld selected=%d mode=%s max=%d",
                 g_detected_cpu_count, g_worker_count,
                 g_worker_count_auto ? "auto" : "manual", MAX_WORKERS);
    }
    log_blue("[AUTH-DIAG] configured credential sizes: username=%zu password=%zu bytes (values redacted)",
             strlen(cfg.username), strlen(cfg.password));
    log_blue("Worker %d/%d starting (process-wide MAX_CLIENTS=%d)",
             g_worker_id + 1, g_worker_count, cfg.max_clients);
    if (g_log_perf)
        log_blue("Diagnostik performa per interval aktif (LOG_PERF=1)");
    if (g_log_backpressure)
        log_blue("Diagnostik backpressure aktif (LOG_BACKPRESSURE=1)");

    if (!cfg.host[0] || !cfg.username[0]) {
        fprintf(stderr, "Host dan Username wajib diisi\n");
        return 1;
    }

    char listen_ip[INET6_ADDRSTRLEN + 1] = {0};
    int listen_port = 1080, listen_loopback = 0;
    struct sockaddr_storage listen_addr;
    socklen_t listen_addr_len = 0;
    if (parse_socks_listen_addr(cfg.socks_addr, &listen_addr, &listen_addr_len,
                                listen_ip, sizeof(listen_ip), &listen_port,
                                &listen_loopback) < 0) {
        log_red("Alamat SOCKS5 tidak valid: %s (gunakan IPv4:port atau [IPv6]:port)", cfg.socks_addr);
        return 1;
    }
    if (!listen_loopback) {
        if (!cfg.allow_remote_socks) {
            log_red("Bind SOCKS5 non-loopback ditolak; set ALLOW_REMOTE_SOCKS=1 hanya jika firewall membatasi akses");
            return 1;
        }
        log_yellow("PERINGATAN: SOCKS5 tanpa autentikasi di-bind ke %s:%d; lindungi dengan firewall",
                   listen_ip, listen_port);
    }

    char *raw_payload = NULL;
    if (payload_str) {
        raw_payload = strdup(payload_str);
    } else if (payload_file) {
        raw_payload = read_entire_file(payload_file);
        if (!raw_payload) log_yellow("Peringatan: gagal membaca payload file %s", payload_file);
    }
    if (!raw_payload) raw_payload = strdup("");

    int is_tls = (strcasecmp(cfg.transport, "TLS") == 0);
    const char *dial_host = cfg.host;
    const char *dial_port = cfg.host_port;

    if (is_tls) {
        if (cfg.proxy[0]) {
            dial_host = cfg.proxy;
            dial_port = cfg.proxy_port[0] ? cfg.proxy_port : "443";
            log_blue("Mode: Direct C TLS/SNI + Proxy -> %s:%s (SNI: %s)", dial_host, dial_port, cfg.sni);
        } else {
            dial_host = cfg.host;
            dial_port = (cfg.host_port[0] && strcmp(cfg.host_port, "22") != 0) ? cfg.host_port : "443";
            log_blue("Mode: Direct C TLS/SNI -> %s:%s (SNI: %s)", dial_host, dial_port, cfg.sni);
        }
    } else {
        if (cfg.proxy[0]) {
            dial_host = cfg.proxy;
            dial_port = cfg.proxy_port[0] ? cfg.proxy_port : "80";
            log_blue("Mode: C TCP via HTTP Proxy -> %s:%s", dial_host, dial_port);
        } else {
            dial_host = cfg.host;
            dial_port = cfg.host_port[0] ? cfg.host_port : "80";
            log_blue("Mode: C Direct TCP Injector -> %s:%s", dial_host, dial_port);
        }
    }

    char upstream_address[INET6_ADDRSTRLEN + 24] = {0};
    int upstream_fd = tcp_connect_host_excluding(
        dial_host, dial_port, NULL, 0, upstream_address, sizeof(upstream_address));
    if (upstream_fd < 0) {
        log_red("Koneksi TCP upstream gagal ke %s:%s", dial_host, dial_port);
        write_marker(NEED_RESTART_FILE, "TCP connect failed");
        free(raw_payload);
        return 1;
    }

    /* Keep the socket number as libssh2's callback cookie. For TLS it remains
     * open but is owned exclusively by TLS Engine; only upstream_watch_fd is
     * registered with epoll and upstream_fd is set to -1 for cleanup safety. */
    int upstream_libssh2_socket = upstream_fd;
    int upstream_watch_fd = upstream_fd;
    upstream_ctx_t uctx = {
        .fd = upstream_fd, .log_path = g_log_path,
        .log_worker_id = g_worker_id, .log_worker_count = g_worker_count,
        .last_activity_ms = now_ms(),
        .allow_http_200_tunnel = cfg.allow_http_200_tunnel
    };
    SSL_CTX *ssl_ctx = NULL;
    LIBSSH2_SESSION *session = NULL;
    int listen_fd = -1;
    int epfd = -1;
    io_worker_pool_t *io_pool = NULL;
    io_worker_completion_tracker_t *io_tracker = NULL;
    int exit_code = 1;

    if (is_tls) {
        static const unsigned char alpn_http11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            log_red("SSL_CTX_new gagal");
            write_marker(NEED_RESTART_FILE, "SSL_CTX_new failed");
            goto fail_cleanup;
        }
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#if defined(SSH_CORE_MIPSEL_24KC)
        /*
         * Prefer ChaCha20-Poly1305 on the MT7621/MIPS build, where software
         * AES-GCM may be more CPU-expensive. Keep both AES-GCM suites as
         * interoperable fallbacks; this affects TLS 1.3 only, not SSH ciphers.
         */
        static const char mips_tls13_ciphersuites[] =
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_AES_128_GCM_SHA256";
        ERR_clear_error();
        if (SSL_CTX_set_ciphersuites(ssl_ctx, mips_tls13_ciphersuites) == 1) {
            log_blue("[TLS] mipsel_24kc TLS 1.3 cipher preference configured: ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM");
        } else {
            unsigned long tls_cipher_error = ERR_get_error();
            log_yellow("[TLS] mipsel_24kc ChaCha preference unavailable; using OpenSSL defaults (%s)",
                       tls_cipher_error ? ERR_reason_error_string(tls_cipher_error) : "no OpenSSL detail");
            ERR_clear_error();
        }
#endif
        if (cfg.tls_diag) {
            SSL_CTX_set_msg_callback(ssl_ctx, tls_message_callback);
            SSL_CTX_set_msg_callback_arg(ssl_ctx, &uctx);
            log_blue("TLS message tracing enabled (TLS_DIAG=1)");
        }
        if (SSL_CTX_set_alpn_protos(ssl_ctx, alpn_http11, sizeof(alpn_http11)) != 0) {
            log_red("[TLS-DIAG] failed to configure ALPN http/1.1");
            write_marker(NEED_RESTART_FILE, "TLS ALPN setup failed");
            goto fail_cleanup;
        }
        if (cfg.verify_tls) {
            if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
                log_red("SSL_CTX_set_default_verify_paths gagal");
                write_marker(NEED_RESTART_FILE, "TLS CA store failed");
                goto fail_cleanup;
            }
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        }

        const char *sni = cfg.sni[0] ? cfg.sni : cfg.host;
        char failed_tls_addresses[TLS_CONNECT_MAX_ADDR_ATTEMPTS][INET6_ADDRSTRLEN + 24];
        const char *excluded_tls_addresses[TLS_CONNECT_MAX_ADDR_ATTEMPTS];
        size_t excluded_tls_count = 0;
        size_t tls_attempt = 0;

        for (;;) {
            tls_engine_t *engine = tls_engine_create(262144U);
            if (!engine) {
                log_red("TLS Engine allocation failed: %s", strerror(errno));
                write_marker(NEED_RESTART_FILE, "TLS Engine allocation failed");
                goto fail_cleanup;
            }
            int tls_socket_fd = upstream_fd;
            log_blue("[TLS-DIAG] OpenSSL=%s fd=%d verify=%d SNI=%s ALPN=http/1.1 address=%s attempt=%zu/%d",
                     OpenSSL_version(OPENSSL_VERSION), tls_socket_fd,
                     cfg.verify_tls, sni, upstream_address,
                     tls_attempt + 1, TLS_CONNECT_MAX_ADDR_ATTEMPTS);
            if (tls_engine_start(engine, ssl_ctx, tls_socket_fd, sni,
                                 cfg.verify_tls, HANDSHAKE_TIMEOUT_MS) != 0) {
                int err = errno ? errno : EIO;
                tls_engine_destroy(engine);
                log_red("TLS Engine thread start failed: %s", strerror(err));
                write_marker(NEED_RESTART_FILE, "TLS Engine start failed");
                errno = err;
                goto fail_cleanup;
            }
            uctx.tls = engine;
            upstream_watch_fd = tls_engine_notify_fd(engine);
            upstream_fd = -1;
            uctx.fd = -1;
            if (tls_engine_wait_ready(engine) == 0) break;
            int retryable = tls_engine_start_retryable(engine);
            int handshake_error = errno ? errno : EIO;
            log_red("[TLS-DIAG] TLS Engine handshake failed error=%s retryable=%d address=%s",
                    strerror(handshake_error), retryable, upstream_address);
            (void)tls_engine_join(engine);
            tls_engine_destroy(engine);
            uctx.tls = NULL;
            upstream_watch_fd = -1;
            if (!retryable || tls_attempt + 1 >= TLS_CONNECT_MAX_ADDR_ATTEMPTS) {
                write_marker(NEED_RESTART_FILE, "TLS handshake failed");
                goto fail_cleanup;
            }
            snprintf(failed_tls_addresses[excluded_tls_count],
                     sizeof(failed_tls_addresses[excluded_tls_count]), "%s",
                     upstream_address);
            excluded_tls_addresses[excluded_tls_count] =
                failed_tls_addresses[excluded_tls_count];
            excluded_tls_count++;
            tls_attempt++;
            log_yellow("[TLS-DIAG] TLS transport failed at %s; trying another resolved address",
                       failed_tls_addresses[excluded_tls_count - 1]);
            upstream_fd = tcp_connect_host_excluding(
                dial_host, dial_port, excluded_tls_addresses, excluded_tls_count,
                upstream_address, sizeof(upstream_address));
            if (upstream_fd < 0) {
                log_red("[TLS-DIAG] no alternate upstream address available after TLS failure");
                write_marker(NEED_RESTART_FILE, "TLS handshake failed; no alternate address");
                goto fail_cleanup;
            }
            uctx.fd = upstream_fd;
            upstream_libssh2_socket = upstream_fd;
            upstream_watch_fd = upstream_fd;
            uctx.last_activity_ms = now_ms();
        }
        char tls_version[32] = "unknown";
        char tls_cipher[128] = "unknown";
        if (tls_engine_copy_negotiated(uctx.tls, tls_version, sizeof(tls_version),
                                        tls_cipher, sizeof(tls_cipher)) != 0) {
            log_red("Could not read negotiated TLS parameters from TLS Engine");
            write_marker(NEED_RESTART_FILE, "TLS Engine state unavailable");
            goto fail_cleanup;
        }
        log_blue("TLS Connected: %s (%s) remote=%s attempts=%zu",
                 tls_version, tls_cipher, upstream_address, tls_attempt + 1);
        log_blue("TLS Engine owner-thread ready; SSH Owner has no SSL* access");
    }

    int has_embedded_banner = 0;
    char *translated = translate_payload(raw_payload, &cfg, is_tls, &has_embedded_banner);
    free(raw_payload);
    raw_payload = NULL;
    if (!translated) {
        log_red("Gagal membangun payload (alokasi atau generator random gagal)");
        write_marker(NEED_RESTART_FILE,"payload translation failed");
        goto fail_cleanup;
    }
    if (has_embedded_banner) {
        uctx.skip_ssh_banner_bytes = strlen(SSH_CLIENT_BANNER "\r\n");
    }

    char *split_ds = strstr(translated, "[delay_split]");
    char *split_s = strstr(translated, "[split]");
    if (split_ds) {
        log_blue("Sending HTTP Payload (delay_split)...");
        const char *p2 = split_ds + strlen("[delay_split]");
        if (split_ds > translated) {
            uctx.expect_connect_resp = starts_with_connect_request(translated);
            if (raw_write_all_nb(&uctx, translated, (size_t)(split_ds - translated), 10000) < 0) {
                log_red("Gagal mengirim payload part 1"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
        } else {
            uctx.expect_connect_resp = starts_with_connect_request(p2);
        }
        delay_wait_and_drain(&uctx, cfg.delay_ms);
        if (*p2 && raw_write_all_nb(&uctx, p2, strlen(p2), 10000) < 0) {
            log_red("Gagal mengirim payload part 2"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
        }
    } else if (split_s) {
        log_blue("Sending HTTP Payload (split)...");
        const char *p2 = split_s + strlen("[split]");
        if (split_s > translated) {
            uctx.expect_connect_resp = starts_with_connect_request(translated);
            if (raw_write_all_nb(&uctx, translated, (size_t)(split_s - translated), 10000) < 0) {
                log_red("Gagal mengirim payload part 1"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
            long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
            int split_rc = 0;
            do {
                uctx.last_http_code = 0;
                while ((split_rc = consume_one_http_response(&uctx, 1)) == -2) {
                    if (wait_upstream_event(&uctx, POLLIN, deadline, 0) <= 0) {
                        split_rc = -1;
                        break;
                    }
                }
            } while (split_rc == 0 && !uctx.tunnel_established &&
                     uctx.last_http_code >= 100 && uctx.last_http_code < 200);
            if (split_rc < 0) {
                log_red("Gagal menerima respons HTTP split"); write_marker(NEED_RESTART_FILE, "split wait"); free(translated); goto fail_cleanup;
            }
        }
        if (*p2) {
            if (split_s == translated || starts_with_http_request(p2)) {
                uctx.tunnel_established = 0;
                uctx.last_http_code = 0;
                uctx.expect_connect_resp = starts_with_connect_request(p2);
            }
            if (raw_write_all_nb(&uctx, p2, strlen(p2), 10000) < 0) {
                log_red("Gagal mengirim payload part 2"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
        }
    } else if (*translated) {
        log_blue("Sending HTTP Payload...");
        uctx.expect_connect_resp = starts_with_connect_request(translated);
        if (raw_write_all_nb(&uctx, translated, strlen(translated), 10000) < 0) {
            log_red("Gagal mengirim payload"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
        }
    }
    free(translated);

    session = libssh2_session_init_ex(NULL, NULL, NULL, &uctx);
    if (!session) {
        log_red("libssh2_session_init gagal");
        goto fail_cleanup;
    }
#if LIBSSH2_VERSION_NUM >= 0x010b01
    /* libssh2 1.11.1+ has the typed callback API. */
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_RECV, (libssh2_cb_generic *)ssh_recv_cb);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND, (libssh2_cb_generic *)ssh_send_cb);
#else
    /* OpenWrt 24.10 ships libssh2 1.11.0, which still uses the legacy API. */
    libssh2_session_callback_set(session, LIBSSH2_CALLBACK_RECV, (void *)ssh_recv_cb);
    libssh2_session_callback_set(session, LIBSSH2_CALLBACK_SEND, (void *)ssh_send_cb);
#endif
    libssh2_session_banner_set(session, SSH_CLIENT_BANNER);
    libssh2_session_flag(session, LIBSSH2_FLAG_SIGPIPE, 0);
    libssh2_session_set_blocking(session, 0);

    log_blue("SSH Client : %s (libssh2)", SSH_CLIENT_BANNER + 8);
    log_blue("Starting Key Exchange");

#ifdef SSH_CORE_MIPSEL_24KC
    /*
     * The r40 Datapacket run confirmed that AES-128-CTR + HMAC-SHA2-256
     * is slower than the already-measured AES-GCM path on the MIPS software
     * crypto backend (5.63 vs 8.88 MiB/s SOCKS5). Restore AES-GCM first for
     * MT7621; keep CTR as a compatibility fallback. The S2C ring is also
     * doubled to 256 KiB to reduce relay-pump/read-call overhead per batch.
     * Other architectures keep their existing cipher preference order.
     */
    const char *ssh_cipher_pref =
        "aes128-gcm@openssh.com,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com";
#else
    const char *ssh_cipher_pref =
        "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr";
#endif
    int cipher_cs_rc = libssh2_session_method_pref(
        session, LIBSSH2_METHOD_CRYPT_CS, ssh_cipher_pref);
    int cipher_sc_rc = libssh2_session_method_pref(
        session, LIBSSH2_METHOD_CRYPT_SC, ssh_cipher_pref);
#ifdef SSH_CORE_MIPSEL_24KC
    if (cipher_cs_rc == 0 && cipher_sc_rc == 0) {
        log_blue("MT7621 SSH cipher preference: AES-128-GCM first (AES-CTR fallback)");
    } else {
        log_yellow("MT7621 SSH cipher preference could not be applied (cs=%d sc=%d); using libssh2 defaults",
                   cipher_cs_rc, cipher_sc_rc);
    }
#else
    (void)cipher_cs_rc;
    (void)cipher_sc_rc;
#endif

    {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int hs_rc;
        while ((hs_rc = libssh2_session_handshake(session, upstream_libssh2_socket)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) { hs_rc = -1; break; }
        }
        if (hs_rc != 0) {
            char *emsg = NULL;
            libssh2_session_last_error(session, &emsg, NULL, 0);
            if (upstream_http_response_rejected(&uctx)) {
                log_red("HTTP/Proxy Rejected (%d): %s", uctx.last_http_code, uctx.last_status);
                write_marker(NEED_RESTART_FILE, uctx.last_status[0] ? uctx.last_status : "http rejected");
            } else {
                log_red("SSH Handshake/KEX Failed: %s", emsg ? emsg : "timeout/error");
                write_marker(KEX_FAILED_FILE, emsg ? emsg : "kex failed");
            }
            goto fail_cleanup;
        }
    }

    const char *srv_banner = libssh2_session_banner_get(session);
    if (srv_banner) {
        const char *sv = strncmp(srv_banner, "SSH-2.0-", 8) == 0 ? srv_banner + 8 : srv_banner;
        log_blue("SSH Server : %s", sv);
    }

    if (verify_ssh_hostkey(session, &cfg) < 0) {
        goto fail_cleanup;
    }

    const char *authlist = NULL;
    {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int list_timed_out = 0;
        while (1) {
            authlist = libssh2_userauth_list(session, cfg.username, (unsigned int)strlen(cfg.username));
            if (authlist || libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) break;
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                list_timed_out = 1;
                break;
            }
        }
        if (list_timed_out) {
            log_red("Authentication Timeout (userauth_list)");
            write_marker(NEED_RESTART_FILE, "auth list timeout");
            goto fail_cleanup;
        }
    }

    int auth_ok = 0;
    const char *auth_method_used = "none";
    log_blue("[AUTH-DIAG] server methods: %s",
             authlist ? authlist : "(unavailable; password fallback will be attempted)");
    if (!authlist) {
        log_yellow("[AUTH-DIAG] userauth_list returned no method list; session_errno=%d",
                   libssh2_session_last_errno(session));
    }

    if (!authlist || auth_method_offered(authlist, "password")) {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int auth_rc;
        while ((auth_rc = libssh2_userauth_password(session, cfg.username, cfg.password)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                log_red("Authentication Timeout (password)");
                write_marker(NEED_RESTART_FILE, "password auth timeout");
                goto fail_cleanup;
            }
        }
        if (auth_rc == 0) {
            auth_ok = 1;
            auth_method_used = "password";
        } else {
            log_yellow("[AUTH-DIAG] password method rejected: rc=%d session_errno=%d",
                       auth_rc, libssh2_session_last_errno(session));
        }
    } else {
        log_yellow("[AUTH-DIAG] server did not advertise password authentication");
    }

    if (!auth_ok && (!authlist || auth_method_offered(authlist, "keyboard-interactive"))) {
        g_kbd_password = cfg.password;
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int auth_rc;
        while ((auth_rc = libssh2_userauth_keyboard_interactive(session, cfg.username, kbd_auth_cb)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                log_red("Authentication Timeout (keyboard-interactive)");
                write_marker(NEED_RESTART_FILE, "kbdint auth timeout");
                goto fail_cleanup;
            }
        }
        if (auth_rc == 0) {
            auth_ok = 1;
            auth_method_used = "keyboard-interactive";
        } else {
            log_yellow("[AUTH-DIAG] keyboard-interactive method rejected: rc=%d session_errno=%d",
                       auth_rc, libssh2_session_last_errno(session));
        }
    } else if (!auth_ok && authlist) {
        log_yellow("[AUTH-DIAG] server did not advertise keyboard-interactive authentication");
    }

    if (!auth_ok) {
        char *emsg = NULL;
        int auth_error_code = libssh2_session_last_errno(session);
        libssh2_session_last_error(session, &emsg, NULL, 0);
        log_red("Authentication Failed: %s (code=%d methods=%s username_len=%zu password_len=%zu)",
                emsg ? emsg : "Permission denied", auth_error_code,
                authlist ? authlist : "unknown",
                strlen(cfg.username), strlen(cfg.password));
        write_marker(AUTH_FAILED_FILE, emsg ? emsg : "Permission denied");
        goto fail_cleanup;
    }

    log_blue("[AUTH-DIAG] authentication accepted via %s", auth_method_used);

    log_blue("Session Keys Established");
    {
        const char *cp = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC);
        const char *mc = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC);
        log_blue("SSH Cipher: %s | MAC: %s", cp ? cp : "?", mc ? mc : "?");
    }

    listen_fd = socket(listen_addr.ss_family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_red("Gagal membuat socket SOCKS5: %s", strerror(errno));
        write_marker(NEED_RESTART_FILE, "SOCKS5 socket failed");
        goto fail_cleanup;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (g_worker_count > 1) {
#ifdef SO_REUSEPORT
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
            log_red("SO_REUSEPORT gagal untuk worker %d/%d: %s",
                    g_worker_id + 1, g_worker_count, strerror(errno));
            goto fail_cleanup;
        }
#else
        log_red("Build target tidak menyediakan SO_REUSEPORT; multi-worker tidak didukung");
        goto fail_cleanup;
#endif
    }
    if (listen_addr.ss_family == AF_INET6) {
        int v6_only = 1;
        if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)) < 0) {
            log_red("Gagal mengatur IPv6-only SOCKS listener: %s", strerror(errno));
            goto fail_cleanup;
        }
    }
    if (set_nonblock(listen_fd, 1) < 0 ||
        bind(listen_fd, (struct sockaddr *)&listen_addr, listen_addr_len) < 0 ||
        listen(listen_fd, 128) < 0) {
        log_red("Gagal membuka SOCKS5 di %s:%d (%s)", listen_ip, listen_port, strerror(errno));
        write_marker(NEED_RESTART_FILE, "SOCKS5 bind failed");
        goto fail_cleanup;
    }
    log_blue("SOCKS5 Listening : %s:%d", listen_ip, listen_port);

    epfd = epoll_create1(0);
    if (epfd < 0) {
        log_red("epoll_create1 gagal: %s", strerror(errno));
        write_marker(NEED_RESTART_FILE, "epoll_create1 failed");
        goto fail_cleanup;
    }

    /* One SSH Owner; CPU topology controls only the bounded local I/O pool. */
    io_pool = io_worker_pool_create(g_io_worker_count,
                                   SSH_CORE_IO_QUEUE_CAPACITY,
                                   io_worker_socket_execute, NULL);
    if (!io_pool) {
        log_red("Unable to create local socket I/O worker pool: %s", strerror(errno));
        goto fail_cleanup;
    }
    io_tracker = io_worker_completion_tracker_create(
        g_io_worker_count, SSH_CORE_IO_QUEUE_CAPACITY);
    if (!io_tracker) {
        log_red("Unable to create I/O completion tracker: %s", strerror(errno));
        goto fail_cleanup;
    }
    g_io_pool = io_pool;
    g_io_tracker = io_tracker;
    struct epoll_event io_completion_ev = {
        .events = EPOLLIN,
        .data.ptr = &g_worker_completion_tag
    };
    for (uint32_t io_worker_id = 0U; io_worker_id < g_io_worker_count; io_worker_id++) {
        int io_completion_fd = io_worker_pool_completion_fd(io_pool, io_worker_id);
        if (io_completion_fd < 0) {
            log_red("Unable to obtain I/O worker %u completion fd: %s",
                    io_worker_id, strerror(errno));
            goto fail_cleanup;
        }
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, io_completion_fd, &io_completion_ev) < 0) {
            log_red("Unable to register I/O worker %u completion fd: %s",
                    io_worker_id, strerror(errno));
            goto fail_cleanup;
        }
    }
    log_blue("[IO worker] pool started: %u workers (CPU detected=%ld, cap=%u), one SSH session",
             g_io_worker_count, g_detected_cpu_count,
             (unsigned int)IO_WORKER_POOL_MAX_WORKERS);

    uint32_t upstream_ev = uctx.tls ? EPOLLIN : (EPOLLIN | EPOLLRDHUP);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &g_listen_tag };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        log_red("epoll_ctl ADD listen_fd gagal: %s", strerror(errno));
        goto fail_cleanup;
    }
    ev.events = upstream_ev;
    ev.data.ptr = &g_upstream_tag;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, upstream_watch_fd, &ev) < 0) {
        log_red("epoll_ctl ADD upstream_fd gagal: %s", strerror(errno));
        goto fail_cleanup;
    }

    if (cfg.keepalive_sec > 0) {
        libssh2_keepalive_config(session, 0, (unsigned int)cfg.keepalive_sec);
    }

    struct epoll_event events[MAX_EVENTS];
    if (g_log_perf) {
        libssh2_session_diag_timing_enable(session, 1);
        perf_begin(now_ms());
    }
    int force_next_tick = 0;
    int idle_rx_paused = 0;
    long long last_ka_try_ms = 0;
    long long last_emfile_log_ms = 0;
    exit_code = 0;

    while (!stop_requested()) {
        int timeout_ms = upstream_epoll_timeout_ms(&uctx, force_next_tick, now_ms());
        if (io_pool && timeout_ms > 100) {
            uint32_t io_workers = io_worker_pool_worker_count(io_pool);
            for (uint32_t io_worker_id = 0U; io_worker_id < io_workers; io_worker_id++) {
                if (io_worker_pool_outstanding(io_pool, io_worker_id) > 0U) {
                    timeout_ms = 100;
                    break;
                }
            }
        }
        long long epoll_started_ms = g_log_perf ? now_ms() : 0;
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout_ms);
        if (g_log_perf) {
            long long waited = now_ms() - epoll_started_ms;
            if (waited < 0) waited = 0;
            g_perf_stats.epoll_calls++;
            g_perf_stats.epoll_wait_ms += (uint64_t)waited;
            if ((uint64_t)waited > g_perf_stats.epoll_wait_max_ms)
                g_perf_stats.epoll_wait_max_ms = (uint64_t)waited;
            if (nfds == 0) g_perf_stats.epoll_timeouts++;
            else if (nfds > 0) g_perf_stats.epoll_wakeups++;
        }
        if (nfds < 0) {
            if (errno == EINTR) continue;
            exit_code = 1;
            break;
        }

        /* Poll completions even if an eventfd notification was lost. */
        if (drain_io_worker_completions(epfd, io_pool, io_tracker) < 0) {
            log_red("[IO worker] fatal completion/lifetime invariant; stopping relay");
            exit_code = 1;
            request_stop();
            break;
        }
        int worker_error = io_pool ? io_worker_pool_error(io_pool) : 0;
        if (worker_error != 0) {
            log_red("Local socket I/O worker pool failed: %s", strerror(worker_error));
            exit_code = 1;
            break;
        }

        int upstream_readable = 0;
        reap_retired_clients(epfd);

        for (int i = 0; i < nfds; i++) {
            uint64_t event_token = events[i].data.u64;
            void *ptr = (void *)(uintptr_t)event_token;
            uint32_t e = events[i].events;

            if (ptr == &g_worker_completion_tag) {
                if (drain_io_worker_completions(epfd, io_pool, io_tracker) < 0) {
                    log_red("[IO worker] fatal completion/lifetime invariant; stopping relay");
                    exit_code = 1;
                    request_stop();
                    break;
                }
                continue;
            }

            uint64_t client_id = 0;
            if (client_event_token_decode(event_token, &client_id)) {
                client_conn_t *c = find_client_by_id(client_id);
                if (c) handle_client_io(epfd, c, e);
                continue;
            }

            if (ptr == &g_listen_tag) {
                if (uctx.hup_seen || listen_fd < 0) continue;
                while (1) {
                    int cfd = accept(listen_fd, NULL, NULL);
                    if (cfd < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EMFILE || errno == ENFILE) {
                            long long now_err_ms = now_ms();
                            if (now_err_ms - last_emfile_log_ms >= 5000LL) {
                                log_yellow("Batas FD tercapai (%s), menolak koneksi baru sementara", strerror(errno));
                                last_emfile_log_ms = now_err_ms;
                            }
                            usleep(5000);
                        }
                        break;
                    }
                    if (!reserve_client_slot(cfg.max_clients)) {
                        close(cfd);
                        continue;
                    }
                    if (set_nonblock(cfd, 1) < 0) {
                        release_client_slot();
                        close(cfd);
                        continue;
                    }
                    int nodelay = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                    client_conn_t *nc = calloc(1, sizeof(client_conn_t));
                    if (!nc) {
                        release_client_slot();
                        close(cfd);
                        continue;
                    }
                    nc->client_id = allocate_client_id();
                    if (nc->client_id == 0) {
                        release_client_slot();
                        close(cfd);
                        free(nc);
                        log_red("Client ID space exhausted; rejecting new connection");
                        continue;
                    }
                    nc->generation = 1;
                    if (client_lifetime_init(&nc->lifetime, nc->client_id, nc->generation) < 0) {
                        release_client_slot();
                        close(cfd);
                        free(nc);
                        log_red("Unable to initialize client lifetime token; rejecting connection");
                        continue;
                    }
                    nc->fd = cfd;
                    nc->state = ST_SOCKS_GREETING;
                    nc->epoll_events = EPOLLIN | EPOLLRDHUP;
                    nc->accepted_at_ms = now_ms();
                    nc->last_activity_ms = now_ms();

                    struct epoll_event cev = {
                        .events = nc->epoll_events,
                        .data.u64 = client_event_token_encode(nc->client_id)
                    };
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
                        release_client_slot();
                        close(cfd);
                        free(nc);
                        continue;
                    }
                    nc->in_epoll = 1;
                    nc->next = g_clients;
                    if (g_clients) g_clients->prev = nc;
                    g_clients = nc;
                    g_client_count++;
                    g_accepted_total++;
                }
            } else if (ptr == &g_upstream_tag) {
                if (uctx.tls) {
                    /* eventfd reports RX bytes and TX queue-space; only RX bytes
                     * and terminal state are inbound SSH readiness. */
                    tls_engine_drain_notify(uctx.tls);
                    int rx_pending = tls_engine_rx_pending(uctx.tls);
                    int rx_error = 0;
                    int rx_terminal = tls_engine_rx_terminal(uctx.tls, &rx_error);
                    if (tls_engine_tx_terminal(uctx.tls, NULL)) {
                        uctx.tx_terminal = 1;
                        uctx.hup_seen = 1;
                    }
                    if (rx_pending > 0) upstream_readable = 1;
                    if (rx_terminal && rx_pending == 0 && !uctx.rx_terminal) {
                        (void)mark_upstream_rx_terminal(
                            &uctx, rx_error ? -(ssize_t)rx_error : 0);
                        upstream_readable = 1;
                    }
                } else {
                    if (e & EPOLLERR) {
                        int so_err = 0;
                        socklen_t so_len = sizeof(so_err);
                        if (getsockopt(upstream_fd, SOL_SOCKET, SO_ERROR,
                                       &so_err, &so_len) == 0 && so_err)
                            uctx.tx_terminal = 1;
                        uctx.hup_seen = 1;
                        uctx.upstream_epoll_detached = 1;
                        upstream_readable = 1;
                    }
                    if (e & EPOLLHUP) {
                        uctx.hup_seen = 1;
                        uctx.upstream_epoll_detached = 1;
                        upstream_readable = 1;
                    } else if (e & EPOLLRDHUP) {
                        uctx.hup_seen = 1;
                        upstream_readable = 1;
                    }
                    if (e & EPOLLIN) upstream_readable = 1;
                }
            }
        }

        if (stop_requested()) break;

        if (uctx.upstream_epoll_detached && upstream_ev != 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, upstream_watch_fd, NULL) == 0 || errno == ENOENT)
                upstream_ev = 0;
        }
        if (uctx.hup_seen) {
            begin_upstream_drain(epfd, &listen_fd, &uctx);
            reject_nonrelay_clients_on_upstream_hup(epfd);
        }

        /*
         * Do not issue a passive TLS EOF-read probe on the shared object.
         * Nonblocking WANT state belongs to the active I/O callback; the SSH
         * channel pump remains the sole consumer of upstream application data.
         */
        /*
         * SSH WINDOW_ADJUST arrives on the upstream transport. A local client
         * socket may already be half-closed, so its events cannot wake this path.
         */
        if (uctx.hup_seen || upstream_readable || tls_buffered_input_pending(&uctx)) {
            if (upstream_readable && has_window_waiter() && g_log_perf)
                g_perf_stats.window_waiter_upstream_events++;
            retry_window_waiters();
        }

        long long now_msec = now_ms();
        for (client_conn_t *c = g_clients, *nxt = NULL; c; c = nxt) {
            nxt = c->next;
            if (!uctx.hup_seen && client_cleanup_timeout_due(c, now_msec)) {
                log_red("Pending SSH channel cleanup exceeded %d ms; forcing session teardown",
                        SSH_CHANNEL_CLEANUP_TIMEOUT_MS);
                write_marker(NEED_RESTART_FILE, "ssh channel cleanup timeout");
                exit_code = 1;
                g_skip_libssh2_cleanup = 1;
                request_stop();
                break;
            }
            if (c->close_after_ctrl && c->fd >= 0 && c->ctrl_close_deadline_ms > 0 &&
                now_msec >= c->ctrl_close_deadline_ms) {
                start_closing_client(epfd, c);
                continue;
            }
            if ((c->state == ST_SOCKS_GREETING || c->state == ST_SOCKS_REQUEST) &&
                (now_msec - c->accepted_at_ms) >= (long long)SOCKS_HS_TIMEOUT_SEC * 1000LL) {
                start_closing_client(epfd, c);
            } else if (!uctx.hup_seen && relay_idle_timeout_due(c, cfg.idle_timeout_sec, now_msec)) {
                /* Idle expiry is intentionally silent; the timeout cleanup remains active. */
                start_closing_client(epfd,c);
            } else if (c->state == ST_SSH_OPENING && c == g_opening_client && c->open_started_ms > 0) {
                long long elapsed = now_msec - c->open_started_ms;
                if (!uctx.hup_seen && elapsed >= SSH_OPEN_HARD_TO_MS) {
                    log_red("Pembukaan channel SSH macet >%d detik (%s:%u), memicu restart sesi",
                            SSH_OPEN_HARD_TO_MS / 1000, c->target_host, (unsigned)c->target_port);
                    write_marker(NEED_RESTART_FILE, "channel open hard timeout");
                    exit_code = 1;
                    request_stop();
                    break;
                } else if (elapsed >= SSH_OPEN_SOFT_TO_MS && !c->abort_on_open && !c->close_after_ctrl && c->fd >= 0) {
                    c->abort_on_open = 1;
                    send_socks_err_and_close(epfd, c, 0x04);
                }
            }
        }

        if (stop_requested()) break;

        int rounds = 0;
        int agg_dirs = 0;
        int did_ssh_read = 0;
        force_next_tick = 0;

        uint64_t upstream_rx_before_pump = uctx.rx_seq;
        while (!stop_requested() && rounds < 16) {
            int round_dirs = 0;
            int round_read = 0;
            int pump_rc = pump_ssh_channels(epfd, session, &uctx, &round_dirs, &round_read);
            agg_dirs |= round_dirs;
            did_ssh_read |= round_read;
            if (pump_rc < 0) {
                log_red("Sesi SSH terputus");
                write_marker(NEED_RESTART_FILE, "ssh session lost");
                exit_code = 1;
                request_stop();
                break;
            }
            if (pump_rc == 0) break;
            rounds++;
        }

        if (stop_requested()) break;

        if (did_ssh_read || g_opening_client != NULL ||
            has_readable_relay_channel() || has_window_waiter()) {
            idle_rx_paused = 0;
        } else if (upstream_readable && g_pending_op == PENDING_NONE &&
                   uctx.rx_seq == upstream_rx_before_pump) {
            /* Avoid a level-triggered EPOLLIN spin when no channel currently
             * has room to consume buffered SSH transport data. A new OPEN,
             * reader, or window waiter re-arms upstream input below. */
            idle_rx_paused = 1;
        }

        if (uctx.upstream_epoll_detached && upstream_ev != 0) {
            if (epoll_ctl(epfd, EPOLL_CTL_DEL, upstream_watch_fd, NULL) == 0 || errno == ENOENT)
                upstream_ev = 0;
        }
        if (uctx.hup_seen) {
            begin_upstream_drain(epfd, &listen_fd, &uctx);
            reject_nonrelay_clients_on_upstream_hup(epfd);
            unsigned long queued_libssh2_bytes = 0;
            unsigned int stalled_channels = 0;
            unsigned int incomplete_channels = 0;
            upstream_drain_result_t drain_result = upstream_drain_status(
                &uctx, &queued_libssh2_bytes, &stalled_channels,
                &incomplete_channels);
            if (drain_result == UPSTREAM_DRAIN_GRACEFUL) {
                log_yellow("Upstream graceful drain complete: all relay channels reached SSH EOF and libssh2 queues are empty");
                write_marker(NEED_RESTART_FILE, "upstream eof after drain");
                exit_code = 1;
                g_skip_libssh2_cleanup = 1;
                request_stop();
                break;
            }
            if (drain_result == UPSTREAM_DRAIN_FORCED) {
                log_red("Upstream forced teardown: rx_terminal=%d rx_rc=%d tx_terminal=%d stalled_channels=%u incomplete_channels=%u libssh2_queued=%lu bytes",
                        uctx.rx_terminal, uctx.rx_terminal_rc, uctx.tx_terminal,
                        stalled_channels, incomplete_channels, queued_libssh2_bytes);
                write_marker(NEED_RESTART_FILE, "upstream forced teardown");
                exit_code = 1;
                g_skip_libssh2_cleanup = 1;
                request_stop();
                break;
            }
            if (upstream_drain_timed_out(&uctx, now_ms())) {
                log_red("Upstream drain exceeded %d ms; forcing session teardown",
                        UPSTREAM_DRAIN_TIMEOUT_MS);
                write_marker(NEED_RESTART_FILE, "upstream drain timeout");
                exit_code = 1;
                g_skip_libssh2_cleanup = 1;
                request_stop();
                break;
            }
        }

        if (!uctx.hup_seen && keepalive_can_start(&uctx, g_pending_op) &&
            cfg.keepalive_sec > 0 &&
            (now_msec - uctx.last_activity_ms) >= (long long)cfg.keepalive_sec * 1000LL &&
            (now_msec - last_ka_try_ms) >= 1000LL) {
            int next_sec = 0;
            last_ka_try_ms = now_msec;
            tls_begin_libssh2_call(&uctx);
            int ka_rc = libssh2_keepalive_send(session, &next_sec);
            tls_finish_libssh2_call(&uctx, ka_rc == LIBSSH2_ERROR_EAGAIN);
            if (ka_rc == 0) {
                uctx.last_activity_ms = now_msec;
                if (g_log_backpressure) log_blue("SSH keepalive sent");
            } else if (ka_rc == LIBSSH2_ERROR_EAGAIN) {
                int ka_dirs = libssh2_session_block_directions(session);
                agg_dirs |= ka_dirs;
                set_pending_operation(NULL, PENDING_KEEPALIVE);
            } else {
                log_red("Keepalive SSH gagal");
                write_marker(NEED_RESTART_FILE, "keepalive failed");
                exit_code = 1;
                request_stop();
                break;
            }
        }

        if (rounds == 16 ||
            (tls_buffered_input_pending(&uctx) &&
             (g_opening_client != NULL || has_readable_relay_channel() ||
              has_window_waiter()))) {
            force_next_tick = 1;
        }

        uint32_t want_up = upstream_epoll_interest(
            &uctx, g_pending_op, agg_dirs, &idle_rx_paused,
            g_opening_client != NULL,
            has_readable_relay_channel(), has_window_waiter());
        if (!uctx.upstream_epoll_detached)
            update_epoll(epfd, upstream_watch_fd, &g_upstream_tag, &upstream_ev, want_up);

        perf_log_interval(now_ms(), session);
    }

    log_blue("Worker %d/%d stopping; accepted_total=%llu",
             g_worker_id + 1, g_worker_count,
             (unsigned long long)g_accepted_total);
    if (!g_skip_libssh2_cleanup && shutdown_io_pending(&uctx)) {
        log_yellow("A libssh2/OpenSSL operation is still pending at process shutdown; skipping further transport I/O");
        g_skip_libssh2_cleanup = 1;
    }
    if (io_pool) {
        (void)io_worker_pool_request_stop(io_pool, 1);
        if (io_worker_pool_join(io_pool, SHUTDOWN_IO_TIMEOUT_MS) != 0)
            log_yellow("I/O worker pool join timed out; retaining referenced client storage");
        if (drain_io_worker_completions(epfd, io_pool, io_tracker) < 0)
            exit_code = 1;
    }
    while (g_clients) {
        client_conn_t *c = g_clients;
        /* remove_client owns FD detachment and may have to defer it. */
        remove_client(epfd, c);
    }
    /* No worker pool is submitted to yet; any nonzero ref here is a hard
     * shutdown invariant violation and must not be freed unsafely. */
    reap_retired_clients(epfd);
    clear_pending_operation();
    g_opening_client = NULL;
    g_io_pool = NULL;
    g_io_tracker = NULL;
    if (io_tracker) {
        if (io_worker_completion_tracker_outstanding(io_tracker) == 0U)
            (void)io_worker_completion_tracker_destroy(io_tracker);
        else
            log_yellow("I/O completion tracker retains outstanding tasks during shutdown");
        io_tracker = NULL;
    }
    if (io_pool) {
        if (io_worker_pool_destroy(io_pool) < 0)
            log_yellow("I/O worker pool retained because workers did not fully join");
        io_pool = NULL;
    }
    if (epfd >= 0) close(epfd);
    if (listen_fd >= 0) close(listen_fd);
    long long shutdown_deadline_ms = now_ms() + SHUTDOWN_IO_TIMEOUT_MS;
    if (session && !g_skip_libssh2_cleanup) {
        int disconnect_rc = 0;
        if (exit_code == 0) {
            disconnect_rc = session_disconnect_with_deadline(
                session, &uctx, shutdown_deadline_ms);
            if (disconnect_rc == LIBSSH2_ERROR_EAGAIN) {
                log_yellow("SSH disconnect remained pending after deadline; skipping session_free and TLS shutdown");
                g_skip_libssh2_cleanup = 1;
            } else if (disconnect_rc < 0) {
                log_yellow("libssh2_session_disconnect returned %d during shutdown", disconnect_rc);
            }
        }
        if (!g_skip_libssh2_cleanup) {
            int free_rc = session_free_with_deadline(
                &session, &uctx, shutdown_deadline_ms);
            if (free_rc == LIBSSH2_ERROR_EAGAIN) {
                log_yellow("Session cleanup remained pending after deadline; skipping TLS shutdown");
                g_skip_libssh2_cleanup = 1;
            } else if (free_rc < 0) {
                log_yellow("libssh2_session_free returned %d during shutdown", free_rc);
                g_skip_libssh2_cleanup = 1;
            }
        }
    } else if (session && g_skip_libssh2_cleanup) {
        log_yellow("Skipping libssh2 disconnect/free; process teardown will reclaim remaining resources");
    }
    if (uctx.tls) {
        int graceful = exit_code == 0 && !g_skip_libssh2_cleanup && session == NULL;
        if (graceful)
            log_blue("TLS Engine: flushing queued SSH bytes and sending close_notify");
        else if (g_skip_libssh2_cleanup)
            log_yellow("TLS Engine: aborting because SSH cleanup was incomplete");
        tls_engine_stop(uctx.tls, graceful, SHUTDOWN_IO_TIMEOUT_MS);
        if (tls_engine_join(uctx.tls) != 0)
            log_yellow("TLS Engine join failed: %s", strerror(errno));
        tls_engine_destroy(uctx.tls);
        uctx.tls = NULL;
        upstream_watch_fd = -1;
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    if (upstream_fd >= 0) close(upstream_fd);
    return exit_code;

fail_cleanup:
    if (raw_payload) free(raw_payload);
    if (io_pool) {
        (void)io_worker_pool_request_stop(io_pool, 1);
        if (io_worker_pool_join(io_pool, SHUTDOWN_IO_TIMEOUT_MS) == 0) {
            if (io_tracker && drain_io_worker_completions(epfd, io_pool, io_tracker) < 0)
                log_red("[IO worker] startup cleanup found a completion invariant failure");
            if (io_tracker && io_worker_completion_tracker_outstanding(io_tracker) == 0U)
                (void)io_worker_completion_tracker_destroy(io_tracker);
            if (io_worker_pool_destroy(io_pool) == 0) io_pool = NULL;
            io_tracker = NULL;
        } else {
            log_yellow("Startup cleanup: worker pool join timed out; retaining worker-owned state");
        }
    }
    g_io_pool = NULL;
    g_io_tracker = NULL;
    if (epfd >= 0) close(epfd);
    if (listen_fd >= 0) close(listen_fd);
    if (session) {
        log_yellow("Startup failed; skipping further libssh2 I/O before process teardown");
        g_skip_libssh2_cleanup = 1;
    }
    if (uctx.tls) {
        tls_engine_stop(uctx.tls, 0, 1);
        (void)tls_engine_join(uctx.tls);
        tls_engine_destroy(uctx.tls);
        uctx.tls = NULL;
        upstream_watch_fd = -1;
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    if (upstream_fd >= 0) close(upstream_fd);
    return 1;
}

typedef struct {
    int argc;
    char **argv;
    int worker_id;
    int worker_count;
    int result;
    int skip_libssh2_exit;
} worker_launch_t;

static int resolve_worker_count(int argc, char **argv, int *out_count) {
    if (!out_count) return -1;

    g_detected_cpu_count = detect_available_cpu_count();
    int requested_workers = 1;
    int manual_workers = 0;
    const char *env_file = NULL;
    g_worker_count_auto = 1;

    /* Keep legacy options parseable, but never turn CPU count into SSH sessions.
     * One process must create one upstream TCP/TLS connection and one SSH login. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-env") == 0 && i + 1 < argc) {
            env_file = argv[++i];
        } else if (strcmp(argv[i], "-workers") == 0) {
            if (i + 1 >= argc ||
                parse_int_range(argv[++i], 1, MAX_WORKERS, &requested_workers) < 0) {
                fprintf(stderr, "-workers harus 1..%d\n", MAX_WORKERS);
                return -1;
            }
            manual_workers = 1;
        }
    }

    if (!manual_workers && env_file) {
        FILE *f = fopen(env_file, "r");
        if (f) {
            char line[2048];
            while (fgets(line, sizeof(line), f)) {
                trim_ws(line);
                if (!line[0] || line[0] == '#') continue;
                char *eq = strchr(line, '=');
                if (!eq) continue;
                *eq = 0;
                char *key = line;
                char *value = eq + 1;
                trim_ws(key);
                trim_ws(value);
                size_t n = strlen(value);
                if (n >= 2 &&
                    ((value[0] == 39 && value[n - 1] == 39) ||
                     (value[0] == 34 && value[n - 1] == 34))) {
                    value[n - 1] = 0;
                    value++;
                }
                if (strcmp(key, "WORKERS") == 0) {
                    if (parse_int_range(value, 1, MAX_WORKERS, &requested_workers) < 0) {
                        fclose(f);
                        fprintf(stderr, "WORKERS harus 1..%d\n", MAX_WORKERS);
                        return -1;
                    }
                    manual_workers = 1;
                }
            }
            fclose(f);
        }
    }

    g_worker_count_auto = 1;
    /* CPU topology sizes only the auxiliary socket-I/O pool. The process
     * still starts exactly one SSH Owner and one upstream SSH session. */
    g_io_worker_count = io_worker_count_for_cpu_count(g_detected_cpu_count);
    *out_count = 1;
    /* Preserve the established single-session diagnostic consumed by the
     * integration harness; report the auxiliary pool separately. */
    fprintf(stderr,
            "[CPU] detected=%ld SSH_sessions=1 mode=single-session; "
            "legacy requested workers=%d%s\n",
            g_detected_cpu_count, requested_workers,
            manual_workers ? " (ignored to prevent multiple SSH logins)" : "");
    fprintf(stderr,
            "[IO worker] CPU topology selected=%u/%u auxiliary I/O workers\n",
            g_io_worker_count, (unsigned int)IO_WORKER_POOL_MAX_WORKERS);
    return 0;
}

static void *worker_thread_main(void *opaque) {
    worker_launch_t *launch = (worker_launch_t *)opaque;
    g_worker_id = launch->worker_id;
    g_worker_count = launch->worker_count;
    launch->result = core_worker_run(launch->argc, launch->argv);
    launch->skip_libssh2_exit = g_skip_libssh2_cleanup;
    if (launch->result != 0) request_stop();
    return NULL;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-workers 1..%d] [-env FILE] [-payload-file FILE] [-socks 127.0.0.1:1080] [-verify-tls 0|1] [-tls-diag 0|1] [-allow-remote-socks 0|1] [-http-200-tunnel 0|1] [-idle-timeout SEC] [-hostkey SHA256:...] [-max-clients 1..256] [-log-backpressure 0|1] [-log-perf 0|1] [-log FILE|-]\n", argv[0], MAX_WORKERS);
            return 0;
        }
    }
    int worker_count = 1;
    if (resolve_worker_count(argc, argv, &worker_count) < 0) return 2;

    __atomic_store_n(&g_stop, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_total_client_count, 0, __ATOMIC_RELAXED);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    unlink(AUTH_FAILED_FILE);
    unlink(KEX_FAILED_FILE);
    unlink(NEED_RESTART_FILE);

    if (libssh2_init(0) != 0) {
        fprintf(stderr, "libssh2_init gagal\n");
        return 1;
    }

    int result = 0;
    int safe_to_call_libssh2_exit = 1;
    if (worker_count == 1) {
        g_worker_id = 0;
        g_worker_count = 1;
        result = core_worker_run(argc, argv);
        if (g_skip_libssh2_cleanup) safe_to_call_libssh2_exit = 0;
    } else {
        pthread_t threads[MAX_WORKERS];
        worker_launch_t launches[MAX_WORKERS];
        int created = 0;
        for (int i = 0; i < worker_count; i++) {
            memset(&launches[i], 0, sizeof(launches[i]));
            launches[i].argc = argc;
            launches[i].argv = argv;
            launches[i].worker_id = i;
            launches[i].worker_count = worker_count;
            int rc = pthread_create(&threads[i], NULL, worker_thread_main, &launches[i]);
            if (rc != 0) {
                fprintf(stderr, "pthread_create worker %d/%d gagal: %s\n",
                        i + 1, worker_count, strerror(rc));
                request_stop();
                result = 1;
                break;
            }
            created++;
        }
        for (int i = 0; i < created; i++) {
            int rc = pthread_join(threads[i], NULL);
            if (rc != 0) {
                fprintf(stderr, "pthread_join worker %d gagal: %s\n", i + 1, strerror(rc));
                result = 1;
                safe_to_call_libssh2_exit = 0;
            }
            if (launches[i].skip_libssh2_exit) safe_to_call_libssh2_exit = 0;
            if (launches[i].result != 0) result = 1;
        }
    }
    if (safe_to_call_libssh2_exit) {
        libssh2_exit();
    } else {
        fprintf(stderr, "Skipping libssh2_exit because a worker retained an unsafe pending session; process teardown will reclaim it.\n");
    }
    return result;
}

#endif /* SSH_CORE_PARSER_TEST */
