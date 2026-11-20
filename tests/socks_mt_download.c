#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS 32
#define HEADER_CAP 8192
#define TARGET_PORT 18080
#define EXPECTED_PATH "/slow-download"

typedef struct {
    int id, socks_port, result;
    uint64_t expected_bytes, received;
    const char *prefix;
    double elapsed_s;
    char error[192];
} worker_t;

static double mono_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}
static int send_all(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}
static int recv_exact(int fd, void *data, size_t len) {
    unsigned char *p = data;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}
static int socks_connect(int fd) {
    const unsigned char hello[3] = {5,1,0};
    unsigned char reply[2];
    if (send_all(fd, hello, sizeof(hello)) || recv_exact(fd, reply, 2) ||
        reply[0] != 5 || reply[1] != 0) return -1;
    const unsigned char request[10] = {
        5,1,0,1,10,0,2,2,(unsigned char)(TARGET_PORT >> 8),
        (unsigned char)TARGET_PORT
    };
    unsigned char response[4];
    if (send_all(fd, request, sizeof(request)) || recv_exact(fd, response, 4) ||
        response[0] != 5 || response[1] != 0) return -1;
    size_t tail = response[3] == 1 ? 6U : response[3] == 4 ? 18U :
                  response[3] == 3 ? 1U : 0U;
    unsigned char discard[18];
    return tail && recv_exact(fd, discard, tail) == 0 ? 0 : -1;
}
static int parse_headers(int fd, char *headers, size_t cap, uint64_t *length) {
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = recv(fd, headers + used, 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        used++;
        if (used >= 4 && !memcmp(headers + used - 4, "\r\n\r\n", 4)) break;
    }
    if (used + 1 >= cap) return -1;
    headers[used] = '\0';
    int status = 0;
    if (sscanf(headers, "HTTP/%*u.%*u %d", &status) != 1 || status != 200) return -1;
    char *cl = strcasestr(headers, "Content-Length:");
    if (!cl) return -1;
    cl += strlen("Content-Length:");
    while (*cl == ' ' || *cl == '\t') cl++;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(cl, &end, 10);
    if (errno || end == cl || !v) return -1;
    *length = (uint64_t)v;
    return 0;
}
static void set_error(worker_t *w, const char *msg) {
    snprintf(w->error, sizeof(w->error), "%s", msg);
    w->result = -1;
}
static void *download_worker(void *arg) {
    worker_t *w = arg;
    char path[256];
    snprintf(path, sizeof(path), "%s-%02d.bin", w->prefix, w->id);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { set_error(w, "socket failed"); return NULL; }
    struct timeval tv = {180,0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)w->socks_port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa))) {
        set_error(w, "SOCKS connect failed"); close(fd); return NULL;
    }
    double started = mono_seconds();
    if (socks_connect(fd)) {
        set_error(w, "SOCKS5 negotiation/CONNECT failed"); close(fd); return NULL;
    }
    char request[512];
    int request_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: 10.0.2.2:%d\r\nConnection: close\r\n\r\n",
        EXPECTED_PATH, TARGET_PORT);
    if (request_len <= 0 || (size_t)request_len >= sizeof(request) ||
        send_all(fd, request, (size_t)request_len)) {
        set_error(w, "HTTP request send failed"); close(fd); return NULL;
    }
    char headers[HEADER_CAP];
    uint64_t body_len = 0;
    if (parse_headers(fd, headers, sizeof(headers), &body_len)) {
        set_error(w, "HTTP response/header parse failed"); close(fd); return NULL;
    }
    if (body_len != w->expected_bytes) {
        set_error(w, "HTTP Content-Length mismatch"); close(fd); return NULL;
    }
    FILE *out = fopen(path, "wb");
    if (!out) { set_error(w, "output file open failed"); close(fd); return NULL; }
    unsigned char buffer[32768];
    uint64_t remaining = body_len;
    while (remaining) {
        size_t want = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        ssize_t n = recv(fd, buffer, want, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { set_error(w, "body truncated"); break; }
        if (fwrite(buffer, 1, (size_t)n, out) != (size_t)n) {
            set_error(w, "output write failed"); break;
        }
        w->received += (uint64_t)n;
        remaining -= (uint64_t)n;
    }
    if (fclose(out) && w->result == 0) set_error(w, "output close failed");
    close(fd);
    w->elapsed_s = mono_seconds() - started;
    if (w->result == 0 && w->received != w->expected_bytes)
        set_error(w, "byte count mismatch");
    if (w->result == 0) w->result = 1;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: %s <clients> <workers> <base-port> <expected-bytes> <output-prefix>\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    long clients = strtol(argv[1], &end, 10);
    if (!end || *end || clients < 1 || clients > MAX_CLIENTS) return 2;
    long workers = strtol(argv[2], &end, 10);
    if (!end || *end || workers < 1 || workers > clients) return 2;
    long base_port = strtol(argv[3], &end, 10);
    if (!end || *end || base_port < 1 || base_port + workers - 1 > 65535) return 2;
    unsigned long long expected = strtoull(argv[4], &end, 10);
    if (!end || *end || !expected || !argv[5][0]) return 2;
    signal(SIGPIPE, SIG_IGN);
    worker_t tasks[MAX_CLIENTS];
    pthread_t threads[MAX_CLIENTS];
    memset(tasks, 0, sizeof(tasks));
    double wall_started = mono_seconds();
    int created = 0;
    for (int i = 0; i < (int)clients; i++) {
        tasks[i].id = i;
        tasks[i].socks_port = (int)base_port + (i % (int)workers);
        tasks[i].expected_bytes = (uint64_t)expected;
        tasks[i].prefix = argv[5];
        if (pthread_create(&threads[i], NULL, download_worker, &tasks[i])) {
            snprintf(tasks[i].error, sizeof(tasks[i].error), "pthread_create failed");
            tasks[i].result = -1;
            break;
        }
        created++;
    }
    for (int i = 0; i < created; i++) pthread_join(threads[i], NULL);
    double wall = mono_seconds() - wall_started;
    int failures = 0;
    uint64_t total = 0;
    for (int i = 0; i < (int)clients; i++) {
        if (tasks[i].result != 1) {
            failures++;
            printf("MT_CLIENT id=%d socks_port=%d result=FAIL bytes=%llu error=%s\n",
                i, tasks[i].socks_port, (unsigned long long)tasks[i].received,
                tasks[i].error[0] ? tasks[i].error : "not-started");
        } else {
            total += tasks[i].received;
            double mbps = tasks[i].elapsed_s > 0 ?
                (double)tasks[i].received * 8.0 / tasks[i].elapsed_s / 1000000.0 : 0;
            printf("MT_CLIENT id=%d socks_port=%d result=PASS bytes=%llu elapsed_s=%.3f Mbps=%.3f\n",
                i, tasks[i].socks_port, (unsigned long long)tasks[i].received,
                tasks[i].elapsed_s, mbps);
        }
    }
    double mibps = wall > 0 ? (double)total / 1048576.0 / wall : 0;
    printf("MT_SUMMARY clients=%ld workers=%ld failures=%d bytes=%llu wall_s=%.3f aggregate_MiBps=%.3f\n",
        clients, workers, failures, (unsigned long long)total, wall, mibps);
    return failures == 0 && created == clients ? 0 : 1;
}
