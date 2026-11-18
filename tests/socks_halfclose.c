#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define SOCKS_HOST "127.0.0.1"
#define SOCKS_PORT 1080
#define RESPONSE_CAP 65536

static uint16_t socks_port = SOCKS_PORT;

static int send_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_exact(int fd, void *data, size_t len)
{
    unsigned char *p = (unsigned char *)data;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_to_eof(int fd, char *buf, size_t cap, size_t *used)
{
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = recv(fd, buf + off, cap - off - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        if (n == 0) {
            buf[off] = '\0';
            *used = off;
            return 0;
        }
        off += (size_t)n;
    }
    buf[off] = '\0';
    *used = off;
    return -1;
}

static int open_socks_tunnel(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(socks_port);
    if (inet_pton(AF_INET, SOCKS_HOST, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    const unsigned char greeting[] = { 0x05, 0x01, 0x00 };
    unsigned char method[2];
    if (send_all(fd, greeting, sizeof(greeting)) < 0 ||
        recv_exact(fd, method, sizeof(method)) < 0 ||
        method[0] != 0x05 || method[1] != 0x00) {
        close(fd);
        return -1;
    }

    const unsigned char request[] = {
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x46, 0xA0
    };
    unsigned char reply[4];
    if (send_all(fd, request, sizeof(request)) < 0 ||
        recv_exact(fd, reply, sizeof(reply)) < 0 ||
        reply[0] != 0x05 || reply[1] != 0x00) {
        close(fd);
        return -1;
    }

    if (reply[3] == 0x01) {
        unsigned char tail[6];
        if (recv_exact(fd, tail, sizeof(tail)) < 0) {
            close(fd);
            return -1;
        }
    } else if (reply[3] == 0x03) {
        unsigned char n;
        if (recv_exact(fd, &n, 1) < 0) {
            close(fd);
            return -1;
        }
        unsigned char tail[256 + 2];
        if (recv_exact(fd, tail, (size_t)n + 2) < 0) {
            close(fd);
            return -1;
        }
    } else if (reply[3] == 0x04) {
        unsigned char tail[18];
        if (recv_exact(fd, tail, sizeof(tail)) < 0) {
            close(fd);
            return -1;
        }
    } else {
        close(fd);
        return -1;
    }
    return fd;
}

static int validate_http_response(const char *response, size_t response_len,
                                  const char *expected_body, size_t expected_len)
{
    const char *header_end = strstr(response, "\r\n\r\n");
    const char *content_length = strstr(response, "Content-Length:");
    const char *line_end = strstr(response, "\r\n");
    if (!header_end || !content_length || !line_end ||
        !strstr(response, " 200 ")) return -1;

    char *endptr = NULL;
    errno = 0;
    unsigned long body_len = strtoul(content_length + strlen("Content-Length:"), &endptr, 10);
    if (errno != 0 || endptr == content_length + strlen("Content-Length:")) return -1;

    size_t header_len = (size_t)(header_end - response) + 4;
    if (body_len != expected_len ||
        header_len + (size_t)body_len != response_len) return -1;
    if (memcmp(response + header_len, expected_body, expected_len) != 0) return -1;
    return 0;
}

static int test_client_fin_first(void)
{
    static const char body[] =
        "client-fin-first:the-client-shuts-down-its-write-side-but-keeps-reading";
    int fd = open_socks_tunnel();
    if (fd < 0) return -1;

    char request[512];
    int request_len = snprintf(request, sizeof(request),
        "POST /half-close-client-eof HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n\r\n",
        (unsigned long)(sizeof(body) - 1));
    if (request_len <= 0 || (size_t)request_len >= sizeof(request) ||
        send_all(fd, request, (size_t)request_len) < 0 ||
        send_all(fd, body, sizeof(body) - 1) < 0 ||
        shutdown(fd, SHUT_WR) < 0) {
        close(fd);
        return -1;
    }

    char response[RESPONSE_CAP];
    size_t response_len = 0;
    int rc = recv_to_eof(fd, response, sizeof(response), &response_len);
    close(fd);
    if (rc < 0) return -1;
    return validate_http_response(response, response_len, body, sizeof(body) - 1);
}

static int test_server_fin_first(void)
{
    static const char expected[] = "server-half-close-ok\n";
    static const char trailer[] = "client-write-after-server-fin";
    static const char request[] =
        "GET /half-close-server-eof HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n";

    int fd = open_socks_tunnel();
    if (fd < 0) return -1;
    if (send_all(fd, request, sizeof(request) - 1) < 0) {
        close(fd);
        return -1;
    }

    char response[RESPONSE_CAP];
    size_t response_len = 0;
    if (recv_to_eof(fd, response, sizeof(response), &response_len) < 0 ||
        validate_http_response(response, response_len, expected, sizeof(expected) - 1) < 0) {
        close(fd);
        return -1;
    }

    /* The server has sent FIN. The client write direction must still work. */
    if (send_all(fd, trailer, sizeof(trailer) - 1) < 0 ||
        shutdown(fd, SHUT_WR) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int send_file_all(int fd, const char *path, size_t *total_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    unsigned char buf[16384];
    size_t total = 0;
    while (1) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n > 0) {
            if (send_all(fd, buf, n) < 0) {
                fclose(f);
                return -1;
            }
            total += n;
        }
        if (n < sizeof(buf)) {
            if (ferror(f)) {
                fclose(f);
                return -1;
            }
            break;
        }
    }
    fclose(f);
    *total_out = total;
    return 0;
}

static int recv_http_body_to_file(int fd, const char *path,
                                  size_t expected_len)
{
    char headers[4096];
    size_t header_used = 0;
    size_t header_end = 0;
    FILE *out = NULL;
    unsigned char body_buf[16384];
    size_t body_received = 0;

    while (header_used + 1 < sizeof(headers)) {
        ssize_t n = recv(fd, headers + header_used,
                         sizeof(headers) - header_used - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        header_used += (size_t)n;
        headers[header_used] = '\0';
        char *end = strstr(headers, "\r\n\r\n");
        if (end) {
            header_end = (size_t)(end - headers) + 4;
            break;
        }
    }
    if (header_end == 0 ||
        strncmp(headers, "HTTP/1.1 200 ", 13) != 0) return -1;

    char *content_length = strstr(headers, "Content-Length:");
    if (!content_length) return -1;
    char *number = content_length + strlen("Content-Length:");
    while (*number == ' ' || *number == '\t') number++;
    char *endptr = NULL;
    errno = 0;
    unsigned long parsed = strtoul(number, &endptr, 10);
    if (errno != 0 || endptr == number ||
        parsed != (unsigned long)expected_len) return -1;

    out = fopen(path, "wb");
    if (!out) return -1;
    if (header_used > header_end) {
        body_received = header_used - header_end;
        if (body_received > expected_len ||
            fwrite(headers + header_end, 1, body_received, out) != body_received) {
            fclose(out);
            return -1;
        }
    }

    while (body_received < expected_len) {
        size_t want = expected_len - body_received;
        if (want > sizeof(body_buf)) want = sizeof(body_buf);
        ssize_t n = recv(fd, body_buf, want, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            fclose(out);
            return -1;
        }
        if (fwrite(body_buf, 1, (size_t)n, out) != (size_t)n) {
            fclose(out);
            return -1;
        }
        body_received += (size_t)n;
    }
    return fclose(out) == 0 ? 0 : -1;
}

static int test_duplex_upload_s2c_full(const char *upload_path,
                                       const char *download_path)
{
    static const char request_fmt[] =
        "POST /duplex-backpressure HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n\r\n";
    int fd = open_socks_tunnel();
    if (fd < 0) return -1;

    int rcvbuf = 32768;
    struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        close(fd);
        return -1;
    }

    char request[512];
    int request_len = snprintf(request, sizeof(request), request_fmt,
                               8U * 1024U * 1024U);
    if (request_len <= 0 || (size_t)request_len >= sizeof(request) ||
        send_all(fd, request, (size_t)request_len) < 0) {
        close(fd);
        return -1;
    }

    size_t uploaded = 0;
    if (send_file_all(fd, upload_path, &uploaded) < 0 ||
        uploaded != (8U * 1024U * 1024U) ||
        shutdown(fd, SHUT_WR) < 0) {
        close(fd);
        return -1;
    }

    /* Do not consume the concurrently generated S2C stream yet. The small
     * local receive window plus this pause forces the core's 32 KiB S2C ring
     * to saturate while C2S upload traffic is being processed. */
    sleep(2);
    int rc = recv_http_body_to_file(fd, download_path, 32U * 1024U * 1024U);
    close(fd);
    return rc;
}

static int test_idle_client_rst(void)
{
    static const char request[] =
        "GET /idle HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n";
    char headers[4096];
    size_t used = 0;
    int fd = open_socks_tunnel();
    if (fd < 0) return -1;

    if (send_all(fd, request, sizeof(request) - 1) < 0) {
        close(fd);
        return -1;
    }

    /* Read only the HTTP headers. The fixture holds its 64-byte response body
     * for 40 seconds, so the SSH channel reaches a read-EAGAIN idle state. */
    while (used + 1 < sizeof(headers)) {
        ssize_t n = recv(fd, headers + used, sizeof(headers) - used - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            return -1;
        }
        used += (size_t)n;
        headers[used] = '\0';
        if (strstr(headers, "\r\n\r\n")) break;
    }
    if (!strstr(headers, "\r\n\r\n")) {
        close(fd);
        return -1;
    }

    /* Give the core time to drain the response headers and enter channel
     * read-pending state before resetting the local SOCKS socket. */
    sleep(2);
    struct linger rst = { .l_onoff = 1, .l_linger = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &rst, sizeof(rst)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int parse_socks_port_arg(const char *arg)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' ||
        parsed < 1 || parsed > 65535) return -1;
    socks_port = (uint16_t)parsed;
    return 0;
}

static int test_server_fin_first_large(const char *upload_path)
{
    static const char expected[] = "server-half-close-large-ok\n";
    static const char request[] =
        "GET /half-close-server-eof-large HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n";

    int fd = open_socks_tunnel();
    if (fd < 0) return -1;
    if (send_all(fd, request, sizeof(request) - 1) < 0) {
        close(fd);
        return -1;
    }

    char response[RESPONSE_CAP];
    size_t response_len = 0;
    if (recv_to_eof(fd, response, sizeof(response), &response_len) < 0 ||
        validate_http_response(response, response_len, expected, sizeof(expected) - 1) < 0) {
        close(fd);
        return -1;
    }

    /* The remote server has sent FIN; keep the client write side open and
     * send enough data to exhaust the SSH channel window. */
    size_t uploaded = 0;
    if (send_file_all(fd, upload_path, &uploaded) < 0 ||
        uploaded != (8U * 1024U * 1024U) ||
        shutdown(fd, SHUT_WR) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--duplex") == 0) {
        if (argc < 4 ||
            (argc > 4 && parse_socks_port_arg(argv[4]) < 0)) {
            fprintf(stderr, "[FAIL] usage: %s --duplex upload.bin download.bin [socks-port]\n", argv[0]);
            return 1;
        }
        if (test_duplex_upload_s2c_full(argv[2], argv[3]) < 0) {
            fprintf(stderr, "[FAIL] 8 MiB upload while the 32 MiB S2C response is backpressured\n");
            return 1;
        }
        puts("[PASS] 8 MiB C2S upload completed while the 32 MiB S2C ring saturated and drained");
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--rst-idle") == 0) {
        if (argc > 2 && parse_socks_port_arg(argv[2]) < 0) {
            fprintf(stderr, "[FAIL] invalid SOCKS port: %s\n", argv[2]);
            return 1;
        }
        if (test_idle_client_rst() < 0) {
            fprintf(stderr, "[FAIL] idle SOCKS client RST\n");
            return 1;
        }
        puts("[PASS] idle SOCKS channel reset with TCP RST");
        return 0;
    }

    if (argc > 2 && parse_socks_port_arg(argv[2]) < 0) {
        fprintf(stderr, "[FAIL] invalid SOCKS port: %s\n", argv[2]);
        return 1;
    }

    if (test_client_fin_first() < 0) {
        fprintf(stderr, "[FAIL] client-FIN-first half-close\n");
        return 1;
    }
    puts("[PASS] client FIN first: server response remained readable");

    if (test_server_fin_first() < 0) {
        fprintf(stderr, "[FAIL] server-FIN-first small half-close\n");
        return 1;
    }
    puts("[PASS] server FIN first: small client write direction remained usable");

    if (argc > 1) {
        if (test_server_fin_first_large(argv[1]) < 0) {
            fprintf(stderr, "[FAIL] server-FIN-first 8 MiB upload after EOF\n");
            return 1;
        }
        puts("[PASS] server FIN first: 8 MiB client upload completed after remote EOF");
    }
    return 0;
}
