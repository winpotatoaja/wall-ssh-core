#define SSH_CORE_PARSER_TEST 1
#include "../ssh-core.c"

#include <sys/un.h>

static int run_case(const char *name, const char *response,
                    int expect_connect, int allow_200,
                    int close_peer, int expected_rc, int expected_tunnel) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] %s: socketpair: %s\n", name, strerror(errno));
        return 1;
    }

    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags < 0 || fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "[FAIL] %s: nonblocking socket setup\n", name);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    if (close_peer) shutdown(sv[1], SHUT_WR);

    upstream_ctx_t u = {
        .fd = sv[0],
        .expect_connect_resp = expect_connect,
        .allow_http_200_tunnel = allow_200
    };
    size_t len = strlen(response);
    if (len > sizeof(u.pre_buf)) {
        fprintf(stderr, "[FAIL] %s: response test fixture too large\n", name);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    memcpy(u.pre_buf, response, len);
    u.pre_len = len;

    int rc = consume_one_http_response(&u, 0);
    int failed = (rc != expected_rc || u.tunnel_established != expected_tunnel);
    if (failed) {
        fprintf(stderr,
                "[FAIL] %s: rc=%d expected=%d tunnel=%d expected_tunnel=%d\n",
                name, rc, expected_rc, u.tunnel_established, expected_tunnel);
    } else {
        printf("[PASS] %s\n", name);
    }

    close(sv[0]);
    close(sv[1]);
    return failed;
}

int main(void) {
    g_log_path = "-";
    int failures = 0;

    failures += run_case(
        "GET 200 Content-Length body is not a tunnel",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        0, 0, 0, 0, 0);

    failures += run_case(
        "GET 200 Content-Length zero is not a tunnel",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        0, 0, 0, 0, 0);

    failures += run_case(
        "GET 200 chunked body is drained, not a tunnel",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        0, 0, 0, 0, 0);

    failures += run_case(
        "GET 200 close-delimited body fails closed at EOF",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nordinary page body",
        0, 0, 1, -1, 0);

    failures += run_case(
        "GET 200 close-delimited waits for EOF",
        "HTTP/1.1 200 OK\r\n\r\nbody",
        0, 0, 0, -2, 0);

    failures += run_case(
        "CONNECT 2xx establishes tunnel",
        "HTTP/1.1 200 Connection Established\r\nContent-Length: 99\r\n\r\n",
        1, 0, 0, 0, 1);

    failures += run_case(
        "legacy non-CONNECT 200 tunnel is explicit opt-in",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        0, 1, 0, 0, 1);

    failures += run_case(
        "legacy 200 tunnel drains Content-Length body first",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        0, 1, 0, 0, 1);

    failures += run_case(
        "legacy 200 tunnel drains chunked body first",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        0, 1, 0, 0, 1);

    failures += run_case(
        "legacy 200 without body framing establishes tunnel",
        "HTTP/1.1 200 OK\r\n\r\n",
        0, 1, 0, 0, 1);

    failures += run_case(
        "malformed HTTP version is rejected",
        "HTTP/1.X 200 OK\r\nContent-Length: 0\r\n\r\n",
        0, 0, 1, -1, 0);

    failures += run_case(
        "101 without Upgrade headers is rejected",
        "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        0, 0, 0, -1, 0);

    failures += run_case(
        "101 with Connection and Upgrade headers establishes tunnel",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
        0, 0, 0, 0, 1);

    failures += run_case(
        "407 close-delimited proxy error is not SSH data",
        "HTTP/1.1 407 Proxy Authentication Required\r\n\r\nproxy denied",
        0, 0, 1, -1, 0);

    if (failures) {
        fprintf(stderr, "HTTP parser regression tests failed: %d\n", failures);
        return 1;
    }
    puts("All HTTP parser regression tests passed.");
    return 0;
}
