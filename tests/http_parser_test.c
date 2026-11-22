#define DELAY_WAIT_POLL_MAX_MS 10
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

static int run_followup_case(const char *name, const char *wire) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] %s: socketpair: %s\n", name, strerror(errno));
        return 1;
    }
    upstream_ctx_t u = {.fd = sv[0]};
    size_t len = strlen(wire);
    if (len > sizeof(u.pre_buf)) {
        fprintf(stderr, "[FAIL] %s: fixture too large\n", name);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    memcpy(u.pre_buf, wire, len);
    u.pre_len = len;
    int first = consume_one_http_response(&u, 0);
    int failed = (first != 0 || u.tunnel_established || u.last_http_code != 200);
    int second = failed ? first : consume_one_http_response(&u, 0);
    if (second != -1 || u.tunnel_established ||
        !upstream_http_response_rejected(&u) || u.last_http_code != 200)
        failed = 1;
    if (failed) {
        fprintf(stderr, "[FAIL] %s: first_rc=%d second_rc=%d tunnel=%d status=%d rejected=%d\n",
                name, first, second, u.tunnel_established, u.last_http_code,
                upstream_http_response_rejected(&u));
    } else {
        printf("[PASS] %s (HTTP/Proxy Rejected %d)\n", name, u.last_http_code);
    }
    close(sv[0]);
    close(sv[1]);
    return failed;
}

static int send_test_bytes(int fd, const char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n > 0) off += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else return -1;
    }
    return 0;
}

static int run_fragmented_followup_case(const char *name,
                                        const char *first_part,
                                        const char *second_part) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] %s: socketpair: %s\n", name, strerror(errno));
        return 1;
    }
    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags < 0 || fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "[FAIL] %s: nonblocking setup\n", name);
        close(sv[0]);
        close(sv[1]);
        return 1;
    }

    upstream_ctx_t u = {.fd = sv[0]};
    int failed = 0;
    size_t first_len = strlen(first_part);
    if (send_test_bytes(sv[1], first_part, first_len) < 0) {
        fprintf(stderr, "[FAIL] %s: first write: %s\n", name, strerror(errno));
        failed = 1;
    }
    int first_rc = failed ? -1 : consume_one_http_response(&u, 0);
    if (!failed && (first_rc != -2 || u.tunnel_established)) {
        fprintf(stderr, "[FAIL] %s: expected EAGAIN mid-body, rc=%d tunnel=%d\n",
                name, first_rc, u.tunnel_established);
        failed = 1;
    }

    if (!failed && send_test_bytes(sv[1], second_part, strlen(second_part)) < 0) {
        fprintf(stderr, "[FAIL] %s: second write: %s\n", name, strerror(errno));
        failed = 1;
    }
    int second_rc = failed ? -1 : consume_one_http_response(&u, 0);
    if (!failed && (second_rc != 0 || u.tunnel_established)) {
        fprintf(stderr, "[FAIL] %s: expected complete non-tunnel response, rc=%d tunnel=%d\n",
                name, second_rc, u.tunnel_established);
        failed = 1;
    }

    int third_rc = failed ? -1 : consume_one_http_response(&u, 0);
    if (!failed && (third_rc != -1 || u.tunnel_established)) {
        fprintf(stderr, "[FAIL] %s: trailing SSH bytes must be rejected, rc=%d tunnel=%d\n",
                name, third_rc, u.tunnel_established);
        failed = 1;
    }

    if (!failed) printf("[PASS] %s (EAGAIN -> body complete -> trailing data rejected)\n", name);
    close(sv[0]);
    close(sv[1]);
    return failed;
}

static int g_test_dns_v4_lookups = 0;
static int g_test_dns_v6_lookups = 0;
static int g_test_dns_force_v4_noname = 0;
static int g_test_dns_force_v6_again = 0;

static int test_tcp_getaddrinfo(const char *host, const char *service,
                                const struct addrinfo *hints,
                                struct addrinfo **res) {
    if (hints && hints->ai_family == AF_INET) {
        g_test_dns_v4_lookups++;
        if (g_test_dns_force_v4_noname) {
            *res = NULL;
            return EAI_NONAME;
        }
    } else if (hints && hints->ai_family == AF_INET6) {
        g_test_dns_v6_lookups++;
        if (g_test_dns_force_v6_again) {
            *res = NULL;
            return EAI_AGAIN;
        }
    }
    return getaddrinfo(host, service, hints, res);
}

static int run_ipv4_dial_regression(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, 1) < 0) {
        close(listener);
        fprintf(stderr, "[FAIL] IPv4 dial test listener setup: %s\n", strerror(errno));
        return 1;
    }
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(listener);
        return 1;
    }
    char port[16];
    snprintf(port, sizeof(port), "%u", (unsigned)ntohs(addr.sin_port));

    g_test_dns_v4_lookups = 0;
    g_test_dns_v6_lookups = 0;
    g_test_dns_force_v4_noname = 0;
    g_test_dns_force_v6_again = 1;
    g_tcp_getaddrinfo = test_tcp_getaddrinfo;
    int client = tcp_connect_host("127.0.0.1", port);
    g_tcp_getaddrinfo = getaddrinfo;
    g_test_dns_force_v6_again = 0;

    int accepted = client >= 0 ? accept(listener, NULL, NULL) : -1;
    int failed = client < 0 || accepted < 0 ||
                 g_test_dns_v4_lookups != 1 || g_test_dns_v6_lookups != 0;
    if (failed) {
        fprintf(stderr, "[FAIL] IPv4 dial must succeed without querying a failing AAAA resolver (v4=%d v6=%d)\n",
                g_test_dns_v4_lookups, g_test_dns_v6_lookups);
    } else {
        puts("[PASS] IPv4 dial is independent of an unavailable AAAA resolver");
    }
    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    close(listener);
    return failed;
}

static int run_ipv6_dial_regression(void) {
    int listener = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener < 0) {
        puts("[SKIP] IPv6 loopback unavailable for destination dial test");
        return 0;
    }
    int one = 1;
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listener, 1) < 0) {
        close(listener);
        puts("[SKIP] IPv6 loopback is not configured in this test environment");
        return 0;
    }
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(listener);
        fprintf(stderr, "[FAIL] IPv6 dial test: getsockname: %s\n", strerror(errno));
        return 1;
    }
    char port[16];
    snprintf(port, sizeof(port), "%u", (unsigned)ntohs(addr.sin6_port));
    g_test_dns_v4_lookups = 0;
    g_test_dns_v6_lookups = 0;
    g_test_dns_force_v4_noname = 1;
    g_test_dns_force_v6_again = 0;
    g_tcp_getaddrinfo = test_tcp_getaddrinfo;
    int client = tcp_connect_host("::1", port);
    g_tcp_getaddrinfo = getaddrinfo;
    g_test_dns_force_v4_noname = 0;
    if (client < 0 || g_test_dns_v4_lookups != 1 || g_test_dns_v6_lookups != 1) {
        if (client >= 0) close(client);
        close(listener);
        fprintf(stderr, "[FAIL] IPv6 fallback after IPv4 lookup miss (v4=%d v6=%d)\\n",
                g_test_dns_v4_lookups, g_test_dns_v6_lookups);
        return 1;
    }
    if (client < 0) {
        close(listener);
        fprintf(stderr, "[FAIL] IPv6 SOCKS destination dialing failed\n");
        return 1;
    }
    int accepted = accept(listener, NULL, NULL);
    int failed = accepted < 0;
    if (failed) fprintf(stderr, "[FAIL] IPv6 dial accept: %s\n", strerror(errno));
    else puts("[PASS] SOCKS IPv6 destination dialing");
    if (accepted >= 0) close(accepted);
    close(client);
    close(listener);
    return failed;
}


static int run_ring_buffer_regressions(void) {
    rb_t r = {0};
    if (rb_init(&r, 8) < 0) return 1;
    int failed = 0;
    if (rb_commit_read(&r, 1, 0) == 0) failed = 1;
    if (rb_push(&r, (const uint8_t *)"abcdef", 6) < 0) failed = 1;
    size_t used_before = r.used, tail_before = r.tail;
    if (rb_commit_write(&r, 3) == 0 || r.used != used_before || r.tail != tail_before) failed = 1;
    if (rb_commit_read(&r, 7, 0) == 0 || r.used != used_before || r.tail != tail_before) failed = 1;
    if (rb_commit_read(&r, 4, 0) < 0 || rb_push(&r, (const uint8_t *)"gh", 2) < 0 ||
        rb_commit_read(&r, 4, 0) < 0 || !rb_state_valid(&r) || r.used != 0) failed = 1;
    if (rb_push(&r, (const uint8_t *)"xyz", 3) < 0) failed = 1;
    const uint8_t *pin = rb_read_slice_pinned(&r, r.head, r.generation, 3);
    if (!pin || memcmp(pin, "xyz", 3) != 0) failed = 1;
    if (rb_commit_read(&r, 1, 1) < 0 || rb_read_slice_pinned(&r, 0, r.generation, 3) != NULL) failed = 1;
    uint64_t old_generation = r.generation;
    if (rb_clear(&r) < 0 || !rb_state_valid(&r) || r.used != 0 ||
        r.head != 0 || r.tail != 0 || r.generation == old_generation ||
        rb_read_slice_pinned(&r, 0, old_generation, 1) != NULL) failed = 1;
    if (rb_push(&r, (const uint8_t *)"12345678", 8) < 0 ||
        r.used != r.cap || r.head != r.tail || rb_clear(&r) < 0 ||
        !rb_state_valid(&r) || r.used != 0) failed = 1;
    rb_free(&r);
    if (failed) { fprintf(stderr, "[FAIL] ring-buffer invariant checks\\n"); return 1; }
    puts("[PASS] ring-buffer invariant checks");
    return 0;
}


static int run_s2c_read_retry_recomputes_slice_regression(void) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] S2C read-retry slice regression: socketpair: %s\\n",
                strerror(errno));
        return 1;
    }
    client_conn_t c = {.fd = sv[0], .state = ST_RELAY};
    int failed = rb_init(&c.s2c, 64) < 0;
    uint8_t payload[60];
    memset(payload, 0xA5, sizeof(payload));
    if (!failed && rb_push(&c.s2c, payload, sizeof(payload)) < 0) failed = 1;
    if (!failed && rb_commit_read(&c.s2c, 30, 0) < 0) failed = 1;

    size_t old_contiguous = 0;
    if (!failed && !rb_write_slice(&c.s2c, &old_contiguous)) failed = 1;
    if (!failed && old_contiguous != 4) failed = 1;

    /* EAGAIN is only a retry state: it does not retain the output pointer. */
    if (!failed && send_from_rb(c.fd, &c.s2c, 0) != 1) failed = 1;

    size_t retry_contiguous = 0;
    uint8_t *retry_ptr = failed ? NULL : rb_write_slice(&c.s2c, &retry_contiguous);
    if (!failed && (!retry_ptr ||
                    retry_ptr != c.s2c.data ||
                    retry_contiguous != c.s2c.cap ||
                    retry_contiguous <= old_contiguous ||
                    c.s2c.used != 0 || c.s2c.head != 0 || c.s2c.tail != 0)) failed = 1;

    uint8_t drained[30];
    ssize_t got = failed ? -1 : recv(sv[1], drained, sizeof(drained), 0);
    if (!failed && (got != (ssize_t)sizeof(drained) ||
                    memcmp(drained, payload + 30, sizeof(drained)) != 0)) failed = 1;

    rb_free(&c.s2c);
    close(sv[0]);
    close(sv[1]);
    if (failed) {
        fprintf(stderr, "[FAIL] S2C read EAGAIN retry recomputes current writable slice\\n");
        return 1;
    }
    puts("[PASS] S2C read EAGAIN retry recomputes current writable slice");
    return 0;
}

static int run_relay_buffer_capacity_regression(void) {
    rb_t c2s = {0}, s2c = {0};
    int failed = rb_init(&c2s, C2S_RELAY_BUF_SIZE) < 0 ||
                 rb_init(&s2c, S2C_RELAY_BUF_SIZE) < 0;
    if (!failed && (c2s.cap != 32768 || s2c.cap != 131072)) failed = 1;
    rb_free(&c2s);
    rb_free(&s2c);
    if (failed) {
        fprintf(stderr, "[FAIL] separate C2S/S2C ring capacities\\n");
        return 1;
    }
    puts("[PASS] C2S ring=32 KiB and S2C ring=128 KiB");
    return 0;
}

static int run_eof_drain_regression(void) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags < 0 || fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sv[0]); close(sv[1]); return 1;
    }
    client_conn_t c = {.fd = sv[0], .rdhup_pending = 1};
    int failed = rb_init(&c.c2s, 64) < 0;
    if (!failed) {
        int rc = drain_pending_eof_to_c2s(-1, &c);
        if (rc != 0 || c.client_eof || c.need_send_eof || !c.rdhup_pending) failed = 1;
        if (send_test_bytes(sv[1], "abc", 3) < 0) failed = 1;
        rc = failed ? -1 : drain_pending_eof_to_c2s(-1, &c);
        if (!failed && (rc != 1 || c.c2s.used != 3 || c.client_eof || c.need_send_eof || !c.rdhup_pending)) failed = 1;
        if (shutdown(sv[1], SHUT_WR) < 0) failed = 1;
        rc = failed ? -1 : drain_pending_eof_to_c2s(-1, &c);
        if (!failed && (rc != 1 || !c.client_eof || !c.need_send_eof || c.rdhup_pending || c.c2s.used != 3)) failed = 1;
    }
    rb_free(&c.c2s); close(sv[0]); close(sv[1]);
    if (failed) { fprintf(stderr, "[FAIL] HUP/RDHUP EAGAIN semantics\\n"); return 1; }
    puts("[PASS] HUP/RDHUP EAGAIN semantics");
    return 0;
}

static int run_graceful_hup_preserves_c2s_regression(void) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
    int flags = fcntl(sv[0], F_GETFL, 0);
    if (flags < 0 || fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sv[0]); close(sv[1]); return 1;
    }

    client_conn_t c = {.fd = sv[0], .hup_pending = 1};
    int failed = rb_init(&c.c2s, 64) < 0;
    if (!failed && send_test_bytes(sv[1], "upload", 6) < 0) failed = 1;
    if (!failed && shutdown(sv[1], SHUT_WR) < 0) failed = 1;
    int rc = failed ? -1 : drain_pending_eof_to_c2s(-1, &c);
    size_t queued_len = 0;
    const uint8_t *queued = rb_read_slice(&c.c2s, &queued_len);
    if (!failed && (rc != 1 || !c.client_eof || !c.need_send_eof ||
                    !c.client_dead || c.client_reset || c.hup_pending ||
                    c.fd >= 0 || c.c2s.used != 6 || queued_len < 6 ||
                    !queued || memcmp(queued, "upload", 6) != 0)) {
        failed = 1;
    }

    rb_free(&c.c2s);
    close(sv[1]);
    if (failed) {
        fprintf(stderr, "[FAIL] graceful HUP must preserve queued C2S bytes for SSH delivery\\n");
        return 1;
    }
    puts("[PASS] graceful HUP preserves queued C2S bytes for SSH delivery");
    return 0;
}

static int run_deferred_client_cleanup_regression(void) {
    client_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->fd = -1; c->state = ST_SOCKS_GREETING;
    g_clients = c; g_client_count = 1; g_opening_client = NULL;
    clear_pending_operation();
    start_closing_client(-1, c);
    int failed = (g_clients != c || c->state != ST_CLOSING);
    upstream_ctx_t u = {.fd = -1};
    int dirs = 0, did_read = 0;
    int pump_rc = failed ? -1 : pump_ssh_channels(-1, NULL, &u, &dirs, &did_read);
    if (pump_rc != 1 || g_clients != NULL || g_client_count != 0) failed = 1;
    if (g_clients) while (g_clients) remove_client(-1, g_clients);
    if (failed) { fprintf(stderr, "[FAIL] deferred client cleanup\\n"); return 1; }
    puts("[PASS] deferred client cleanup");
    return 0;
}

static int run_cleanup_deadline_and_shutdown_pending_regression(void) {
    client_conn_t c = {
        .state = ST_RELAY,
        .abort_on_pending = 1,
        .cleanup_deadline_ms = 5000
    };
    int failed = client_cleanup_timeout_due(&c, 4999) ||
                 !client_cleanup_timeout_due(&c, 5000);

    /* Aborted opens remain governed by SSH_OPEN_HARD_TO_MS, not cleanup's
     * shorter channel-close deadline. */
    c.abort_on_pending = 0;
    c.abort_on_open = 1;
    c.state = ST_SSH_OPENING;
    if (client_cleanup_timeout_due(&c, 4999) ||
        client_cleanup_timeout_due(&c, 5000)) failed = 1;
    c.abort_on_open = 0;
    c.state = ST_CLOSING;
    if (client_cleanup_timeout_due(&c, 4999) ||
        !client_cleanup_timeout_due(&c, 5000)) failed = 1;

    /* A reset peer closes promptly even when a C2S buffer or retry state exists. */
    c.state = ST_RELAY;
    c.client_dead = 1;
    c.client_reset = 1;
    c.hup_pending = 0;
    c.c2s.used = 0;
    c.need_send_eof = 1;
    c.write_pending = 1;
    if (!client_dead_ready_to_close(&c)) failed = 1;
    c.c2s.used = 1;
    if (!client_dead_ready_to_close(&c)) failed = 1;
    c.c2s.used = 0;
    c.hup_pending = 1;
    if (client_dead_ready_to_close(&c)) failed = 1;

    /* A graceful EOF waits for queued C2S writes and the SSH EOF packet. */
    c.hup_pending = 0;
    c.client_reset = 0;
    c.client_eof = 1;
    c.need_send_eof = 1;
    c.write_pending = 0;
    c.c2s.used = 1;
    if (client_dead_ready_to_close(&c) || client_eof_ready_to_close(&c)) failed = 1;
    c.c2s.used = 0;
    if (client_eof_ready_to_close(&c)) failed = 1;
    c.need_send_eof = 0;
    if (!client_eof_ready_to_close(&c)) failed = 1;
    c.write_pending = 1;
    if (client_eof_ready_to_close(&c)) failed = 1;

    c.client_dead = 0;
    c.client_eof = 0;
    c.need_send_eof = 0;
    c.write_pending = 0;

    g_clients = &c;
    g_opening_client = NULL;
    clear_pending_operation();
    c.cleanup_deadline_ms = 0;
    c.write_pending = 1;
    c.write_waiting_window = 1;
    if (has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.write_waiting_window = 0;
    if (!has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.write_pending = 0;
    if (has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.need_send_eof = 1;
    if (has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.need_send_eof = 0;
    c.state = ST_CLOSING;
    c.channel = (LIBSSH2_CHANNEL *)(uintptr_t)1;
    if (!has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.channel = NULL;
    c.state = ST_RELAY;
    set_pending_operation(NULL, PENDING_KEEPALIVE);
    if (!has_pending_libssh2_work_for_shutdown()) failed = 1;
    clear_pending_operation();
    g_opening_client = &c;
    if (!has_pending_libssh2_work_for_shutdown()) failed = 1;
    g_opening_client = NULL;
    g_clients = NULL;

    if (failed) {
        fprintf(stderr, "[FAIL] bounded cleanup deadline, dead-client close, and shutdown pending detection\n");
        return 1;
    }
    puts("[PASS] bounded cleanup deadline and shutdown pending detection");
    return 0;
}

static int run_pending_open_cleanup_deadline_regression(void) {
    client_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->fd = -1;
    c->state = ST_SSH_OPENING;
    c->open_started_ms = now_ms();
    g_clients = c;
    g_client_count = 1;
    g_opening_client = c;
    set_pending_operation(c, PENDING_OPEN);

    start_closing_client(-1, c);
    int failed = !c->abort_on_open || c->abort_on_pending ||
                 c->cleanup_deadline_ms != 0 || c->fd != -1 ||
                 g_pending_client != c || g_pending_op != PENDING_OPEN ||
                 client_cleanup_timeout_due(c, now_ms());

    clear_pending_operation();
    g_opening_client = NULL;
    remove_client(-1, c);
    g_clients = NULL;
    g_client_count = 0;

    if (failed) {
        fprintf(stderr, "[FAIL] pending OPEN uses hard-open deadline, not channel cleanup deadline\n");
        return 1;
    }
    puts("[PASS] pending OPEN uses hard-open deadline, not channel cleanup deadline");
    return 0;
}

static int run_aborted_open_completion_cleanup_regression(void) {
    client_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->fd = -1;
    c->state = ST_SSH_OPENING;
    c->abort_on_pending = 1;
    c->cleanup_deadline_ms = 1; /* stale 10-second deadline from pending OPEN */
    g_clients = c;
    g_client_count = 1;
    g_opening_client = c;
    clear_pending_operation();

    int rc = finish_open_channel(-1, c, (LIBSSH2_CHANNEL *)(uintptr_t)1);
    long long now = now_ms();
    int failed = rc != 1 || g_opening_client != NULL ||
                 c->state != ST_CLOSING || c->cleanup_deadline_ms <= now ||
                 client_cleanup_timeout_due(c, now);

    c->channel = NULL;
    if (g_clients == c) remove_client(-1, c);
    else free(c);
    clear_pending_operation();
    g_opening_client = NULL;
    g_clients = NULL;
    g_client_count = 0;

    if (failed) {
        fprintf(stderr, "[FAIL] aborted OPEN completion receives a fresh channel cleanup deadline\n");
        return 1;
    }
    puts("[PASS] aborted OPEN completion receives a fresh channel cleanup deadline");
    return 0;
}

static int run_shutdown_poll_ignores_stop_regression(void) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] shutdown poll stop-state: socketpair: %s\\n", strerror(errno));
        return 1;
    }
    if (send_test_bytes(sv[1], "x", 1) < 0 || shutdown(sv[1], SHUT_WR) < 0) {
        close(sv[0]);
        close(sv[1]);
        fprintf(stderr, "[FAIL] shutdown poll stop-state: send/shutdown\\n");
        return 1;
    }

    sig_atomic_t old_stop = g_stop;
    g_stop = 1;
    int normal_rc = poll_fd_until(sv[0], POLLIN, now_ms() + 100);
    int shutdown_rc = poll_fd_until_shutdown(sv[0], POLLIN, now_ms() + 100);
    g_stop = old_stop;

    close(sv[0]);
    close(sv[1]);
    if (normal_rc >= 0 || shutdown_rc <= 0) {
        fprintf(stderr, "[FAIL] shutdown poll must ignore g_stop and accept POLLIN with HUP\\n");
        return 1;
    }
    puts("[PASS] shutdown poll remains usable after g_stop");
    return 0;
}

static int run_pending_channel_close_buffer_regression(void) {
    client_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->fd = -1;
    c->state = ST_RELAY;
    c->channel = (LIBSSH2_CHANNEL *)(uintptr_t)1;

    int failed = rb_init(&c->c2s, 64) < 0 || rb_init(&c->s2c, 64) < 0;
    if (!failed && rb_push(&c->c2s, (const uint8_t *)"upload", 6) < 0) failed = 1;
    size_t free_len = 0;
    uint8_t *s2c_write = failed ? NULL : rb_write_slice(&c->s2c, &free_len);
    if (!s2c_write || free_len < 8) failed = 1;

    if (!failed) {
        c->write_pending = 1;
        c->write_pending_head = c->c2s.head;
        c->write_pending_generation = c->c2s.generation;
        c->write_pending_len = 6;

        g_clients = c;
        g_client_count = 1;
        g_opening_client = NULL;
        set_pending_operation(c, PENDING_WRITE);
        start_closing_client(-1, c);

        const uint8_t *c2s_read = rb_read_slice_pinned(
            &c->c2s, c->write_pending_head, c->write_pending_generation, c->write_pending_len);
        if (g_clients != c || g_client_count != 1 || c->state != ST_RELAY ||
            !c->abort_on_pending || g_pending_client != c || g_pending_op != PENDING_WRITE ||
            !c->write_pending ||
            !c2s_read || memcmp(c2s_read, "upload", 6) != 0 || !s2c_write) {
            failed = 1;
        }

        /* C2S write arguments remain pinned across EAGAIN. An S2C read retry
         * retains only its retry flag, never a caller-owned buffer pointer. */
        clear_pending_operation();
        c->abort_on_pending = 0;
        c->write_pending = 0;
        start_closing_client(-1, c);
        if (c->state != ST_CLOSING || c->c2s.data || c->s2c.data ||
            c->write_pending) failed = 1;
    }

    if (g_clients == c) {
        c->channel = NULL;
        remove_client(-1, c);
    } else {
        c->channel = NULL;
        rb_free(&c->c2s);
        rb_free(&c->s2c);
        free(c);
    }
    clear_pending_operation();
    if (failed) { fprintf(stderr, "[FAIL] global pending write alone pins channel buffers\n"); return 1; }
    puts("[PASS] global pending write alone pins channel buffers");
    return 0;
}

static int run_inbound_only_channel_close_regression(void) {
    client_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->fd = -1;
    c->state = ST_RELAY;
    c->channel = (LIBSSH2_CHANNEL *)(uintptr_t)1;

    int failed = rb_init(&c->c2s, 64) < 0 || rb_init(&c->s2c, 64) < 0;
    if (!failed && rb_push(&c->c2s, (const uint8_t *)"queued", 6) < 0) failed = 1;
    if (!failed) {
        c->write_pending = 1;
        c->write_waiting_window = 1;
        c->write_pending_head = c->c2s.head;
        c->write_pending_generation = c->c2s.generation;
        c->write_pending_len = c->c2s.used;

        g_clients = c;
        g_client_count = 1;
        g_opening_client = NULL;
        clear_pending_operation();
        start_closing_client(-1, c);
        if (c->state != ST_CLOSING || c->write_pending ||
            c->c2s.data || c->s2c.data || c->cleanup_deadline_ms <= 0 ||
            c->abort_on_pending) failed = 1;
    }

    if (g_clients == c) {
        c->channel = NULL;
        remove_client(-1, c);
    } else {
        c->channel = NULL;
        rb_free(&c->c2s);
        rb_free(&c->s2c);
        free(c);
    }

    /* A nonzero-window write EAGAIN may have created a packet even when
     * the TLS callback requests inbound readiness; keep that exact buffer. */
    client_conn_t *write_c = calloc(1, sizeof(*write_c));
    if (!write_c) failed = 1;
    if (write_c) {
        write_c->fd = -1;
        write_c->state = ST_RELAY;
        write_c->channel = (LIBSSH2_CHANNEL *)(uintptr_t)1;
        if (rb_init(&write_c->c2s, 64) < 0 ||
            rb_init(&write_c->s2c, 64) < 0 ||
            rb_push(&write_c->c2s, (const uint8_t *)"write", 5) < 0) {
            failed = 1;
        } else {
            write_c->write_pending = 1;
            write_c->write_waiting_window = 0;
            write_c->write_pending_head = write_c->c2s.head;
            write_c->write_pending_generation = write_c->c2s.generation;
            write_c->write_pending_len = write_c->c2s.used;
            g_clients = write_c;
            g_client_count = 1;
            clear_pending_operation();
            start_closing_client(-1, write_c);
            if (write_c->state != ST_RELAY || !write_c->abort_on_pending ||
                !write_c->write_pending || write_c->write_waiting_window ||
                !write_c->c2s.data || !write_c->s2c.data ||
                write_c->cleanup_deadline_ms <= 0 || g_pending_op != PENDING_NONE) {
                failed = 1;
            }

            /* The same write arguments stay pinned until libssh2 reports
             * completion. After that, the deferred close may release them. */
            write_c->write_pending = 0;
            write_c->abort_on_pending = 0;
            start_closing_client(-1, write_c);
            if (write_c->state != ST_CLOSING || write_c->c2s.data ||
                write_c->s2c.data || write_c->write_pending) failed = 1;
        }
        if (g_clients == write_c) {
            write_c->channel = NULL;
            remove_client(-1, write_c);
        } else {
            write_c->channel = NULL;
            rb_free(&write_c->c2s);
            rb_free(&write_c->s2c);
            free(write_c);
        }
    }

    clear_pending_operation();
    g_opening_client = NULL;
    g_clients = NULL;
    g_client_count = 0;
    if (failed) { fprintf(stderr, "[FAIL] inbound-only EAGAIN does not defer channel close\n"); return 1; }
    puts("[PASS] inbound-only EAGAIN does not defer channel close");
    return 0;
}

static int run_pending_op_serialization_regression(void) {
    client_conn_t c = {
        .write_pending = 1,
        .write_waiting_window = 0
    };
    int inbound = LIBSSH2_SESSION_BLOCK_INBOUND;
    int outbound = LIBSSH2_SESSION_BLOCK_OUTBOUND;
    int failed = 0;

    /* An active write must keep its exact caller buffer even if TLS reports
     * WANT_READ; only a zero-window wait is safe to release. */
    if (!pending_op_requires_serial_retry(PENDING_WRITE, &c, inbound, 1))
        failed = 1;
    c.write_waiting_window = 1;
    if (pending_op_requires_serial_retry(PENDING_WRITE, &c, inbound, 0))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_WRITE, &c, outbound, 0))
        failed = 1;

    if (!pending_op_requires_serial_retry(PENDING_SEND_EOF, &c, inbound, 0))
        failed = 1;
    /* A TLS read that needs the socket writable must be retried before other
     * SSH calls; an ordinary read WANT_READ can share the SSH packet reader. */
    if (pending_op_requires_serial_retry(PENDING_READ, &c, inbound, 0))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_READ, &c, inbound, 1))
        failed = 1;
    if (pending_op_requires_serial_retry(PENDING_FREE, &c, inbound, 0))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_FREE, &c, outbound, 0))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_KEEPALIVE, NULL, inbound, 0))
        failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] libssh2 EAGAIN serialization preserves active write and send operations\n");
        return 1;
    }
    puts("[PASS] libssh2 EAGAIN serialization preserves active write and send operations");
    return 0;
}

static int run_tls_want_event_lifetime_regression(void) {
    tls_engine_t *engine = tls_engine_create(4096U);
    if (!engine) {
        fprintf(stderr, "[FAIL] TLS Engine readiness regression: %s\n", strerror(errno));
        return 1;
    }

    upstream_ctx_t u = {.tls = engine};
    int idle_rx_paused = 1;
    int failed = 0;
    clear_pending_operation();

    /* A TLS eventfd must stay armed even while SSH Owner pauses idle RX.
     * The Engine reports both RX bytes and TX queue-space through this fd. */
    uint32_t want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 0, 0);
    if (want != EPOLLIN || !idle_rx_paused ||
        !keepalive_can_start(&u, PENDING_NONE) ||
        shutdown_io_pending(&u) ||
        tls_want_requires_serial_retry(&u)) {
        failed = 1;
    }

    /* Pending libssh2 work is still serialized by SSH Owner, but its wakeup
     * source remains the same eventfd rather than SSL WANT state. */
    set_pending_operation(NULL, PENDING_WRITE);
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_WRITE, LIBSSH2_SESSION_BLOCK_OUTBOUND,
        &idle_rx_paused, 0, 0, 0);
    if (want != EPOLLIN || keepalive_can_start(&u, PENDING_WRITE) ||
        !shutdown_io_pending(&u)) {
        failed = 1;
    }
    clear_pending_operation();

    /* A detached event source must not be re-armed. */
    u.upstream_epoll_detached = 1;
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 0, 0);
    if (want != 0 || tls_engine_notify_fd(engine) < 0) failed = 1;

    tls_engine_destroy(engine);
    if (failed) {
        fprintf(stderr, "[FAIL] TLS Engine eventfd readiness, pending-op serialization and epoll lifetime\n");
        return 1;
    }
    puts("[PASS] TLS Engine eventfd readiness, pending-op serialization and epoll lifetime");
    return 0;
}

static int run_upstream_rx_progress_regression(void) {
    upstream_ctx_t u = {.rx_seq = 12};
    int did_ssh_read = 0;
    note_upstream_rx_progress(&u, 11, &did_ssh_read);
    int failed = !did_ssh_read;

    did_ssh_read = 0;
    note_upstream_rx_progress(&u, 12, &did_ssh_read);
    if (did_ssh_read) failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] relay pump detects actual upstream receive progress\n");
        return 1;
    }
    puts("[PASS] relay pump detects actual upstream receive progress");
    return 0;
}

static int run_upstream_drain_state_regression(void) {
    upstream_ctx_t u = {
        .hup_seen = 1,
        .rx_terminal = 1,
        .rx_terminal_rc = 0
    };
    upstream_drain_channel_state_t channels[2] = {
        {.read_drained = 1, .channel_present = 1, .channel_eof = 1},
        {.read_drained = 1, .channel_present = 1, .channel_eof = 1}
    };
    unsigned long queued = 0;
    unsigned int stalled = 0, incomplete = 0;
    int failed = 0;

    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                &queued, &stalled, &incomplete) !=
            UPSTREAM_DRAIN_GRACEFUL ||
        queued != 0 || stalled != 0 || incomplete != 0) {
        failed = 1;
    }

    /* Pending operations, active reads, and unsent local output must wait. */
    if (classify_upstream_drain(&u, channels, 2, 1, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_WAIT ||
        classify_upstream_drain(&u, channels, 2, 0, 1,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_WAIT) {
        failed = 1;
    }
    channels[0].read_drained = 0;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_WAIT) {
        failed = 1;
    }
    channels[0].read_drained = 1;
    channels[0].output_pending = 1;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_WAIT) {
        failed = 1;
    }
    channels[0].output_pending = 0;

    /* Non-relay SOCKS clients rejected on HUP may still have an error reply
     * queued. Do not terminate before those control bytes have been sent. */
    client_conn_t control = {
        .fd = 1234,
        .state = ST_SOCKS_GREETING,
        .ctrl_len = 2
    };
    g_clients = &control;
    clear_pending_operation();
    g_opening_client = NULL;
    if (upstream_drain_status(&u, NULL, NULL, NULL) != UPSTREAM_DRAIN_WAIT)
        failed = 1;
    g_clients = NULL;

    /* A stalled channel is never a graceful completion, even if its queue
     * appears empty and the SSH EOF flag is set. */
    channels[0].read_stalled = 1;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_FORCED) {
        failed = 1;
    }

    /* A drained/stalled flag is also insufficient when libssh2 still has
     * queued channel data, or when the channel never reported SSH EOF. */
    channels[0].read_avail = 4096;
    channels[0].channel_eof = 0;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                &queued, &stalled, &incomplete) !=
            UPSTREAM_DRAIN_FORCED ||
        queued != 4096 || stalled != 1 || incomplete != 1) {
        failed = 1;
    }

    channels[0].read_stalled = 0;
    channels[0].read_avail = 0;
    channels[0].channel_eof = 0;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_FORCED) {
        failed = 1;
    }

    channels[0].channel_eof = 1;
    channels[0].channel_present = 0;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_FORCED) {
        failed = 1;
    }
    channels[0].channel_present = 1;
    u.rx_terminal_rc = -ECONNRESET;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_FORCED) {
        failed = 1;
    }
    u.rx_terminal_rc = 0;
    u.rx_terminal = 0;
    if (classify_upstream_drain(&u, channels, 2, 0, 0,
                                NULL, NULL, NULL) != UPSTREAM_DRAIN_FORCED) {
        failed = 1;
    }

    if (failed) {
        fprintf(stderr, "[FAIL] upstream drain distinguishes wait, graceful, and forced teardown\n");
        return 1;
    }
    puts("[PASS] upstream drain distinguishes wait, graceful, and forced teardown");
    return 0;
}

static int run_upstream_client_write_gate_regression(void) {
    upstream_ctx_t u = {0};
    int failed = 0;
    if (!upstream_client_write_allowed(&u)) failed = 1;

    u.hup_seen = 1;
    if (upstream_client_write_allowed(&u)) failed = 1;

    u.hup_seen = 0;
    u.tx_terminal = 1;
    if (upstream_client_write_allowed(&u)) failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] upstream HUP/terminal state blocks new client-to-SSH writes\n");
        return 1;
    }
    puts("[PASS] upstream HUP/terminal state blocks new client-to-SSH writes");
    return 0;
}

static int run_upstream_hup_epoll_policy_regression(void) {
    upstream_ctx_t u = {.hup_seen = 1};
    int idle_rx_paused = 0;
    uint32_t want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 0, 0);
    int failed = (want & EPOLLIN) == 0 || (want & EPOLLRDHUP) != 0;

    u.upstream_epoll_detached = 1;
    idle_rx_paused = 0;
    want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 1, 0);
    if (want != 0) failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] upstream RDHUP keeps EPOLLIN until terminal receive\n");
        return 1;
    }
    puts("[PASS] upstream RDHUP keeps EPOLLIN armed and removes repeated RDHUP");
    return 0;
}

static int run_upstream_epoll_timeout_regression(void) {
    upstream_ctx_t u = {.hup_seen = 1, .drain_deadline_ms = 20000};
    int failed = upstream_epoll_timeout_ms(&u, 0, 10000) != 1000;

    u.upstream_epoll_detached = 1;
    set_pending_operation(NULL, PENDING_READ);
    if (upstream_epoll_timeout_ms(&u, 0, 10000) != UPSTREAM_DRAIN_POLL_MS)
        failed = 1;
    u.drain_deadline_ms = 10010;
    if (upstream_epoll_timeout_ms(&u, 0, 10000) != 10) failed = 1;
    if (upstream_epoll_timeout_ms(&u, 1, 10000) != 0) failed = 1;
    clear_pending_operation();

    if (failed) {
        fprintf(stderr, "[FAIL] upstream drain epoll timeout is deadline/pending-op bounded\n");
        return 1;
    }
    puts("[PASS] upstream drain avoids idle 25ms polling and bounds pending retries");
    return 0;
}

static int run_upstream_hup_client_rejection_regression(void) {
    int greeting_pair[2] = {-1, -1};
    int request_pair[2] = {-1, -1};
    int opening_pair[2] = {-1, -1};
    int pending_pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, greeting_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, request_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, opening_pair) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, pending_pair) != 0) {
        for (int i = 0; i < 2; i++) {
            if (greeting_pair[i] >= 0) close(greeting_pair[i]);
            if (request_pair[i] >= 0) close(request_pair[i]);
            if (opening_pair[i] >= 0) close(opening_pair[i]);
            if (pending_pair[i] >= 0) close(pending_pair[i]);
        }
        return 1;
    }

    client_conn_t greeting = {.fd = greeting_pair[0], .state = ST_SOCKS_GREETING,
                              .req_buf = {0x05, 0x01}, .req_len = 2};
    client_conn_t request = {.fd = request_pair[0], .state = ST_SOCKS_REQUEST};
    client_conn_t opening = {.fd = opening_pair[0], .state = ST_SSH_OPENING};
    client_conn_t pending = {.fd = pending_pair[0], .state = ST_SSH_OPENING};
    greeting.next = &request;
    request.prev = &greeting;
    request.next = &opening;
    opening.prev = &request;
    /* Keep the pending-open fixture out of the initial rejection pass. */
    opening.next = NULL;
    pending.prev = NULL;
    g_clients = &greeting;
    g_opening_client = &opening;
    clear_pending_operation();

    reject_nonrelay_clients_on_upstream_hup(-1);
    uint8_t buf[16] = {0};
    ssize_t greeting_n = recv(greeting_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
    int failed = greeting_n != 2 || buf[0] != 0x05 || buf[1] != 0xFF;
    int greeting_ok = !failed;
    memset(buf, 0, sizeof(buf));
    ssize_t request_n = recv(request_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
    int request_ok = request_n == 10 && buf[0] == 0x05 && buf[1] == 0x05;
    if (!request_ok) failed = 1;
    memset(buf, 0, sizeof(buf));
    ssize_t opening_n = recv(opening_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
    int opening_reply_ok = opening_n == 10 && buf[0] == 0x05 && buf[1] == 0x05;
    int opening_state_ok = opening.abort_on_open == 1 && g_opening_client == NULL;
    if (!opening_reply_ok || !opening_state_ok) failed = 1;

    /* Add this client only after it has a real in-flight PENDING_OPEN.
     * The earlier rejection pass must not see it as an unstarted OPEN. */
    opening.next = &pending;
    pending.prev = &opening;
    g_opening_client = &pending;
    set_pending_operation(&pending, PENDING_OPEN);
    reject_nonrelay_clients_on_upstream_hup(-1);
    ssize_t pending_n = recv(pending_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
    if (pending_n >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
        pending.abort_on_open || g_opening_client != &pending ||
        g_pending_client != &pending || g_pending_op != PENDING_OPEN)
        failed = 1;

    clear_pending_operation();
    g_opening_client = NULL;
    g_clients = NULL;
    if (greeting.fd >= 0) close(greeting.fd);
    if (request.fd >= 0) close(request.fd);
    if (opening.fd >= 0) close(opening.fd);
    if (pending.fd >= 0) close(pending.fd);
    close(greeting_pair[1]);
    close(request_pair[1]);
    close(opening_pair[1]);
    close(pending_pair[1]);

    if (failed) {
        fprintf(stderr,
                "[FAIL] upstream HUP SOCKS rejection: greeting(n=%zd,ok=%d) "
                "request(n=%zd,ok=%d) opening(n=%zd,reply=%d,state=%d) "
                "pending(n=%zd,errno=%d,abort=%d,opening=%d,op=%d)\\n",
                greeting_n, greeting_ok, request_n, request_ok,
                opening_n, opening_reply_ok, opening_state_ok,
                pending_n, errno, pending.abort_on_open,
                g_opening_client == &pending, (int)g_pending_op);
        return 1;
    }
    puts("[PASS] upstream HUP rejects waiting SOCKS clients and preserves in-flight PENDING_OPEN");
    return 0;
}

static int run_upstream_rx_terminal_callback_regression(void) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
    upstream_ctx_t u = {
        .fd = sv[0], .tunnel_established = 1, .rx_flush_eagain = 1
    };
    void *abstract = &u;
    char buf[32];
    if (shutdown(sv[1], SHUT_WR) < 0) {
        close(sv[0]);
        close(sv[1]);
        return 1;
    }
    ssize_t first = ssh_recv_cb(sv[0], buf, sizeof(buf), 0, &abstract);
    ssize_t second = ssh_recv_cb(sv[0], buf, sizeof(buf), 0, &abstract);
    u.rx_flush_eagain = 0;
    ssize_t final = ssh_recv_cb(sv[0], buf, sizeof(buf), 0, &abstract);
    int failed = first != -EAGAIN || second != -EAGAIN || final != 0 ||
                 u.rx_terminal_rc != 0 || !u.rx_terminal || !u.hup_seen ||
                 !u.upstream_epoll_detached;
    close(sv[0]);
    close(sv[1]);

    upstream_ctx_t bad = {
        .tunnel_established = 1, .rx_flush_eagain = 1
    };
    void *bad_abstract = &bad;
    ssize_t bad_first = ssh_recv_cb(-1, buf, sizeof(buf), 0, &bad_abstract);
    int bad_errno = errno;
    ssize_t bad_second = ssh_recv_cb(-1, buf, sizeof(buf), 0, &bad_abstract);
    bad.rx_flush_eagain = 0;
    ssize_t bad_final = ssh_recv_cb(-1, buf, sizeof(buf), 0, &bad_abstract);
    if (bad_first != -EAGAIN || bad_second != -EAGAIN ||
        bad_final != -EBADF || bad.rx_terminal_rc != -EBADF ||
        bad_errno != EBADF || !bad.rx_terminal || !bad.hup_seen ||
        !bad.upstream_epoll_detached)
        failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] scoped RX flush exposes terminal as EAGAIN only inside channel-read scope\n");
        return 1;
    }
    puts("[PASS] scoped RX flush drains queued packets while preserving the terminal callback result");
    return 0;
}

static int run_ssl_read_terminal_classification_regression(void) {
    tls_engine_t *clean_engine = tls_engine_create(4096U);
    tls_engine_t *error_engine = tls_engine_create(4096U);
    if (!clean_engine || !error_engine) {
        fprintf(stderr, "[FAIL] TLS Engine terminal regression allocation: %s\n",
                strerror(errno));
        tls_engine_destroy(clean_engine);
        tls_engine_destroy(error_engine);
        return 1;
    }

    upstream_ctx_t clean = {.tls = clean_engine};
    upstream_ctx_t unexpected = {.tls = error_engine};
    ssize_t clean_rc = mark_upstream_rx_terminal(&clean, 0);
    ssize_t error_rc = mark_upstream_rx_terminal(&unexpected, -ECONNRESET);

    int failed = clean_rc != 0 || !clean.rx_terminal ||
                 clean.rx_terminal_rc != 0 || !clean.hup_seen ||
                 clean.upstream_epoll_detached ||
                 !upstream_client_write_allowed(&clean) ||
                 error_rc != -ECONNRESET || !unexpected.rx_terminal ||
                 unexpected.rx_terminal_rc != -ECONNRESET ||
                 unexpected.upstream_epoll_detached ||
                 upstream_client_write_allowed(&unexpected);

    /* Once TX is terminal as well, the eventfd is no longer needed by
     * either half of the transport and the SSH Owner may detach it. */
    clean.tx_terminal = 1;
    (void)mark_upstream_rx_terminal(&clean, 0);
    if (!clean.upstream_epoll_detached ||
        upstream_client_write_allowed(&clean))
        failed = 1;

    tls_engine_destroy(clean_engine);
    tls_engine_destroy(error_engine);
    if (failed) {
        fprintf(stderr, "[FAIL] TLS close_notify RX half-close, unexpected EOF and TX terminal classification\n");
        return 1;
    }
    puts("[PASS] TLS close_notify preserves TX half-close; unexpected EOF stays an error");
    return 0;
}

static int run_http_rejection_classification_regression(void) {
    upstream_ctx_t u = {.last_http_code = 200};
    int failed = !upstream_http_response_rejected(&u);
    u.last_http_code = 407;
    if (!upstream_http_response_rejected(&u)) failed = 1;
    u.last_http_code = 101;
    if (!upstream_http_response_rejected(&u)) failed = 1;
    u.tunnel_established = 1;
    if (upstream_http_response_rejected(&u)) failed = 1;
    u.tunnel_established = 0;
    u.last_http_code = 0;
    if (upstream_http_response_rejected(&u)) failed = 1;
    if (failed) {
        fprintf(stderr, "[FAIL] rejected non-tunnel HTTP responses are classified as proxy failures\n");
        return 1;
    }
    puts("[PASS] rejected non-tunnel HTTP responses are classified as proxy failures");
    return 0;
}

static int run_socks_listener_address_regression(void) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    char host[INET6_ADDRSTRLEN + 1];
    int port = 0, loopback = 0, failed = 0;
    if (parse_socks_listen_addr("127.0.0.2:1081", &ss, &slen, host, sizeof(host), &port, &loopback) < 0 ||
        ss.ss_family != AF_INET || port != 1081 || !loopback) failed = 1;
    if (parse_socks_listen_addr("[::1]:1082", &ss, &slen, host, sizeof(host), &port, &loopback) < 0 ||
        ss.ss_family != AF_INET6 || port != 1082 || !loopback) failed = 1;
    if (parse_socks_listen_addr("[2001:db8::1]:1083", &ss, &slen, host, sizeof(host), &port, &loopback) < 0 ||
        ss.ss_family != AF_INET6 || loopback) failed = 1;
    if (parse_socks_listen_addr("2001:db8::1:1083", &ss, &slen, host, sizeof(host), &port, &loopback) == 0) failed = 1;
    if (failed) { fprintf(stderr, "[FAIL] IPv4/IPv6 SOCKS listener parsing\\n"); return 1; }
    puts("[PASS] IPv4/IPv6 SOCKS listener parsing");
    return 0;
}

static int run_tcp_dial_exclusion_regression(void) {
    int listeners[2] = {-1, -1};
    struct sockaddr_in addresses[2];
    socklen_t address_lengths[2] = {sizeof(addresses[0]), sizeof(addresses[1])};
    struct addrinfo entries[2];
    int client = -1, accepted = -1, failed = 0;
    char excluded_address[INET6_ADDRSTRLEN + 24] = {0};
    char expected_address[INET6_ADDRSTRLEN + 24] = {0};
    char selected_address[INET6_ADDRSTRLEN + 24] = {0};

    memset(addresses, 0, sizeof(addresses));
    memset(entries, 0, sizeof(entries));
    for (int i = 0; i < 2; i++) {
        listeners[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (listeners[i] < 0) { failed = 1; break; }
        int one = 1;
        (void)setsockopt(listeners[i], SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        addresses[i].sin_family = AF_INET;
        addresses[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listeners[i], (struct sockaddr *)&addresses[i], sizeof(addresses[i])) < 0 ||
            listen(listeners[i], 1) < 0 ||
            getsockname(listeners[i], (struct sockaddr *)&addresses[i],
                        &address_lengths[i]) < 0 ||
            set_nonblock(listeners[i], 1) < 0) {
            failed = 1;
            break;
        }
        entries[i].ai_family = AF_INET;
        entries[i].ai_socktype = SOCK_STREAM;
        entries[i].ai_protocol = IPPROTO_TCP;
        entries[i].ai_addr = (struct sockaddr *)&addresses[i];
        entries[i].ai_addrlen = sizeof(addresses[i]);
        entries[i].ai_next = i == 0 ? &entries[1] : NULL;
    }

    if (!failed) {
        tcp_format_address((struct sockaddr *)&addresses[0],
                           excluded_address, sizeof(excluded_address));
        tcp_format_address((struct sockaddr *)&addresses[1],
                           expected_address, sizeof(expected_address));
        const char *excluded[] = {excluded_address};
        int old_debug = g_tcp_dial_debug;
        g_tcp_dial_debug = 0;
        int last_error = 0;
        client = tcp_connect_addrinfo_list(
            &entries[0], AF_INET, now_ms() + 2000,
            excluded, 1, selected_address, sizeof(selected_address), &last_error);
        g_tcp_dial_debug = old_debug;

        if (client < 0 || strcmp(selected_address, expected_address) != 0) {
            failed = 1;
        } else {
            accepted = accept(listeners[1], NULL, NULL);
            if (accepted < 0) failed = 1;
        }

        int unwanted = accept(listeners[0], NULL, NULL);
        if (unwanted >= 0) {
            close(unwanted);
            failed = 1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            failed = 1;
        }
    }

    if (failed)
        fprintf(stderr, "[FAIL] TCP dial excludes a TLS-failed endpoint and selects an alternate address\n");
    else
        puts("[PASS] TCP dial excludes a TLS-failed endpoint and selects an alternate address");

    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    for (int i = 0; i < 2; i++) if (listeners[i] >= 0) close(listeners[i]);
    return failed;
}

static int run_poll_hup_regression(void) {
    int sv[2] = {-1, -1};
    int failed = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] poll HUP regression: socketpair: %s\n", strerror(errno));
        return 1;
    }

    if (send(sv[1], "x", 1, MSG_NOSIGNAL) != 1 ||
        shutdown(sv[1], SHUT_WR) < 0) {
        failed = 1;
    } else {
        int rc = poll_fd_until(sv[0], POLLIN, now_ms() + 500);
        char byte = 0;
        ssize_t n = recv(sv[0], &byte, 1, 0);
        int eof_rc = poll_fd_until(sv[0], POLLIN, now_ms() + 500);
        char eof_byte = 0;
        ssize_t eof_n = recv(sv[0], &eof_byte, 1, 0);
        if (rc != 1 || n != 1 || byte != 'x' ||
            eof_rc != 1 || eof_n != 0) failed = 1;
    }

    if (failed)
        fprintf(stderr, "[FAIL] poll HUP is surfaced as readable EOF without losing buffered data\n");
    else
        puts("[PASS] poll HUP is surfaced as readable EOF without losing buffered data");

    close(sv[0]);
    close(sv[1]);
    return failed;
}

static int run_tls_message_callback_errno_regression(void) {
    const unsigned char message[] = {1};
    unsigned int saved_count = g_tls_diag_message_count;
    const char *saved_log_path = g_log_path;
    int saved_errno = errno;

    g_tls_diag_message_count = 0;
    /* /dev/null is a file, not a directory: fopen() must fail with ENOTDIR.
     * This guarantees the logger clobbers errno unless the callback restores it. */
    g_log_path = "/dev/null/passwall-core-errno-test.log";
    errno = EAGAIN;
    tls_message_callback(1, TLS1_2_VERSION, SSL3_RT_HANDSHAKE,
                         message, sizeof(message), NULL, NULL);
    int callback_errno = errno;

    g_tls_diag_message_count = saved_count;
    g_log_path = saved_log_path;
    errno = saved_errno;

    if (callback_errno != EAGAIN) {
        fprintf(stderr, "[FAIL] TLS message callback logger changed errno (%d -> %d)\n",
                EAGAIN, callback_errno);
        return 1;
    }
    puts("[PASS] TLS message callback preserves errno for SSL_get_error");
    return 0;
}

static int run_tls_unexpected_eof_retryable_regression(void) {
    int sv[2] = {-1, -1};
    SSL_CTX *ctx = NULL;
    tls_engine_t *engine = NULL;
    int started = 0;
    int wait_rc = 0;
    int failed = 0;
    int retryable = 0;
    int start_error = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] TLS Engine unexpected-EOF setup: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }
    ctx = SSL_CTX_new(TLS_client_method());
    engine = tls_engine_create(4096U);
    if (!ctx || !engine) {
        fprintf(stderr, "[FAIL] TLS Engine unexpected-EOF allocation: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }

    /* Peer closes without a TLS alert or handshake response. */
    close(sv[1]);
    sv[1] = -1;
    if (tls_engine_start(engine, ctx, sv[0], "localhost", 0, 1000) != 0) {
        fprintf(stderr, "[FAIL] TLS Engine unexpected-EOF start: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }
    sv[0] = -1; /* descriptor ownership transferred to TLS Engine */
    started = 1;
    wait_rc = tls_engine_wait_ready(engine);
    retryable = tls_engine_start_retryable(engine);
    start_error = tls_engine_start_error(engine);
    if (wait_rc == 0 || !retryable || start_error == 0)
        failed = 1;

done:
    if (started) (void)tls_engine_join(engine);
    tls_engine_destroy(engine);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
    SSL_CTX_free(ctx);

    if (failed) {
        fprintf(stderr,
                "[FAIL] peer EOF during TLS Engine handshake is retryable (rc=%d retryable=%d error=%d)\n",
                wait_rc, retryable, start_error);
        return 1;
    }
    puts("[PASS] peer EOF during TLS Engine handshake is classified as retryable");
    return 0;
}

static int run_tls_diag_config_regression(void) {
    char path[] = "/tmp/passwall-tls-diag-test-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "[FAIL] TLS_DIAG config regression: mkstemp: %s\n", strerror(errno));
        return 1;
    }

    const char enabled[] = "TLS_DIAG=1\n";
    ssize_t written = write(fd, enabled, sizeof(enabled) - 1);
    close(fd);
    if (written != (ssize_t)(sizeof(enabled) - 1)) {
        unlink(path);
        fprintf(stderr, "[FAIL] TLS_DIAG config regression: write failed\n");
        return 1;
    }

    app_cfg_t cfg = {0};
    if (cfg.tls_diag != 0) {
        unlink(path);
        fprintf(stderr, "[FAIL] TLS_DIAG defaults to off\n");
        return 1;
    }
    load_env(path, &cfg);
    unlink(path);

    if (cfg.tls_diag != 1) {
        fprintf(stderr, "[FAIL] TLS_DIAG=1 was not parsed (value=%d)\n", cfg.tls_diag);
        return 1;
    }
    puts("[PASS] TLS message tracing is opt-in and TLS_DIAG=1 is parsed");
    return 0;
}

static int run_tls_handshake_timeout_retryable_regression(void) {
    int sv[2] = {-1, -1};
    SSL_CTX *ctx = NULL;
    tls_engine_t *engine = NULL;
    int started = 0;
    int wait_rc = 0;
    int failed = 0;
    int retryable = 0;
    int start_error = 0;
    long long elapsed = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] TLS Engine handshake timeout setup: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }
    ctx = SSL_CTX_new(TLS_client_method());
    engine = tls_engine_create(4096U);
    if (!ctx || !engine) {
        fprintf(stderr, "[FAIL] TLS Engine handshake timeout allocation: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }

    /* Keep peer open but silent: ClientHello is written and handshake deadline expires. */
    long long started_at = now_ms();
    if (tls_engine_start(engine, ctx, sv[0], "localhost", 0, 100) != 0) {
        fprintf(stderr, "[FAIL] TLS Engine handshake timeout start: %s\n", strerror(errno));
        failed = 1;
        goto done;
    }
    sv[0] = -1;
    started = 1;
    wait_rc = tls_engine_wait_ready(engine);
    elapsed = now_ms() - started_at;
    retryable = tls_engine_start_retryable(engine);
    start_error = tls_engine_start_error(engine);
    if (wait_rc == 0 || !retryable || start_error != ETIMEDOUT ||
        elapsed < 70 || elapsed > 1500)
        failed = 1;

done:
    if (started) (void)tls_engine_join(engine);
    tls_engine_destroy(engine);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
    SSL_CTX_free(ctx);

    if (failed) {
        fprintf(stderr,
                "[FAIL] silent TLS peer timeout is bounded and retryable (rc=%d retryable=%d error=%d elapsed=%lld ms)\n",
                wait_rc, retryable, start_error, elapsed);
        return 1;
    }
    puts("[PASS] silent TLS peer timeout is bounded and retryable");
    return 0;
}

static int run_tcp_dial_success_clears_errno_regression(void) {
    int refused_fd = -1;
    int listener = -1;
    int client = -1;
    int accepted = -1;
    int failed = 0;
    struct sockaddr_in refused_addr, live_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct addrinfo entries[2];
    char selected[INET6_ADDRSTRLEN + 24] = {0};
    int last_error = 0;

    memset(&refused_addr, 0, sizeof(refused_addr));
    memset(&live_addr, 0, sizeof(live_addr));
    memset(entries, 0, sizeof(entries));

    refused_fd = socket(AF_INET, SOCK_STREAM, 0);
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (refused_fd < 0 || listener < 0) { failed = 1; goto done; }

    /* Reserve the live endpoint first so the refused port cannot be reused. */
    live_addr.sin_family = AF_INET;
    live_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    live_addr.sin_port = 0;
    addr_len = sizeof(live_addr);
    if (bind(listener, (struct sockaddr *)&live_addr, sizeof(live_addr)) < 0 ||
        listen(listener, 1) < 0 ||
        getsockname(listener, (struct sockaddr *)&live_addr, &addr_len) < 0) {
        failed = 1;
        goto done;
    }

    refused_addr.sin_family = AF_INET;
    refused_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    refused_addr.sin_port = 0;
    addr_len = sizeof(refused_addr);
    if (bind(refused_fd, (struct sockaddr *)&refused_addr, sizeof(refused_addr)) < 0 ||
        getsockname(refused_fd, (struct sockaddr *)&refused_addr, &addr_len) < 0) {
        failed = 1;
        goto done;
    }
    close(refused_fd);
    refused_fd = -1;

    entries[0].ai_family = AF_INET;
    entries[0].ai_socktype = SOCK_STREAM;
    entries[0].ai_protocol = IPPROTO_TCP;
    entries[0].ai_addr = (struct sockaddr *)&refused_addr;
    entries[0].ai_addrlen = sizeof(refused_addr);
    entries[0].ai_next = &entries[1];

    entries[1].ai_family = AF_INET;
    entries[1].ai_socktype = SOCK_STREAM;
    entries[1].ai_protocol = IPPROTO_TCP;
    entries[1].ai_addr = (struct sockaddr *)&live_addr;
    entries[1].ai_addrlen = sizeof(live_addr);

    int old_debug = g_tcp_dial_debug;
    g_tcp_dial_debug = 0;
    errno = 0;
    client = tcp_connect_addrinfo_list(
        &entries[0], AF_INET, now_ms() + 2000,
        NULL, 0, selected, sizeof(selected), &last_error);
    int result_errno = errno;
    g_tcp_dial_debug = old_debug;

    if (client < 0 || last_error != 0 || result_errno != 0)
        failed = 1;
    if (!failed) {
        accepted = accept(listener, NULL, NULL);
        if (accepted < 0) failed = 1;
    }

done:
    if (failed)
        fprintf(stderr,
                "[FAIL] successful TCP race clears stale errno after an earlier refused candidate (errno=%d last_error=%d)\n",
                errno, last_error);
    else
        puts("[PASS] successful TCP race clears stale errno after an earlier refused candidate");

    if (accepted >= 0) close(accepted);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    if (refused_fd >= 0) close(refused_fd);
    return failed;
}

static int run_pending_keepalive_terminal_cleanup_regression(void) {
    int failed = 0;

    set_pending_operation(NULL, PENDING_KEEPALIVE);
    int eagain_state = settle_pending_keepalive_result(LIBSSH2_ERROR_EAGAIN);
    if (eagain_state != 0 || g_pending_op != PENDING_KEEPALIVE ||
        g_pending_client != NULL) {
        failed = 1;
        fprintf(stderr, "[FAIL] pending keepalive retains state only on EAGAIN\n");
    }

    set_pending_operation(NULL, PENDING_KEEPALIVE);
    int error_state = settle_pending_keepalive_result(LIBSSH2_ERROR_SOCKET_RECV);
    if (error_state != -1 || g_pending_op != PENDING_NONE ||
        g_pending_client != NULL) {
        failed = 1;
        fprintf(stderr, "[FAIL] terminal keepalive socket error clears pending state\n");
    }

    set_pending_operation(NULL, PENDING_KEEPALIVE);
    int success_state = settle_pending_keepalive_result(0);
    if (success_state != 1 || g_pending_op != PENDING_NONE ||
        g_pending_client != NULL) {
        failed = 1;
        fprintf(stderr, "[FAIL] successful keepalive clears pending state\n");
    }

    clear_pending_operation();
    if (!failed)
        puts("[PASS] pending keepalive is retained on EAGAIN and cleared on terminal results");
    return failed;
}


static int run_tls_buffered_input_probe_gate_regression(void) {
    tls_engine_t *engine = tls_engine_create(4096U);
    if (!engine) {
        fprintf(stderr, "[FAIL] TLS Engine queue readiness setup: %s\n", strerror(errno));
        return 1;
    }
    upstream_ctx_t u = {.tls = engine};
    char byte = 0;
    int failed = 0;
    errno = 0;
    ssize_t rc = tls_engine_recv(engine, &byte, sizeof(byte));
    if (rc != -1 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
        tls_buffered_input_pending(&u) ||
        tls_engine_rx_pending(engine) != 0 ||
        tls_engine_tx_pending(engine) != 0 ||
        tls_engine_notify_fd(engine) < 0)
        failed = 1;
    tls_engine_destroy(engine);

    if (failed) {
        fprintf(stderr, "[FAIL] empty TLS RX queue reports EAGAIN and no buffered input\n");
        return 1;
    }
    puts("[PASS] empty TLS RX queue reports EAGAIN and no buffered input");
    return 0;
}

static int run_tls_callback_terminal_result_clears_want_event_regression(void) {
    tls_engine_t *engine = tls_engine_create(4096U);
    if (!engine) {
        fprintf(stderr, "[FAIL] TLS terminal eventfd setup: %s\n", strerror(errno));
        return 1;
    }
    upstream_ctx_t u = {.tls = engine, .rx_flush_eagain = 1};
    int failed = 0;

    ssize_t first = mark_upstream_rx_terminal(&u, 0);
    if (first != -EAGAIN || !u.rx_terminal || u.rx_terminal_rc != 0 ||
        u.upstream_epoll_detached || !upstream_client_write_allowed(&u))
        failed = 1;

    u.rx_flush_eagain = 0;
    ssize_t drained = mark_upstream_rx_terminal(&u, 0);
    if (drained != 0 || u.rx_terminal_rc != 0 || u.upstream_epoll_detached)
        failed = 1;

    u.tx_terminal = 1;
    (void)mark_upstream_rx_terminal(&u, 0);
    if (!u.upstream_epoll_detached || upstream_client_write_allowed(&u))
        failed = 1;

    tls_engine_destroy(engine);
    if (failed) {
        fprintf(stderr, "[FAIL] receive terminal flush and TLS RX/TX eventfd lifetime\n");
        return 1;
    }
    puts("[PASS] receive terminal flush and TLS RX/TX eventfd lifetime");
    return 0;
}

static int run_core_state_regressions(void) {
    int failures = 0;
    failures += run_ipv4_dial_regression();
    failures += run_ipv6_dial_regression();
    failures += run_tcp_dial_exclusion_regression();
    failures += run_tcp_dial_success_clears_errno_regression();
    failures += run_poll_hup_regression();
    failures += run_tls_message_callback_errno_regression();
    failures += run_tls_diag_config_regression();
    failures += run_tls_unexpected_eof_retryable_regression();
    failures += run_tls_handshake_timeout_retryable_regression();
    failures += run_ring_buffer_regressions();
    failures += run_s2c_read_retry_recomputes_slice_regression();
    failures += run_relay_buffer_capacity_regression();
    failures += run_eof_drain_regression();
    failures += run_graceful_hup_preserves_c2s_regression();
    failures += run_deferred_client_cleanup_regression();
    failures += run_cleanup_deadline_and_shutdown_pending_regression();
    failures += run_pending_open_cleanup_deadline_regression();
    failures += run_aborted_open_completion_cleanup_regression();
    failures += run_shutdown_poll_ignores_stop_regression();
    failures += run_pending_channel_close_buffer_regression();
    failures += run_inbound_only_channel_close_regression();
    failures += run_pending_op_serialization_regression();
    failures += run_pending_keepalive_terminal_cleanup_regression();
    failures += run_tls_want_event_lifetime_regression();
    failures += run_tls_buffered_input_probe_gate_regression();
    failures += run_tls_callback_terminal_result_clears_want_event_regression();
    failures += run_upstream_rx_progress_regression();
    failures += run_upstream_drain_state_regression();
    failures += run_upstream_client_write_gate_regression();
    failures += run_upstream_hup_epoll_policy_regression();
    failures += run_upstream_epoll_timeout_regression();
    failures += run_upstream_hup_client_rejection_regression();
    failures += run_upstream_rx_terminal_callback_regression();
    failures += run_ssl_read_terminal_classification_regression();
    failures += run_http_rejection_classification_regression();
    failures += run_socks_listener_address_regression();

    size_t parsed_hex = 0;
    if (parse_strict_hex_size("10", &parsed_hex, MAX_HTTP_SKIP_BODY) != 0 || parsed_hex != 16 ||
        parse_strict_hex_size("10 garbage", &parsed_hex, MAX_HTTP_SKIP_BODY) == 0) {
        fprintf(stderr, "[FAIL] chunk-size parser rejects non-hex suffixes\n");
        failures++;
    } else {
        puts("[PASS] chunk-size parser rejects non-hex suffixes");
    }

    upstream_ctx_t chunk_guard = {0};
    if (http_chunk_total_add(&chunk_guard, MAX_HTTP_SKIP_BODY - 1U) != 0 ||
        http_chunk_total_add(&chunk_guard, 1U) != 0 ||
        http_chunk_total_add(&chunk_guard, 1U) == 0) {
        fprintf(stderr, "[FAIL] cumulative chunked-body limit is enforced\n");
        failures++;
    } else {
        puts("[PASS] cumulative chunked-body limit is enforced");
    }

    uint8_t socks_req[4] = {0x05, 0x01, 0x00, 0x01};
    uint8_t domain_req_ok[10] = {0x05, 0x01, 0x00, 0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50};
    uint8_t domain_req_short[5] = {0x05, 0x01, 0x00, 0x03, 0x03};
    uint8_t domain_req_nul[10] = {0x05, 0x01, 0x00, 0x03, 0x03, 'a', 0x00, 'c', 0x00, 0x50};
    if (!socks5_reserved_valid(socks_req, sizeof(socks_req)) ||
        socks5_reserved_valid((uint8_t[]){0x05,0x01,0x01,0x01}, 4) ||
        !socks5_domain_valid(domain_req_ok, sizeof(domain_req_ok)) ||
        socks5_domain_valid(domain_req_short, sizeof(domain_req_short)) ||
        socks5_domain_valid(domain_req_nul, sizeof(domain_req_nul))) {
        fprintf(stderr, "[FAIL] SOCKS5 RSV and domain validation\n");
        failures++;
    } else {
        puts("[PASS] SOCKS5 RSV and domain validation");
    }

    failures += run_ipv6_dial_regression();

    client_conn_t idle = {
        .state = ST_RELAY,
        .last_activity_ms = 1000
    };
    if (!relay_idle_timeout_due(&idle, 1, 2000)) {
        fprintf(stderr, "[FAIL] expired relay idle timeout is detected\n");
        failures++;
    } else {
        puts("[PASS] expired relay idle timeout is detected");
    }
    idle.abort_on_pending = 1;
    if (relay_idle_timeout_due(&idle, 1, 3000)) {
        fprintf(stderr, "[FAIL] pending-abort relay does not repeat idle-timeout handling\n");
        failures++;
    } else {
        puts("[PASS] pending-abort relay does not repeat idle-timeout handling");
    }

    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fprintf(stderr, "[FAIL] delay wait deadline: socketpair: %s\n", strerror(errno));
        failures++;
    } else {
        upstream_ctx_t u = {.fd = sv[0]};
        long long start = now_ms();
        delay_wait_and_drain(&u, 45);
        long long elapsed = now_ms() - start;
        if (elapsed < 35) {
            fprintf(stderr, "[FAIL] delay wait stopped at the poll slice timeout (%lld ms)\n", elapsed);
            failures++;
        } else {
            printf("[PASS] delay wait respects full deadline across poll time slices (%lld ms)\n", elapsed);
        }
        close(sv[0]);
        close(sv[1]);
    }

    return failures;
}

static int run_perf_metrics_regression(void) {
    char path[] = "/tmp/ssh-core-perf-test-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "[FAIL] perf metrics: mkstemp: %s\\n", strerror(errno));
        return 1;
    }
    close(fd);

    const char *saved_log_path = g_log_path;
    int saved_log_perf = g_log_perf;
    g_log_path = path;
    g_log_perf = 1;
    perf_begin(1000);
    g_perf_stats.epoll_calls = 4;
    g_perf_stats.epoll_wait_ms = 375;
    g_perf_stats.tls_rx_bytes = 8192;
    g_perf_stats.tls_rx_eagain = 3;
    g_perf_stats.s2c_read_bytes = 4096;
    g_perf_stats.socks_tx_bytes = 4096;
    g_perf_stats.pending_blocks = 2;

    perf_log_interval(1999);
    FILE *f = fopen(path, "r");
    long early_size = -1;
    if (f) {
        fseek(f, 0, SEEK_END);
        early_size = ftell(f);
        fclose(f);
    }

    perf_log_interval(2000);
    char line[2048] = {0};
    f = fopen(path, "r");
    if (f) {
        (void)fread(line, 1, sizeof(line) - 1, f);
        fclose(f);
    }

    int failed = early_size != 0 ||
        !strstr(line, "[PERF] span_ms=1000") ||
        !strstr(line, "ep_calls=4") ||
        !strstr(line, "ep_wait_ms=375") ||
        !strstr(line, "tls_rx_bytes=8192") ||
        !strstr(line, "tls_rx_eagain=3") ||
        !strstr(line, "s2c_read_bytes=4096") ||
        !strstr(line, "socks_tx_bytes=4096") ||
        !strstr(line, "pend_blk=2") ||
        g_perf_stats.epoll_calls != 0 ||
        g_perf_stats.tls_rx_bytes != 0 ||
        g_perf_stats.pending_blocks != 0;

    g_log_perf = saved_log_perf;
    g_log_path = saved_log_path;
    unlink(path);

    if (failed) {
        fprintf(stderr, "[FAIL] opt-in per-interval perf metrics or counter reset\\n");
        return 1;
    }
    puts("[PASS] opt-in per-interval perf metrics and counter reset");
    return 0;
}

static int run_worker_count_regressions(void) {
    static const long cpu_counts[] = { -2, 0, 1, 2, 3, 4, 8, 16 };
    static const uint32_t expected_io_workers[] = { 1, 1, 1, 2, 3, 4, 4, 4 };
    int failures = 0;

    for (size_t i = 0; i < sizeof(cpu_counts) / sizeof(cpu_counts[0]); i++) {
        int sessions = ssh_session_count_for_cpu_count(cpu_counts[i]);
        uint32_t io_workers = io_worker_count_for_cpu_count(cpu_counts[i]);
        if (sessions != 1) {
            fprintf(stderr,
                    "[FAIL] CPU count %ld selected %d SSH sessions; expected exactly 1\\n",
                    cpu_counts[i], sessions);
            failures++;
        } else {
            printf("[PASS] CPU count %ld keeps exactly one SSH session\\n",
                   cpu_counts[i]);
        }
        if (io_workers != expected_io_workers[i]) {
            fprintf(stderr,
                    "[FAIL] CPU count %ld selected %u I/O workers; expected %u\\n",
                    cpu_counts[i], io_workers, expected_io_workers[i]);
            failures++;
        } else {
            printf("[PASS] CPU count %ld selects %u bounded I/O worker(s)\\n",
                   cpu_counts[i], io_workers);
        }
    }

    long detected = detect_available_cpu_count();
    int sessions = ssh_session_count_for_cpu_count(detected);
    uint32_t io_workers = io_worker_count_for_cpu_count(detected);
    if (detected < 1 || sessions != 1 || io_workers < 1U ||
        io_workers > IO_WORKER_POOL_MAX_WORKERS) {
        fprintf(stderr,
                "[FAIL] live CPU detection returned %ld CPU(s), SSH sessions=%d, I/O workers=%u\\n",
                detected, sessions, io_workers);
        failures++;
    } else {
        printf("[PASS] live CPU detection: %ld available CPU(s), %u I/O worker(s), exactly 1 SSH session\\n",
               detected, io_workers);
    }
    return failures;
}

int main(void) {
    g_log_path = "-";
    int failures = run_core_state_regressions();
    failures += run_perf_metrics_regression();
    failures += run_worker_count_regressions();

    failures += run_case(
        "GET 200 Content-Length body is not a tunnel",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        0, 0, 0, 0, 0);

    failures += run_case(
        "GET 200 Content-Length zero is not a tunnel",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        0, 0, 0, 0, 0);

    failures += run_followup_case(
        "GET 200 Content-Length zero followed by SSH is rejected",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nSSH-2.0-should-not-be-a-tunnel\r\n");

    failures += run_followup_case(
        "GET 200 framed body followed by SSH is rejected",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloSSH-2.0-should-not-be-a-tunnel\r\n");

    failures += run_followup_case(
        "GET 200 chunked body followed by SSH is rejected",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nSSH-2.0-should-not-be-a-tunnel\r\n");

    failures += run_fragmented_followup_case(
        "fragmented Content-Length body preserves parser state across EAGAIN",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe",
        "lloSSH-2.0-should-not-be-a-tunnel\r\n");

    failures += run_fragmented_followup_case(
        "fragmented chunked body preserves parser state across EAGAIN",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe",
        "llo\r\n0\r\n\r\nSSH-2.0-should-not-be-a-tunnel\r\n");

    failures += run_case(
        "GET 200 chunked body is drained, not a tunnel",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        0, 0, 0, 0, 0);

    failures += run_case(
        "malformed chunk-size suffix is rejected",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10 garbage\r\n",
        0, 0, 0, -1, 0);

    failures += run_case(
        "single chunk above the body limit is rejected",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000001\r\n",
        0, 0, 0, -1, 0);

    failures += run_case(
        "GET 200 close-delimited body fails closed at EOF",
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nordinary page body",
        0, 0, 1, -1, 0);

    failures += run_case(
        "unframed non-CONNECT HTTP 200 fails closed",
        "HTTP/1.1 200 OK\r\n\r\nbody",
        0, 0, 0, -1, 0);
    failures += run_case(
        "HTTP status line with repeated separator spaces is rejected",
        "HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n",
        0, 0, 0, -1, 0);

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
        "bare SSH banner without an HTTP response is accepted",
        "SSH-2.0-direct-server\r\n",
        0, 0, 0, 0, 1);

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
    puts("All HTTP parser, SOCKS validation, IPv6, worker-selection and core state regression tests passed.");
    return 0;
}
