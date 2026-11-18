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
    c.read_pending = 1;
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
    c.read_pending = 0;
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
    c.read_pending = 1;
    if (has_pending_libssh2_work_for_shutdown()) failed = 1;
    c.read_pending = 0;
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
        c->read_pending = 1;
        c->read_pending_tail = c->s2c.tail;
        c->read_pending_generation = c->s2c.generation;
        c->read_pending_len = 8;

        g_clients = c;
        g_client_count = 1;
        g_opening_client = NULL;
        set_pending_operation(c, PENDING_WRITE);
        start_closing_client(-1, c);

        const uint8_t *c2s_read = rb_read_slice_pinned(
            &c->c2s, c->write_pending_head, c->write_pending_generation, c->write_pending_len);
        uint8_t *s2c_retry = rb_write_slice_pinned(
            &c->s2c, c->read_pending_tail, c->read_pending_generation, c->read_pending_len);
        if (g_clients != c || g_client_count != 1 || c->state != ST_RELAY ||
            !c->abort_on_pending || g_pending_client != c || g_pending_op != PENDING_WRITE ||
            !c->write_pending || !c->read_pending ||
            !c2s_read || memcmp(c2s_read, "upload", 6) != 0 || s2c_retry != s2c_write) {
            failed = 1;
        }

        /* Once the pinned write has completed, a leftover inbound read EAGAIN
         * must not keep the client object or ring buffers alive. */
        clear_pending_operation();
        c->abort_on_pending = 0;
        c->write_pending = 0;
        start_closing_client(-1, c);
        if (c->state != ST_CLOSING || c->c2s.data || c->s2c.data ||
            c->read_pending || c->write_pending) failed = 1;
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
        c->read_pending = 1;
        c->read_pending_tail = c->s2c.tail;
        c->read_pending_generation = c->s2c.generation;
        c->read_pending_len = 8;
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
        if (c->state != ST_CLOSING || c->read_pending || c->write_pending ||
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
    if (!pending_op_requires_serial_retry(PENDING_WRITE, &c, inbound, EPOLLIN))
        failed = 1;
    c.write_waiting_window = 1;
    if (pending_op_requires_serial_retry(PENDING_WRITE, &c, inbound, EPOLLIN))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_WRITE, &c, outbound, 0))
        failed = 1;

    if (!pending_op_requires_serial_retry(PENDING_SEND_EOF, &c, inbound, EPOLLIN))
        failed = 1;
    /* A TLS read that needs the socket writable must be retried before other
     * SSH calls; an ordinary read WANT_READ can share the SSH packet reader. */
    if (pending_op_requires_serial_retry(PENDING_READ, &c, inbound, EPOLLIN))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_READ, &c, inbound, EPOLLOUT))
        failed = 1;
    if (pending_op_requires_serial_retry(PENDING_FREE, &c, inbound, EPOLLIN))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_FREE, &c, outbound, 0))
        failed = 1;
    if (!pending_op_requires_serial_retry(PENDING_KEEPALIVE, NULL, inbound, EPOLLIN))
        failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] libssh2 EAGAIN serialization preserves active write and send operations\n");
        return 1;
    }
    puts("[PASS] libssh2 EAGAIN serialization preserves active write and send operations");
    return 0;
}

static int run_tls_want_event_lifetime_regression(void) {
    upstream_ctx_t u = {
        .ssl = (SSL *)(uintptr_t)1,
        .ssl_want_events = EPOLLIN
    };
    int idle_rx_paused = 1;
    uint32_t want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 0, 0);
    int failed = 0;

    /* An idle SSL_read WANT_READ is stale readiness, not a pinned operation:
     * it must not defeat the S2C backpressure pause or block keepalive. */
    if ((want & EPOLLIN) != 0 || (want & EPOLLRDHUP) == 0 ||
        !idle_rx_paused || !keepalive_can_start(&u, PENDING_NONE) ||
        tls_write_retry_pending(&u) || shutdown_io_pending(&u)) {
        failed = 1;
    }

    /* The same WANT_READ is authoritative when it belongs to a serialized
     * operation such as SSL_write; the pending retry must keep EPOLLIN armed
     * and must protect both keepalive and shutdown from interleaving. */
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_WRITE, LIBSSH2_SESSION_BLOCK_OUTBOUND,
        &idle_rx_paused, 0, 0, 0);
    set_pending_operation(NULL, PENDING_WRITE);
    if ((want & EPOLLIN) == 0 ||
        keepalive_can_start(&u, PENDING_WRITE) ||
        !shutdown_io_pending(&u)) {
        failed = 1;
    }
    clear_pending_operation();

    /* WANT_WRITE remains an active TLS retry even without a libssh2 pending
     * marker and must block both keepalive and teardown I/O. */
    u.ssl_want_events = EPOLLOUT;
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 0, 0);
    if ((want & EPOLLOUT) == 0 ||
        keepalive_can_start(&u, PENDING_NONE) ||
        !tls_write_retry_pending(&u) ||
        !shutdown_io_pending(&u)) {
        failed = 1;
    }

    /* Normal channel demand can re-arm EPOLLIN after the pause has been set. */
    u.ssl_want_events = EPOLLIN;
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_NONE, 0, &idle_rx_paused, 0, 1, 0);
    if ((want & EPOLLIN) == 0 || idle_rx_paused) failed = 1;

    /* A pending libssh2 operation with no TLS readiness flag still uses the
     * libssh2 block directions instead of losing its wakeup source. */
    u.ssl_want_events = 0;
    idle_rx_paused = 1;
    want = upstream_epoll_interest(
        &u, PENDING_FREE,
        LIBSSH2_SESSION_BLOCK_INBOUND | LIBSSH2_SESSION_BLOCK_OUTBOUND,
        &idle_rx_paused, 0, 0, 0);
    if ((want & (EPOLLIN | EPOLLOUT)) != (EPOLLIN | EPOLLOUT))
        failed = 1;

    if (failed) {
        fprintf(stderr, "[FAIL] TLS WANT_READ lifetime, keepalive, shutdown and epoll backpressure state\n");
        return 1;
    }
    puts("[PASS] TLS WANT_READ lifetime, keepalive, shutdown and epoll backpressure state");
    return 0;
}

static int run_upstream_rx_progress_regression(void) {
    upstream_ctx_t u = {.rx_seq = 12, .ssl_want_events = EPOLLIN};
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

static int run_upstream_hup_state_regression(void) {
    int failed = 0;
    if (!upstream_hup_needs_restart(1, 10, 10, 0)) failed = 1;
    if (upstream_hup_needs_restart(1, 10, 11, 0)) failed = 1;
    if (upstream_hup_needs_restart(1, 10, 10, 16)) failed = 1;
    if (upstream_hup_needs_restart(0, 10, 10, 0)) failed = 1;
    if (failed) {
        fprintf(stderr, "[FAIL] upstream HUP restarts only after buffered receive progress is drained\n");
        return 1;
    }
    puts("[PASS] upstream HUP waits for receive drain progress before restart");
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

static int run_core_state_regressions(void) {
    int failures = 0;
    failures += run_ipv4_dial_regression();
    failures += run_ipv6_dial_regression();
    failures += run_tcp_dial_exclusion_regression();
    failures += run_poll_hup_regression();
    failures += run_ring_buffer_regressions();
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
    failures += run_tls_want_event_lifetime_regression();
    failures += run_upstream_rx_progress_regression();
    failures += run_upstream_hup_state_regression();
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

int main(void) {
    g_log_path = "-";
    int failures = run_core_state_regressions();

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
    puts("All HTTP parser, SOCKS validation, IPv6 and core state regression tests passed.");
    return 0;
}
