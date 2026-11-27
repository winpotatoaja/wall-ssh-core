#!/usr/bin/env python3
"""Source invariants for R67 diagnostic-only TCP/TLS queue sampling."""
from pathlib import Path
import sys

def check(ok, message):
    print(("PASS: " if ok else "FAIL: ") + message)
    return bool(ok)

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: r67_queue_diag_source_test.py SSH_CORE TLS_ENGINE_C TLS_ENGINE_H")
    ssh, tls_c, tls_h = [Path(p).read_text() for p in sys.argv[1:]]
    p0 = ssh.find("static void perf_log_interval(")
    p1 = ssh.find("\nstatic int poll_fd_until", p0)
    perf = ssh[p0:p1] if p0 >= 0 and p1 > p0 else ""
    a0 = tls_c.find("int tls_engine_queue_snapshot(")
    a1 = tls_c.find("\nint tls_engine_rx_terminal", a0)
    api = tls_c[a0:a1] if a0 >= 0 and a1 > a0 else ""
    d0 = tls_c.find("int tls_engine_diag_snapshot(")
    d1 = tls_c.find("\nint tls_engine_queue_snapshot", d0)
    diag_api = tls_c[d0:d1] if d0 >= 0 and d1 > d0 else ""
    checks = [
        check("#include <sys/ioctl.h>" in ssh and "#include <linux/sockios.h>" in ssh, "ssh-core includes Linux TCP queue ioctl declarations"),
        check("perf_socket_queue_bytes(c->fd, SIOCINQ" in perf and "perf_socket_queue_bytes(c->fd, SIOCOUTQ" in perf, "active SOCKS sockets expose both kernel queues"),
        check("perf_socket_queue_bytes(upstream->fd, SIOCINQ" in perf and "perf_socket_queue_bytes(upstream->fd, SIOCOUTQ" in perf, "plain TCP upstream exposes both kernel queues"),
        check("tls_engine_queue_snapshot(upstream->tls, &snapshot)" in perf, "TLS upstream queues are sampled through TLS Engine API"),
        check('log_raw("[QUEUE] span_ms=%lld' in perf and "tls_rx_buffered_bytes=%u" in perf and "socks_rxq_bytes_sum=%llu" in perf and "socks_txq_bytes_sum=%llu" in perf, "QUEUE record includes kernel and userspace queues"),
        check("if (!g_log_perf) return;" in perf and "perf_log_interval(now_ms(), session, &uctx);" in ssh, "queue sampling is gated by LOG_PERF"),
        check("tls_engine_queue_snapshot_t" in tls_h and "uint32_t rx_buffered_bytes;" in tls_h, "TLS queue snapshot API is declared"),
        check("ring_used(&engine->tls_to_ssh)" in api and "ring_used(&engine->ssh_to_tls)" in api and "ioctl(fd, SIOCINQ" in api and "ioctl(fd, SIOCOUTQ" in api, "TLS API reports ring occupancy and upstream kernel queues"),
        check("pthread_mutex_lock(&mutable_engine->mutex)" in api and "tls_engine_close_owned_socket(engine);" in tls_c, "TLS ioctl sampling is serialized against final socket close"),
        check("recv(" not in api and "send(" not in api and "SSL_read(" not in api and "SSL_write(" not in api, "snapshot performs no socket or TLS I/O"),
        check("tls_engine_diag_snapshot_t" in tls_h and "rx_want_read" in tls_h and "rx_burst_max" in tls_h and "tx_burst_max" in tls_h, "TLS fairness API exposes RX/TX wait and burst metrics"),
        check("tls_engine_diag_enable(engine, g_log_perf);" in ssh and ssh.find("tls_engine_diag_enable(engine, g_log_perf);") < ssh.find("tls_engine_start(engine, ssl_ctx"), "TLS telemetry configured before worker start"),
        check("tls_engine_diag_snapshot(upstream->tls, &tls_diag, 1)" in perf and 'log_raw("[TLSFAIR] span_ms=%lld' in perf, "TLS fairness snapshot is reset and emitted per LOG_PERF interval"),
        check("engine_try_read_measured" in tls_c and "engine_try_write_measured" in tls_c and "rx_while_tx_pending" in tls_c and "tx_while_rx_buffered" in tls_c, "TLS worker measures RX/TX service and cross-direction backlog"),
        check("poll_wait_us" in tls_c and "poll_socket_both" in tls_c and "rx_ring_full" in tls_c, "TLS worker records wait time, simultaneous readiness and RX ring pressure"),
        check("SSL_read(" not in diag_api and "SSL_write(" not in diag_api and "poll(" not in diag_api, "fairness snapshot reads counters only and performs no I/O"),
        check("uint64_t       s2c_nonempty_since_ns;" in ssh and
              "perf_note_s2c_nonempty(c, s2c_before);" in ssh and
              ssh.count("perf_note_s2c_nonempty(c, s2c_before);") == 2 and
              "perf_note_s2c_nonempty(c, before);" in ssh,
              "S2C nonempty episode timing follows both enqueue paths and the single client flush path"),
        check("s2c_nonempty_age_us_max" in perf or
              ('log_raw("[S2CAGE] span_ms=%lld' in perf and "s2c_nonempty_since_ns" in perf),
              "S2C episode age is sampled and emitted per LOG_PERF interval"),
        check("getsockopt(fd, IPPROTO_TCP, TCP_INFO" in ssh and
              "tcpi_rtt" in ssh and "tcpi_rttvar" in ssh and
              "tcpi_unacked" in ssh and "tcpi_snd_cwnd" in ssh and
              "tcpi_total_retrans" in ssh and "offsetof(struct tcp_info" in ssh,
              "TCP_INFO sampling validates returned structure length before reading fields"),
        check("#if defined(SIOCOUTQNSD)" in ssh and
              "perf_socket_queue_bytes(c->fd, SIOCOUTQNSD" in ssh and
              "notsent_supported=%u" in ssh,
              "SIOCOUTQNSD is compile-time guarded and reports support, samples and failures"),
        check('log_raw("[TCPINFO] span_ms=%lld' in perf and
              'log_raw("[S2CAGE] span_ms=%lld' in perf and
              "if (!g_log_perf || !c) return;" in ssh,
              "R68-D records remain read-only and LOG_PERF-gated"),
    ]
    if not all(checks): return 1
    print("PASS: R67 queue and R68-C TLS fairness diagnostics are read-only and LOG_PERF-gated")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
