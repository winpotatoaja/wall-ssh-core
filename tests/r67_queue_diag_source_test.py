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
    ]
    if not all(checks): return 1
    print("PASS: R67-DIAG queue instrumentation is read-only and LOG_PERF-gated")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
