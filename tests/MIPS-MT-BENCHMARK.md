# MT7621 MIPS parallel-session benchmark

This experiment targets the OpenWrt 24.10.7 mipsel_24kc guest booted by the MT7621 QEMU router emulator.

## What is being compared

The MIPS helper socks-mt-download creates four real POSIX pthreads. Each thread opens its own SOCKS5 connection and downloads the same 32 MiB fixture through the local core.

The VM runs three configurations:

1. 1 core / 1 SSH session: all four client threads share the single core process and its existing single LIBSSH2_SESSION.
2. 2 isolated core workers / 2 SSH sessions: two core processes listen on ports 1080 and 1081. The four download threads are distributed round-robin across them.
3. 4 isolated core workers / 4 SSH sessions: four core processes listen on ports 1080–1083, one SSH session per independent core process.

Each run transfers 4 × 32 MiB (128 MiB total). The helper streams each response body through a SHA-256 digest without writing the 4 × 32 MiB payloads to OpenWrt tmpfs. Each client verifies HTTP Content-Length, exact received byte count and SHA-256 against the host fixture. It prints per-client duration and throughput plus aggregate MiB/s.

## Why the initial comparison uses isolated sessions

The present ssh-core.c has a single process-global LIBSSH2_SESSION and global event-loop state (g_clients, g_pending_op, g_opening_client, upstream TLS state and performance counters). Concurrently calling libssh2 on that one session from several threads would not be a safe threading experiment.

The 2-worker and 4-worker configurations therefore use independent core processes, each with its own upstream socket, TLS/TCP state, libssh2 session, event loop and SOCKS listener. This is a safe parallel-session reference point for a future in-process worker-thread design. It is not a claim that the core itself has already become multithreaded. The pthreads in this first experiment are the concurrent download clients.

A real in-process thread pool must give every worker exclusive ownership of its own upstream connection, TLS object, LIBSSH2_SESSION, epoll set, pending-operation state, client list and ring buffers. Sharing the current session under a mutex would serialize the bottleneck and can violate libssh2's operation/buffer retry requirements.

## Diagnostics collected

For every benchmark run the guest records:

- [PERF] counters from every core instance: epoll wait/wakeups, TLS RX calls/bytes/EAGAIN, SSH channel reads, SOCKS TX, S2C-full events and libssh2 EAGAIN.
- Per-process /proc/<pid>/status: Threads, RSS and context switches.
- Per-thread /proc/<pid>/task/<tid>/stat user/system CPU ticks.
- Per-core /proc/stat, load average, /proc/net/snmp, /proc/net/netstat and /proc/net/tcp.
- Download helper per-client and aggregate throughput, streamed exact byte counts and SHA-256 checks (payloads are not written to guest storage).
- Core stdout/log files, guest console, host HTTP/SSH/TLS fixture logs and emulator logs.

## Interpretation

- If throughput increases from 1 to 2 or 4 isolated sessions, independent libssh2 sessions can use more of the MT7621's available CPU/transport capacity. That gives a target for a later in-process worker-thread architecture.
- If throughput does not increase, compare per-process CPU, TCP queues/retransmissions, TLS RX and S2C-full counters before assuming thread scheduling is the answer.
- Compare QEMU results as relative A/B measurements only. TCG emulation throughput is not a prediction of native router MiB/s.
- A successful transfer requires every client to receive exactly 33,554,432 bytes and match the host SHA-256 fixture.

The workflow is .github/workflows/passwall-ssh-core-openwrt24-mipsel-vm.yml. It uses [mips-stage=sdk] to build the R23 IPK and MIPS helpers, then [mips-stage=vm] [sdk_run_id=RUN_ID] to boot the MT7621 VM and run the tests.
