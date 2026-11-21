# Passwall SSH Core

A non-blocking libssh2 client that owns exactly one upstream SSH session
(one authentication per process) and multiplexes local SOCKS5 clients over
SSH `direct-tcpip` channels. CPU detection must never increase the number of
upstream SSH logins; auxiliary multi-core I/O processing is developed separately.

## Single-session safety policy (R28+)

The process creates exactly one upstream TCP/TLS connection and one SSH
session, regardless of detected CPU count. Legacy WORKERS and -workers
settings remain accepted for launcher compatibility but are ignored when
selecting upstream SSH sessions. This prevents CPU detection from multiplying
password authentications. Calls on the single LIBSSH2_SESSION remain serialized.

## SPSC queue foundation (R29)

The standalone spsc_rb.h module is the first primitive for the planned
single-session multithreaded I/O pipeline. It is not yet wired into the live
relay and does not create additional threads.

The ring uses monotonically increasing uint32_t head/tail counters, a
power-of-two capacity no larger than 2^30, unsigned counter differences, and
acquire/release publication. It has no shared used field. Producer-owned tail
and consumer-owned head are separated by a 64-byte stride. A pinned read-span
API preserves the same byte pointer while libssh2 channel_write is pending on
EAGAIN; the SSH Owner will be the only consumer allowed to commit head.

Native regression tests pass, and the OpenWrt 24.10.7 SDK successfully
cross-compiled the standalone static SPSC test for MIPS32 Release 2. The
MT7621 QEMU execution is the next validation gate. Tests cover full/empty
states, physical wrap, pinned-span stability during producer appends, irregular
chunk sizes, byte integrity, and uint32_t counter rollover. This validates
the queue primitive only; eventfd, TLS ownership, I/O workers, and live relay
integration remain future stages.

## TLS Engine integration (Phase 2, R31)

The live SSH/TLS path uses a dedicated TLS Engine pthread. That thread creates
and exclusively owns SSL*, performs the TLS handshake and all TLS record I/O,
handles close_notify, and frees SSL*. The SSH Owner retains one LIBSSH2_SESSION
and all SSH channels. The two sides exchange plaintext through two SPSC byte
queues and an eventfd notification pair.

The integration covers initial HTTP payload transport, libssh2 send/receive
callbacks, readiness waits, epoll dispatch, RX terminal handling, clean
receive half-close while preserving TX, and bounded TLS shutdown. TX-space
eventfd notifications are not treated as inbound SSH data. Native, OpenWrt
24.10.7 mipsel_24kc SDK and MT7621 QEMU checks validate the engine; R31 CI
also asserts that ssh-core.c contains no direct SSL I/O calls.

## Package and executable names

The OpenWrt package is named `passwall-ssh-core`, and the runtime executable
installed by the package is `/usr/bin/passwall-ssh-core`. The package manifest,
service scripts, and VM integration test use this same executable path; no
post-install rename is required.

## OpenWrt 25.12.5 x86_64 build

The repository includes an OpenWrt package recipe at `Makefile`.
The recommended build path is the staged GitHub Actions workflow described
below. It uses the official OpenWrt 25.12.5 x86_64 SDK and the matching
OpenWrt 25.12 source package makefiles for OpenSSL and zlib, then builds
libssh2 from the packages feed.

## Security-related defaults

- SOCKS5 listens on `127.0.0.1:1080` by default and supports no-authentication
  only. Binding to a non-loopback address is rejected unless
  `ALLOW_REMOTE_SOCKS=1` / `-allow-remote-socks 1` is explicitly selected.
  If enabled, firewall restrictions are the operator's responsibility.
- `HTTP_200_TUNNEL=0` by default. A non-CONNECT HTTP 200 response is not
  treated as an SSH tunnel unless the legacy behavior is explicitly enabled.
- `VERIFY_TLS=1` is the secure default. TLS certificate-chain and hostname
  validation are enabled using the OpenWrt CA store. The profile option
  `AllowInsecure` must explicitly map to `VERIFY_TLS=0`; TLS encryption remains
  enabled, but certificate identity validation is skipped.
- `HOSTKEY` optionally pins the SSH host-key fingerprint. Without a pin, the
  fingerprint is informational; server rotation is not blocked by a known_hosts
  database.
- `MAX_CLIENTS` defaults to 64 and is capped at 256.
- `IDLE_TIMEOUT` defaults to 600 seconds; set it to 0 to disable idle expiry.
  Idle relay expiry is silent in normal logs; it still closes expired channels.
- Per-channel backpressure/window-transition diagnostics are disabled by default
  to keep normal logs quiet. Set `LOG_BACKPRESSURE=1` in the environment file,
  or pass `-log-backpressure 1`, only when troubleshooting flow control. The
  CI integration test enables this flag explicitly; it does not affect buffering
  or retry behavior.

## TLS upstream resilience (R15)

The TLS transport retries a stalled or disconnected handshake on another
DNS-resolved upstream address, excluding endpoints that already failed. The
retry is bounded to four endpoints and applies only to transport-level
failures/timeouts; certificate validation and TLS protocol/configuration
failures remain fatal. The TCP racer also clears errno when a candidate wins,
so a refused earlier candidate cannot leak an error into the TLS layer. DNS
resolution and the operating-system routing table remain dynamic, so the
core does not bind to a fixed WAN interface.

OpenSSL non-blocking I/O clears the thread error queue before each
`SSL_connect()`, `SSL_read()`, `SSL_write()`, and shutdown I/O so
`SSL_get_error()` can classify retry readiness consistently. OpenSSL unexpected EOF during handshake
is treated as a transport failure eligible for alternate-address retry. The
TLS message-logging callback also restores `errno` before returning,
preventing stdio/file logging from contaminating OpenSSL's error
classification.

## TLS diagnostics (R17)

TLS handshake message tracing is disabled by default to avoid synchronous
file logging inside OpenSSL callbacks. Enable it only for diagnosis with
`TLS_DIAG=1` in the env file or `-tls-diag 1` on the core command line.
The default connection path still reports handshake failures and alternate
endpoint retries without message-by-message callback logging.

## SSH/TLS terminal-state handling (R18)

A serialized `PENDING_KEEPALIVE` remains active only while libssh2 returns
`LIBSSH2_ERROR_EAGAIN`. A terminal transport/session result clears the
pending marker before the main loop enters shutdown. TLS socket callbacks
likewise retain `WANT_READ/WANT_WRITE` readiness only while OpenSSL explicitly
requests a retry; a terminal result such as peer `close_notify` clears stale
readiness, so shutdown does not mistake a completed operation for an active
writable retry and skip bounded SSH/TLS cleanup.

## R18 parser verification

The parser stage passes new state-transition regressions proving that a
pending keepalive is retained on EAGAIN and cleared on terminal error/success,
and that terminal TLS callback results clear stale WANT_WRITE readiness while
WANT_READ/WANT_WRITE still request the correct retry. The full existing parser,
SOCKS, TCP dial, TLS retry, ring-buffer, half-close, pending-cleanup, and core
state regression suite also passes. The next stages build this R18 source with
the OpenWrt 25.12.5 x86_64 SDK and run the resulting APK in QEMU.
 
The native state regression suite now covers scoped receive-terminal flushing,
the distinction between TLS `close_notify` and unexpected EOF, and all
three drain outcomes. The MIPS SDK stage runs that suite before compiling the
r22 `mipsel_24kc` IPK.

## Classified upstream drain (R22)

Relay channel reads temporarily translate a confirmed upstream receive terminal
into `-EAGAIN` while inside `libssh2_channel_read()` only, allowing
libssh2 to copy complete channel packets already present in its session queue
into the local S2C ring. This does not bypass a failed `CHANNEL_WINDOW_ADJUST`:
that transmit operation precedes libssh2's packet scan, so an affected channel
is reported as stalled and causes a forced teardown once local output buffers
are empty.

An upstream shutdown is now classified as waiting, graceful, or forced. A
graceful result requires a clean receive EOF, SSH EOF on every live relay
channel, zero queued channel bytes from `libssh2_channel_window_read_ex()`,
and empty local S2C/control buffers. Unexpected TLS EOF without `close_notify`
is an error, not a clean EOF. If all live channels are drained or stalled but
the transport or any channel is incomplete, the core logs RX/TX terminal
status, stalled/incomplete channel counts, and queued libssh2 bytes before
restarting without waiting for the 15-second drain timeout.
Queued SOCKS rejection/control replies are also allowed to flush before the
 drain is classified, including replies for clients that never reached relay
 state.
A live relay entry with a missing libssh2 channel is treated as incomplete
 and forced, rather than being left in the drain wait state.

## Upstream EOF and half-close drain (R21)

The upstream receive callback now reports a real EOF as zero and preserves
terminal socket errors across retries, preventing a closed-but-readable socket
from being mistaken for EAGAIN. An upstream RDHUP is treated as a half-close:
EPOLLIN remains available until the receive side confirms EOF, and 25 ms polling
is reserved for a pending libssh2 operation after the upstream descriptor has
been detached. During drain, pre-relay SOCKS clients receive a protocol-appropriate
failure, active PENDING_OPEN calls are allowed to resolve, and pinned C2S write
buffers are not discarded. A stalled S2C channel remains incomplete until the
bounded drain deadline rather than risking loss of packets still queued inside
libssh2.

The OpenWrt 24.10.7 mipsel_24kc workflow builds package r29 and performs
cross-architecture ELF/package checks before its separate QEMU integration run.


## Four-vCPU performance investigation (experimental)

The experimental branch `perf/4core-ssh-relay-benchmark` runs the existing OpenWrt 25.12.5 QEMU integration and sustained concurrent-transfer workload with a four-vCPU guest (`qemu -smp 4`) on the GitHub-hosted Ubuntu runner. The workflow records the host CPU topology as an artifact. This validates behavior under a four-core guest and provides a repeatable baseline; it does not by itself make the current single-threaded SSH event loop parallel. The current core shares one libssh2 session and TLS transport, so channel operations must remain serialized. The planned single-session pipeline moves TLS and local socket I/O off-thread while keeping libssh2 session operations serialized.

## Continuous integration tests

Pushes to `main` that change `ssh-core.c`, the package `Makefile`, tests, or this
workflow automatically run the full pipeline in order:

1. **Parser regression** — compile and run `tests/http_parser_test.c` on Debian.
2. **OpenWrt SDK build** — build the package using the official OpenWrt 25.12.5
   x86_64 SDK, including the OpenWrt OpenSSL/zlib sources and packages-feed
   libssh2. The APK is uploaded as an artifact in the same workflow run.
3. **QEMU VM integration tests** — install that APK in the official OpenWrt
   25.12.5 x86_64 guest, then exercise SSH authentication, SOCKS bind safety,
   strict numeric parsing, and concurrent direct-tcpip transfers over one
   upstream SSH session.
4. **Backpressure and recovery** — force a 32 MiB C2S upload through a stalled,
   small-window receiver; run four simultaneous 8 MiB uploads; then throttle
   the S2C reader during a 32 MiB download. Both directions verify exact
   lengths and SHA-256. The C2S ring remains 32 KiB; the S2C ring is 128 KiB
   to absorb downstream send jitter. Tests assert that both stay within their
   configured capacity and drain to zero after the receiver resumes. With the
   default 64 relay clients, ring storage alone can reach 10 MiB at peak.
5. **TCP half-close and sustained stress** — use a statically linked client
   cross-compiled by the OpenWrt SDK to test client-FIN-first and server-FIN-first
   sequences. The host fixture independently verifies that each FIN arrives
   and that the opposite write direction remains usable. Then run four
   concurrent SOCKS client threads through the same single SSH session, verify
   every response by SHA-256, and monitor peak RSS and FD counts.
6. **Disconnect and repeated-connection checks** — abort an in-flight client
   request, verify that the service remains usable, then open and close 12
   more SOCKS connections while checking process RSS and file-descriptor
   counts for material growth.

The workflow is a single sequential job for push-triggered runs: SDK build
must finish successfully before the VM stage downloads and installs its APK.
The guest test script is syntax-checked before the VM boots, the host HTTP
fixture is Python-compiled before it starts, and the statically linked
half-close test client is cross-compiled with the OpenWrt SDK and checksum-
verified as part of the SDK artifact. The job has a 60-minute hard
timeout; individual transfers also have explicit curl timeouts.

For diagnosis, the workflow still exposes a manual `workflow_dispatch` route
for running one isolated stage (`parser`, `sdk`, or `vm`). The manual VM
stage requires the run ID of a successful SDK-stage artifact from the same
repository. A green workflow result means all stages and all guest assertions
completed successfully; a timeout or skipped test is not considered a pass.
The current VM run validates the x86_64 OpenWrt 25.12.5 target only; it does
not replace a runtime test on the actual physical router or another target.


## Opt-in runtime performance counters (R23)

The core accepts `-log-perf 1` or `LOG_PERF=1` in the environment file. The
default is disabled. When enabled, it writes one `[PERF]` line per elapsed
second to the normal core log; when disabled, no periodic performance log is
written and the relay behavior is unchanged.

The line reports active SOCKS clients and relay channels, `ep_calls`,
`ep_wait_ms`, maximum epoll wait, wakeups/timeouts, TLS receive bytes and
EAGAINs, SSH bytes delivered to libssh2, S2C channel-read bytes and EAGAINs,
bytes sent from S2C rings to local SOCKS clients, SOCKS send EAGAINs, S2C
full-buffer events, libssh2 EAGAIN returns, and serialized pending-operation
blocks. `span_ms - ep_wait_ms` approximates time outside `epoll_wait()` for
that reporting interval; it is not a CPU-time measurement. TLS RX counts
OpenSSL bytes returned from the upstream receive callback, while S2C reads and
SOCKS TX are separate downstream stages.

The companion `diag-download.sh` script supplied with this change records
per-second process/thread CPU, interface throughput, per-socket TCP states
and queues matched by process FD inode, and system TCP/softnet deltas.
The optional `ss -tinp` snapshot records per-upstream-socket TCP_INFO details
such as RTT, congestion window and retransmissions. On OpenWrt 24.10, install
the `ss` utility with `opkg update && opkg install ip-full`. Without `ss`,
socket states and queues are still collected from `/proc/net/tcp*`; TCP_INFO
is reported unavailable.


The R23 `mipsel_24kc` package has passed the native regression stage and
the OpenWrt 24.10.7 cross-build. The separate MT7621 QEMU integration job
installs that exact SDK artifact and exercises SOCKS forwarding, SSH channel
I/O, half-close and reconnect behavior.


## Historical independent-session worker mode (R24–R27)

The R24–R27 experimental implementation created one upstream transport and
one SSH authentication per worker. That could multiply logins when CPU
auto-detection or WORKERS selected more than one worker. It is no longer the
active policy: R28 and later enforce one upstream SSH session per process,
and legacy WORKERS/-workers values are ignored for session creation. The
planned replacement is a single-session pipeline with separate TLS and local
I/O ownership; libssh2 session operations remain serialized by one SSH Owner.

## R25: MIPS TLS cipher preference and diagnostics

The `mipsel_24kc` package build prefers the TLS 1.3 suite
`TLS_CHACHA20_POLY1305_SHA256`, followed by
`TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`. This policy is
compiled only when the OpenWrt package architecture resolves to
`mipsel_24kc`; x86_64 and other targets retain OpenSSL's default policy.
The AES suites remain available as fallbacks. This affects the outer TLS
connection only; the SSH cipher negotiated inside the tunnel is independent.

When `LOG_PERF=1`, the interval counters now include S2C ring occupancy
(sum, maximum and nonempty-client count), the number of S2C clients with
`EPOLLOUT` armed, eligible S2C clients missing `EPOLLOUT`, partial SOCKS
sends, and epoll ADD/MOD failures. These values distinguish a genuinely
full local ring from aggregate TLS/SSH byte-counter differences. A nonzero
`s2c_epollout_missing` or epoll-control failure is a diagnostic signal,
not by itself proof of the root cause.

Authentication failure logs now include the server-advertised methods,
libssh2 return/error codes, and username/password byte lengths. Secret values
are always redacted. Username and password values exceeding the configured
buffer sizes are rejected instead of being silently truncated. If a session
worked and an immediate reconnect is rejected by every worker, compare the
redacted lengths and server methods across attempts; also inspect server-side
account/session limits and whether the previous SSH sessions have expired.
The core does not automatically retry an explicit authentication rejection,
to avoid repeatedly submitting credentials to a server that may be rate
limiting or temporarily locking the account.

The QEMU test uses a TLS test server restricted to ChaCha20-Poly1305 and
requires the MIPS client to negotiate that exact TLS 1.3 suite. QEMU results
remain an integration check; final throughput and stability decisions require
testing on the physical MT7621 router.

## R26: C2S diagnostics after remote SSH EOF

The `[PERF]` interval now reports the C2S bytes received from local SOCKS
clients and bytes accepted by `libssh2_channel_write()`, including separate
totals for data arriving/written after the remote SSH channel EOF. It also
reports C2S buffer occupancy, channels waiting on a zero write window,
channels that have seen remote EOF, and upstream input events/window-waiter
retries. These counters are intended to distinguish local socket ingestion,
libssh2 write progress, and remote WINDOW_ADJUST wakeups.

With `LOG_BACKPRESSURE=1`, the core reports remote EOF while explicitly
keeping the local C2S half open, incoming C2S data after that EOF, successful
C2S writes after EOF, and zero-window waits after EOF. These messages do not
include payload bytes or secrets. A zero-window wait is not by itself a bug:
it is expected under backpressure while the destination is not reading.
A wait that is never followed by an input wakeup or write recovery is the
condition this instrumentation is designed to expose.

