# Passwall SSH Core changelog

## Unreleased

- Correct the offline MT7621 VM dependency assertion to use the actual OpenWrt 24.10.7 runtime package names `libopenssl3` and `libssh2-1` (confirmed in the ImageBuilder install log). The previous assertion used build/dependency aliases and failed despite both runtime libraries being installed. The MIPS SPSC stress binary had already passed in that run.
- The first MT7621 QEMU attempt booted successfully but could not run package/SPSC checks because guest `opkg update` was blocked by the isolated VM network. The VM harness now preinstalls `libopenssl` and `libssh2` into the ImageBuilder firmware, installs the local IPK offline, normalizes the staged SPSC binary mode before copying it out of `/tmp`, and checks startup CPU diagnostics in stderr capture.
- Native SPSC stress tests pass on the GitHub runner; the OpenWrt 24.10.7 SDK cross-compiled the standalone static MIPS32 Release 2 SPSC test binary and built the r29 IPK (SDK run 44866732425). MT7621 QEMU execution remains the next validation step.
- Add a standalone SPSC byte-ring primitive for the planned single-session I/O pipeline. Use monotonically increasing uint32_t head/tail counters, power-of-two capacity <= 2^30, acquire/release publication, no shared used field, and 64-byte separation between producer and consumer indices.
- Add native tests for capacity validation, full/empty and physical wrap behavior, pinned read-span stability during producer appends, irregular chunk sizes, byte integrity, and uint32_t counter rollover.
- Cross-compile the SPSC test with the OpenWrt 24.10.7 mipsel_24kc SDK and execute the static binary in the MT7621 QEMU guest.
- Correct package metadata to describe the active one-session SSH relay rather than the historical independent-session worker implementation.
- Enforce exactly one upstream SSH session and one authentication per process (R28); legacy WORKERS/-workers values remain accepted only for launcher compatibility.
- Bump the OpenWrt package release to r29.

- Select the default pthread worker count automatically from CPUs available to the process: respect Linux CPU affinity when available, fall back to the online CPU count, and cap the pool at four workers. Keep explicit `WORKERS=1..4` and `-workers 1..4` overrides; add synthetic 1/2/3/4/8/16-CPU regression coverage and a guest test of the automatic default.
- Bump the OpenWrt package release to r27.
- Extend `[PERF]` with C2S bytes received from local clients, bytes accepted by libssh2, C2S occupancy, remote-EOF relay counts, zero-window waits after remote EOF, and WINDOW_ADJUST/input wakeup counts.
- Add opt-in `[LOG_BACKPRESSURE]` diagnostics for C2S data arriving after remote SSH EOF, writes progressing after EOF, and window-zero waits while the opposite direction remains open. This specifically traces full-duplex/half-close behavior without logging payload contents.
- Bump the OpenWrt package release to r26 for the additional C2S/SSH-window observability.


- Add a TLS 1.3 cipher preference scoped exclusively to the OpenWrt `mipsel_24kc` package build: prefer `TLS_CHACHA20_POLY1305_SHA256`, while retaining AES-256-GCM and AES-128-GCM fallbacks. This changes the outer TLS transport only; SSH transport cipher negotiation remains independent.
- Extend `[PERF]` with actual S2C ring occupancy (sum/max/nonempty clients), EPOLLOUT armed/missing counts, partial SOCKS sends, and epoll ADD/MOD failure counts plus the last errno.
- Add redacted `[AUTH-DIAG]` records for credential byte lengths, server-advertised authentication methods, method return codes, and final libssh2 error code. Password values are never logged. Reject overlong username/password values rather than silently truncating them.
- Add an MT7621 QEMU assertion that forces the test TLS server to offer only ChaCha20-Poly1305 and verifies the negotiated TLS 1.3 suite.
- Bump the OpenWrt package release to r25.


- Add opt-in in-process pthread workers (R24, 1–4 workers). Each worker owns an independent upstream transport, TLS state, `LIBSSH2_SESSION`, epoll loop, pending-operation state, client list, and relay buffers; a single process runs all workers.
- Bind worker SOCKS listeners in one `SO_REUSEPORT` group. Preserve the process-wide `MAX_CLIENTS` cap with atomic admission accounting, serialize shared payload-rotation and marker-file writes, and coordinate shutdown with a shared atomic stop flag.
- Initialize libssh2 once before worker creation and call `libssh2_exit()` only after worker joins. Add worker identity/accepted-client diagnostics and OpenWrt 24 MIPS VM tests for one-PID thread counts plus TCP and TLS/SNI downloads.
- Bump the OpenWrt package release to r24.


- Scope a terminal-RX-as-EAGAIN shim to relay channel reads only, so libssh2
  can consume complete channel packets already queued in the session before
  reporting the saved transport terminal result to other API calls.
- Do not treat the shim as a workaround for a failed CHANNEL_WINDOW_ADJUST:
  that send happens before libssh2 reads or scans queued packets, so that
  channel remains stalled and is explicitly reported during forced teardown.
- Classify upstream shutdown as WAIT, graceful, or forced. Graceful completion
  now requires clean RX EOF, SSH EOF on every live relay channel, empty
  libssh2 channel queues, and empty local S2C/control buffers. Once every live
  channel is drained or stalled, unrecoverable transport states restart
  immediately with terminal status and queued-byte diagnostics instead of
  waiting out the full 15-second drain deadline.
- Treat OpenSSL unexpected EOF without close_notify as a transport error on
  both OpenSSL 1.1.x and 3.x; only SSL_ERROR_ZERO_RETURN is a clean TLS EOF.
- Use next-node traversal when rejecting non-relay clients during upstream HUP.
- Bump the OpenWrt package release to r22.

- Report upstream receive EOF as 0 and replay a stable negative errno for terminal
  receive errors. Do not turn a closed socket into EAGAIN, which could spin
  libssh2 handshake/auth retries on a permanently readable EOF.
- Treat upstream EPOLLRDHUP as a half-close: remove repeated RDHUP readiness but
  retain EPOLLIN until recv/SSL_read confirms the receive terminal. Use short
  25 ms retries only for a pending libssh2 operation after the upstream fd has
  been detached; otherwise wait for client EPOLLOUT or the drain deadline.
- Reject SOCKS greeting/request/opening clients that cannot be served after
  upstream HUP, while allowing an already-pending PENDING_OPEN to resolve.
- Guard C2S ring cleanup so a buffer pinned by an active libssh2 write is never
  cleared during upstream drain.
- Keep the stalled S2C drain fail-safe: a failed WINDOW_ADJUST send is not proof
  that libssh2's queued channel packets were drained.
- Bump the OpenWrt package release to r21.

- Remove the redundant per-client S2C `read_pending` flag; retain only the
  serialized libssh2 `PENDING_READ` operation and never synthesize EAGAIN when
  the writable S2C ring slice is unavailable.
- Track OpenSSL WANT direction and origin per libssh2 API invocation, including
  `SSL_write` WANT_READ and `SSL_read` WANT_WRITE, and prevent keepalive or
  shutdown I/O from interleaving with a pinned TLS operation.
- Replace immediate upstream-HUP restart with a bounded drain phase: detach
  the upstream fd from epoll, continue pumping channels fairly, and restart only
  after all live relay channels and S2C queues drain or the 15-second deadline
  expires.
- If upstream TX terminates before a channel can send `CHANNEL_WINDOW_ADJUST`,
  mark that channel's receive drain as stalled and wait for the bounded deadline
  rather than falsely claiming its libssh2 receive queue is empty.
- Add regressions for per-call TLS WANT lifetime, upstream EOF, and two-channel
  S2C drain completion.
- Bump the OpenWrt package release to r20.


- Remove unnecessary pointer pinning for nonblocking S2C `libssh2_channel_read()` retries.
  Recompute the writable ring slice on every attempt and allow the local client
  to reset the ring after draining it. Preserve exact buffer pinning for
  C2S `libssh2_channel_write()` retries, where it is required across EAGAIN.
- Increase the per-relay S2C ring from 32 KiB to 128 KiB while keeping C2S at
  32 KiB. The buffers remain lazily allocated per relay; at the default
  64-client limit, combined ring storage is capped at 10 MiB.
- Detect buffered TLS records with `SSL_has_pending()` after successful TLS I/O,
  but only when no SSL callback is waiting for WANT_READ/WANT_WRITE. This avoids
  losing already-buffered TLS records without busy-looping on partial records.
  Add retry-gate regression coverage.
- Bump the OpenWrt package release to r19.

- Keep the configured idle-relay timeout and channel cleanup unchanged, but
  suppress the repetitive per-relay `Menutup relay idle ...` log message.
  This keeps routine logs quiet without disabling expiration.
- Clear the serialized `PENDING_KEEPALIVE` state after any terminal libssh2
  result. Only `LIBSSH2_ERROR_EAGAIN` retains it for retry; a fatal transport
  result now releases the pending slot so shutdown does not mistake a dead
  keepalive for active libssh2 work and skip bounded SSH/TLS cleanup. Add a
  regression for EAGAIN, terminal socket error, and success transitions.
- Clear stale TLS `WANT_READ/WANT_WRITE` readiness when an SSL callback
  returns a terminal result. Preserve readiness only while OpenSSL explicitly
  requests a retry; a received `close_notify` must not leave a stale
  `EPOLLOUT` flag that makes shutdown incorrectly skip bounded cleanup.
  Add regression coverage for both retry and terminal callback outcomes.
- Bump the OpenWrt package release to r18.


- Strengthen the callback errno regression by forcing the logger's
  fopen() to fail with ENOTDIR, proving the callback restores errno rather
  than passing only because successful stdout logging left it unchanged.
- Apply the same clean OpenSSL error-queue and errno preparation to the
  TLS close_notify read and SSL_shutdown() path, not just connection/data I/O.
- Clear errno on successful TCP dial returns as well as before SSL I/O.
  The happy-eyeballs dialer may have observed a refused earlier candidate
  before a later candidate wins; that stale errno must not escape the dialer.
  Add a regression for refused-first/successful-second candidate selection.
- Add a silent-peer handshake timeout regression to verify the timeout path
  is classified as retryable and therefore eligible for an alternate endpoint.
- Disable the synchronous TLS message callback by default. Enable it
  only with `TLS_DIAG=1` in the env file (or `-tls-diag 1`), so normal
  handshakes are not affected by per-message file logging; keep the callback's
  errno-preservation regression for diagnostic mode.
- Bump the OpenWrt package release to r17.

- Treat OpenSSL's TLS 1.3 `unexpected eof while reading` reason as a
  retryable transport failure, alongside syscall EOF and handshake timeout.
  Add a socketpair regression where the peer closes without close_notify.
- Preserve errno across the TLS diagnostic message callback. The callback
  executes inside SSL I/O and its logger uses stdio/file operations; without
  restoration, that logging could corrupt the errno inspected by SSL_get_error().
  Add a regression that checks the callback leaves errno unchanged.
- Bump the OpenWrt package release to r16.


- Retry a failed or stalled TLS transport on other DNS-resolved upstream
  addresses. R13 selected the first TCP-connected CloudFront edge and did not
  try another address if that endpoint then stalled during TLS. The retry
  excludes the failed endpoint and preserves the system resolver and kernel
  routing behavior; certificate/protocol errors remain non-retryable.
- Clear the OpenSSL error queue and errno before SSL_connect/SSL_read/SSL_write
  so SSL_get_error() classifies nonblocking results reliably. Distinguish
  read-side POLLHUP/EOF from write readiness and propagate socket SO_ERROR.
- Add regressions for failed-endpoint exclusion and poll HUP/EOF handling.
- Bump the OpenWrt package release to r15.


- Add temporary OpenSSL TLS handshake diagnostics for the physical-router
  failure: report OpenSSL version, nonblocking socket state, SNI/ALPN, sent
  and received handshake messages, TLS alerts, SSL_connect state transitions,
  poll readiness direction, timeout elapsed time, and socket SO_ERROR. Check
  SSL_set_fd() and ALPN setup failures explicitly. This is diagnostic-only;
  it does not change SNI, payload, routing, DNS, or TLS policy.
- Bump the OpenWrt package release to r14 for the diagnostic build.

- Resolve upstream DNS by querying IPv4 (A) and IPv6 (AAAA) independently,
  so a broken AAAA response on musl cannot discard a usable A result. Race
  returned addresses within each family instead of serially aborting each
  candidate after 1.2 seconds; allow a four-second family connect window and
  fall back to IPv6 when IPv4 resolution or connection attempts fail.
- Add temporary TCP dial diagnostics for resolver family, DNS latency,
  candidate addresses, connect errno, selected remote endpoint, and local
  socket address. Add regressions proving IPv4 succeeds without an AAAA lookup
  and IPv6 fallback is attempted after an IPv4 lookup miss.
- Bump the OpenWrt package release to r13 for the upstream DNS/connect fix.


- Preserve compatibility with OpenWrt 24.10's libssh2 1.11.0 callback API while using the typed `libssh2_session_callback_set2()` API on libssh2 1.11.1 and newer. This keeps the custom SSH socket callbacks enabled across both supported SDK generations.

- Add a full-duplex transport regression on both TCP and TLS: the SOCKS
  client sends an exact 8 MiB C2S upload and half-closes its write side while
  the remote HTTP fixture concurrently streams a 32 MiB S2C response. The
  client deliberately pauses response reads to fill the 32 KiB S2C ring,
  then verifies the complete response length and SHA-256 after resuming.
  The host fixture independently verifies the complete upload hash and FIN.
- Add an explicit zero-linger RST test against an idle channel after it has
  received response headers and reached the read-EAGAIN wait. Repeat 33 resets
  on TCP (one more than `MAX_CLIENTS=32`) to detect leaked client slots, and
  exercise a reset on TLS while another S2C slow-reader channel remains active;
  verify daemon liveness and bounded RSS/file-descriptor growth.
- Keep the three-second `IDLE_TIMEOUT` isolation test on its dedicated
  TCP daemon so it cannot expire the TLS half-close fixture during its
  intentional eight-second remote-read pause. Verify `KEEPALIVE=10` produces
  repeated idle TLS keepalives and require a clean SIGTERM exit without
  skipped SSH cleanup or an incomplete TLS close_notify exchange.
- Extend the four-worker VM stress period from 90 seconds to 30 minutes.
  Update the QEMU expect and Actions job timeouts to accommodate the run.
- Strengthen the HTTP 200 follow-up regression so trailing non-HTTP data
  must leave the tunnel unestablished and classify as
  `HTTP/Proxy Rejected (200)`, alongside malformed chunk-size and
  over-limit chunked-body rejection tests.


- Extend the SOCKS half-close helper with an explicit zero-linger client RST
  against an idle response channel after it has received headers and entered
  the read-EAGAIN wait. Exercise the reset on TCP and TLS, including while a
  separate TLS slow-reader S2C channel remains active, and verify daemon
  liveness plus bounded RSS/file-descriptor growth.
- Make the TLS VM daemon use `IDLE_TIMEOUT=3` so the idle second channel must
  expire independently while the 32 MiB TLS slow-reader transfer completes.
- Verify `SIGTERM` on an idle TLS session returns successfully and does not
  skip SSH disconnect/session cleanup due only to a stale inbound WANT_READ.
- Extend the four-worker OpenWrt VM stress duration from 90 seconds to
  30 minutes and increase the expect timeout to accommodate the longer run.
- Strengthen HTTP 200 follow-up parser regressions: after a zero-length 200
  response followed by non-HTTP data, assert the tunnel remains unestablished
  and the rejection classifier reports HTTP/Proxy Rejected (200).


- Distinguish an idle TLS `SSL_read()` WANT_READ from a live serialized TLS
  operation. Stale inbound-only readiness no longer permanently suppresses
  SSH keepalive, forces upstream EPOLLIN through S2C backpressure pauses, or
  causes graceful SSH/TLS cleanup to be skipped at shutdown. WANT_WRITE and
  WANT_READ belonging to a pending serialized libssh2 operation remain armed.
- Add native regressions for idle TLS WANT_READ, keepalive eligibility,
  shutdown gating, pending SSL-write WANT_READ retries, writable TLS retries,
  and EPOLLIN pause/re-arm behavior. Log successful SSH keepalives only when
  `LOG_BACKPRESSURE=1`, allowing the manual TLS idle test to verify activity
  without adding periodic keepalive messages to normal production logs.
- Add the TLS readiness helper's forward declaration before the early delay
  helper, avoiding an implicit function declaration under the OpenWrt GCC
  toolchain; retain the parenthesized call in the delay poller.
- Extend the manual OpenWrt VM TLS test with idle keepalive verification and a
  two-channel case: saturate one TLS S2C channel with a rate-limited reader,
  close a second idle channel, then verify the slow transfer's exact length
  and SHA-256 and confirm its S2C buffer drains.
- Bump the OpenWrt package release to r11.


- Allow channel cleanup after inbound-only channel-read EAGAIN and zero-window
  write waits. Retain buffers for active channel writes even when a TLS callback
  reports WANT_READ, and serialize pending send-EOF operations before retry.
- Close reset-client channels immediately, discarding queued C2S data that
  no live local peer can consume; do not wait for inbound-only EAGAIN or remote
  EOF that may never arrive.
- Keep aborted channel-open attempts, including globally pending OPEN
  retries, under the existing 30-second hard-open timeout instead of the
  shorter 10-second cleanup deadline. Clear any stale OPEN deadline when the
  open resolves and begin a fresh close budget.
- Remove the passive SSL_peek EOF probe from the shared TLS transport.
  Nonblocking WANT_READ/WANT_WRITE belongs to the active TLS read operation;
  SSH channel callbacks now own upstream consumption, while epoll HUP/RDHUP
  drives transport-loss handling after buffered receive progress is drained.
- Track upstream receive-sequence changes across every relay-pump return path
  so reads performed inside channel writes are visible to EOF/idle handling.
- Classify rejected non-tunnel HTTP 200 and invalid 101 responses as proxy
  failures rather than SSH KEX failures.
- Add regressions for inbound-only read and zero-window cleanup, active
  write-buffer retention under WANT_READ, globally pending write serialization,
  reset-client disposal, pending-OPEN and channel-close deadlines, upstream
  receive-sequence tracking, HUP drain handling, and HTTP rejection classification.
- Extend the manual OpenWrt VM suite with an isolated `IDLE_TIMEOUT=3` daemon:
  hold one SOCKS channel idle while a second channel streams 6 MiB
  over 24 seconds, then verify only the idle channel closes, the active
  transfer hash remains exact, and the daemon accepts a subsequent request.
- Add a host-side TLS-to-SSH relay and run the half-close helper over
  `TRANSPORT=TLS`, including an 8 MiB upload after the remote TCP write side
  has sent FIN; verify the TLS daemon remains usable for a new SOCKS channel.
  Host-side assertions require two exact 8 MiB upload receipts and both FIN
  directions, covering the TCP and TLS runs independently.
- Allow the cross-compiled half-close helper to select a SOCKS listener port
  so TCP and TLS transport integration tests can run in separate daemons.
- Bump the OpenWrt package release to r10.


- Treat HUP/RDHUP as drain hints rather than EOF: EAGAIN keeps the drain
  pending, and only recv()==0 confirms the client's write-side EOF.
- Validate ring-buffer state and commit lengths/contiguous slices. Replace
  retained libssh2 buffer pointers with ring offsets and generation checks.
- Defer client unlink/free to the channel pump, avoiding destruction from
  start_closing_client() while callers may still hold a client pointer.
- Retry channel_free() on EAGAIN in the pump; final teardown delegates remaining
  channels to session cleanup instead of ignoring a one-shot channel_free().
- Interleave IPv4/IPv6 candidates with a 1.2-second per-address budget under one
  10-second total dial deadline.
- Add bracketed IPv6 SOCKS listener support, for example [::1]:1080, while
  retaining the IPv4 loopback default and remote-bind safety guard.
- Use the destination host rather than the proxy as default TLS SNI and
  hostname-verification identity. Reject ambiguous unframed non-CONNECT HTTP
  200 unless HTTP_200_TUNNEL is explicitly enabled.
- Apply the deferred-cleanup deadline to aborted SSH channel-open operations
  as well as pending relay I/O and ST_CLOSING channel_free retries.
- Add a hard deadline for deferred channel cleanup; if it expires, stop the
  process without issuing another libssh2 API call while an operation is pending.
- Preserve pinned buffers for real channel read/write EAGAIN; use a validated,
  generation-changing ring clear only for a write blocked before packet creation
  by a zero remote window.
- Use one absolute 2.5-second deadline for SSH disconnect, session free, and
  TLS shutdown rather than resetting the budget at each phase.
- Complete nonblocking TLS shutdown without calling SSL_get_error() on the
  special zero return from SSL_shutdown(); drain with SSL_read() until the
  peer close_notify or deadline, and retry WANT_READ/WANT_WRITE correctly.
- Let shutdown polling retry reads when POLLIN is reported together with HUP,
  so buffered close_notify data is not discarded by the poller.
- Retry TLS close_notify on WANT_READ/WANT_WRITE with a deadline, using a
  shutdown poller that remains active after g_stop; skip TLS I/O if SSH teardown
  is incomplete or any libssh2 operation is still pending.
- Skip libssh2 API cleanup entirely on startup failure, avoiding a switch to
  session_free when handshake or authentication may still be pending.
- Add native regressions for ring clear, cleanup deadlines, shutdown pending
  detection, and shutdown polling after g_stop, including the distinction
  between window wait and active write.
- Add regressions for ring invariants, HUP/RDHUP EAGAIN, deferred cleanup, IPv6
  listener parsing, strict HTTP status lines, and unframed HTTP 200 responses.
- Bump the OpenWrt package release to r9.


- Reject unexpected non-HTTP bytes after a non-CONNECT HTTP 1xx/2xx response so
  a completed HTTP 200 response cannot silently become an SSH tunnel when
  HTTP_200_TUNNEL=0.
- Parse chunk-size fields strictly and cap the aggregate chunked response body
  at the same 16 MiB limit used for Content-Length bodies.
- Validate the SOCKS5 request RSV byte and reject truncated or embedded-NUL
  domain names only after the complete SOCKS5 request frame has arrived.
- Enable IPv6 destination dialing for SOCKS5 IPv6 requests while preferring
  IPv4 and bounding the total address-attempt period to 10 seconds.
- Default TLS certificate and hostname verification to enabled
  (VERIFY_TLS=1); profiles must explicitly opt into AllowInsecure.
- Add native regressions for HTTP response sequencing, fragmented Content-Length
  and chunked bodies across EAGAIN, strict chunk framing, cumulative chunk limits,
  SOCKS request validation, and IPv6 dialing.
- Use a connect-specific poller that rejects POLLERR/POLLHUP as connection
  completion, closes failed descriptors on every path, and shares one 10-second
  deadline across IPv4-first and IPv6 fallback attempts.
- Bump the OpenWrt package release to r8.


- Retry TLS EOF peeks on the readiness event requested by OpenSSL, without interleaving another libssh2 operation while the peek is pending; this prevents a writable-socket spin on `SSL_ERROR_WANT_WRITE`.
- Suppress repeated idle-timeout handling while a relay is already marked `abort_on_pending` and waiting for a libssh2 operation to unwind.
- Keep `DELAY` waits alive across the 60-second poll slices until the configured deadline expires.
- Add native regressions for TLS peek readiness, pending-abort idle timeout, and delay deadlines spanning multiple poll slices.
- Bump the OpenWrt package release to r7.


- Fix C2S half-close stalls when an SSH channel write window reaches zero. Keep upstream reads armed while a channel is waiting for `WINDOW_ADJUST`, retry the pinned write when upstream data becomes readable (including already-decrypted TLS data), and preserve the window-wait state when resuming a pending write.
- Bump the OpenWrt package release to r6.


- Align the package payload, service executable name, and VM checks on `/usr/bin/passwall-ssh-core`; fresh installs and upgrades no longer require a manual rename. Bump the OpenWrt package release to r5.


- Gate verbose per-channel C2S/S2C backpressure, SSH window EAGAIN/recovery, and ring-buffer close diagnostics behind `LOG_BACKPRESSURE=1`; default production logs no longer emit these high-frequency test diagnostics. Preserve the diagnostic path for CI and opt-in troubleshooting.
- Bump OpenWrt package release to r4.


- Increase the S2C slow-reader regression from 8 MiB to 32 MiB, with a 128 KiB/s receiver, a 420-second transfer bound, and exact byte-count/SHA-256 verification.
- Add a target-ABI static half-close test client cross-compiled by the OpenWrt 25.12.5 SDK. Exercise client-FIN-first while reading the server response, and server-FIN-first while continuing to send to the server; verify both FIN directions independently in the host fixture.
- Add a 90-second stress run with four concurrent SOCKS workers. Verify each 1 MiB response by length and SHA-256, and sample peak process RSS/file-descriptor usage.
- Include the half-close helper and its SHA-256 manifest in the SDK artifact, and verify the helper source matches the VM run's source commit.
- Add OpenWrt 25.12.5 x86_64 SDK package integration using the official 25.12 OpenWrt package makefiles and packages feed.
- Use the repository's real OpenWrt package Makefile for SDK packaging; verify the source file is copied and the target binary is produced. Compile with TARGET_CPPFLAGS and GNU11.
- Tighten HTTP status-line parsing to accept only valid HTTP/1.0 and HTTP/1.1 response versions.
- Fix the malformed-version regression fixture to use actual CRLF delimiters; close the peer for deterministic parser rejection.
- Add HTTP response parser regression coverage for malformed versions, CONNECT, Content-Length, chunked, close-delimited, and explicitly enabled legacy HTTP 200 tunnel responses.
- Split CI into manually selected parser, SDK, and QEMU VM stages. The VM stage downloads the APK from a prior SDK run and verifies both source commit and APK checksum.
- Mirror the manual dispatcher to the repository default branch so GitHub exposes the workflow UI; dispatch it against the `passwall-ssh-core` branch.
- Build and VM test results are not claimed until their respective manual stages complete successfully.
- Fix the QEMU VM host SSH fixture startup by creating `/run/sshd` with root ownership and mode `0755` before launching OpenSSH; the previous VM failure was caused by sshd refusing to start because this directory was absent.
- Fix SDK run ID Summary output by using `printf` for Markdown backticks, avoiding Bash command substitution.
- Verify VM APK provenance against the compiled `ssh-core.c` and package `Makefile` inputs, allowing workflow/documentation-only commits without forcing an otherwise identical SDK rebuild.
- Fix the concurrent SOCKS VM test to wait on the four curl worker PIDs only; a bare `wait` also joined the long-lived `ssh-core` daemon and stalled the test after the concurrent stage banner.
- Strengthen SSH channel backpressure detection: libssh2 reports a depleted write window as `LIBSSH2_ERROR_EAGAIN` when no inbound packet is ready, so query `libssh2_channel_window_write_ex()` and only count a zero-window event when it returns zero. Pause retries until the SSH receive sequence advances, and make the VM assert this exact event.
- Separate the backpressure log latch from the retry/wait state so a sustained zero-window episode is logged once; log recovery only after a channel write succeeds again.
- Track the c2s ring-buffer high-water mark and report its final occupancy when closing a backpressured channel. Extend the QEMU VM upload test to require matching block/recovery events, an empty ring buffer at close, a peak no greater than 32 KiB, and an exact 32 MiB remote size/SHA-256.
- Add a push-triggered full CI pipeline on `main`; parser, SDK compilation, APK handoff, QEMU boot, and guest integration tests execute sequentially in one run.
- Add S2C backpressure diagnostics: track the reverse-direction ring-buffer high-water mark, detect saturation, and report whether it drains after the client resumes reading.
- Extend VM coverage with four concurrent 8 MiB uploads, an 8 MiB throttled download with exact SHA-256, client-abort recovery, and 12 repeated SOCKS connections with RSS/FD checks.
- Bump the OpenWrt package release to 3 for the additional S2C diagnostics.

## Unreleased
- Fix graceful client EOF/HUP cleanup so queued client-to-SSH data is drained and SSH EOF is sent before releasing the channel; preserve the immediate close path for reset peers.
- Add a native regression for graceful HUP with queued C2S data, and refine dead-client shutdown state checks.
- Bump OpenWrt package release to r12 so devices on r11 can upgrade to the graceful EOF fix.
- Native parser/core-state regression for the graceful EOF cleanup fix passed in GitHub Actions run #20 (commit 2697caad).
- The OpenWrt 25.12.5 x86_64 SDK build for r12 succeeded in GitHub Actions run #24; the resulting artifact is reserved for the separate QEMU VM validation stage.
