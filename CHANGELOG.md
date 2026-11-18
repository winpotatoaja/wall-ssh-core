# Passwall SSH Core changelog

## Unreleased

- Allow channel cleanup after inbound-only `libssh2` EAGAIN; only an operation
  held in the global pending slot pins its original channel buffers.
- Close dead-client channels once queued C2S data is drained, without waiting
  for stale read-pending state or a remote EOF that may never arrive.
- Keep aborted channel-open attempts under the existing 30-second hard-open
  timeout instead of applying the shorter 10-second channel-cleanup deadline.
- Separate passive TLS EOF-peek readiness from TLS callback retry state.
  A passive WANT_READ no longer blocks SSH channel pumping; WANT_WRITE remains
  serialized, and actual upstream receive progress invalidates the old probe.
- Classify rejected non-tunnel HTTP 200 and invalid 101 responses as proxy
  failures rather than SSH KEX failures.
- Add regressions for inbound-only read/write EAGAIN cleanup, globally pending
  write buffer retention, dead-client cleanup readiness, TLS EOF-peek state,
  receive-sequence tracking, HTTP rejection classification, and aborted-open
  deadline behavior.
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
