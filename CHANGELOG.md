# Passwall SSH Core changelog

## Unreleased

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
