# Passwall SSH Core changelog

## Unreleased

- Add OpenWrt 25.12.5 x86_64 SDK package integration using the official 25.12 OpenWrt package makefiles and packages feed.
- Use the repository's real OpenWrt package Makefile for SDK packaging; verify the source file is copied and the target binary is produced. Compile with TARGET_CPPFLAGS and GNU11.
- Tighten HTTP status-line parsing to accept only valid HTTP/1.0 and HTTP/1.1 response versions.
- Fix the malformed-version regression fixture to use actual CRLF delimiters; close the peer for deterministic parser rejection.
- Add HTTP response parser regression coverage for malformed versions, CONNECT, Content-Length, chunked, close-delimited, and explicitly enabled legacy HTTP 200 tunnel responses.
- Split CI into manually selected parser, SDK, and QEMU VM stages. The VM stage downloads the APK from a prior SDK run and verifies both source commit and APK checksum.
- Disable push-triggered Actions for the Passwall SSH workflows to prevent repeated runs and unnecessary Actions-minute usage.
- Mirror the manual dispatcher to the repository default branch so GitHub exposes the workflow UI; dispatch it against the `passwall-ssh-core` branch.
- Build and VM test results are not claimed until their respective manual stages complete successfully.
- Fix the QEMU VM host SSH fixture startup by creating `/run/sshd` with root ownership and mode `0755` before launching OpenSSH; the previous VM failure was caused by sshd refusing to start because this directory was absent.
- Fix SDK run ID Summary output by using `printf` for Markdown backticks, avoiding Bash command substitution.
- Verify VM APK provenance against the compiled `ssh-core.c` and package `Makefile` inputs, allowing workflow/documentation-only commits without forcing an otherwise identical SDK rebuild.
- Fix the concurrent SOCKS VM test to wait on the four curl worker PIDs only; a bare `wait` also joined the long-lived `ssh-core` daemon and stalled the test after the concurrent stage banner.
- Strengthen SSH channel backpressure detection: libssh2 reports a depleted write window as `LIBSSH2_ERROR_EAGAIN` when no inbound packet is ready, so query `libssh2_channel_window_write_ex()` and only count a zero-window event when it returns zero. Pause retries until the SSH receive sequence advances, and make the VM assert this exact event.
- Separate the backpressure log latch from the retry/wait state so a sustained zero-window episode is logged once; log recovery only after a channel write succeeds again.
- Track the c2s ring-buffer high-water mark and report its final occupancy when closing a backpressured channel. Extend the QEMU VM upload test to require matching block/recovery events, an empty ring buffer at close, a peak no greater than 32 KiB, and an exact 32 MiB remote size/SHA-256.
