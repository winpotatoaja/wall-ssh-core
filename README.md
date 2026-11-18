# Passwall SSH Core

A non-blocking libssh2 client that opens one SSH session and multiplexes local
SOCKS5 clients over SSH `direct-tcpip` channels.

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

## R16 verification

The parser stage includes focused regressions for TLS callback `errno`
preservation, OpenSSL unexpected EOF during handshake, alternate upstream
endpoint retry, and poll HUP/EOF handling. Build the R16 package with the
OpenWrt 25.12.5 x86_64 SDK before running the separate QEMU VM stage.

## Continuous integration tests

Pushes to `main` that change `ssh-core.c`, the package `Makefile`, tests, or this
workflow automatically run the full pipeline in order:

1. **Parser regression** — compile and run `tests/http_parser_test.c` on Debian.
2. **OpenWrt SDK build** — build the package using the official OpenWrt 25.12.5
   x86_64 SDK, including the OpenWrt OpenSSL/zlib sources and packages-feed
   libssh2. The APK is uploaded as an artifact in the same workflow run.
3. **QEMU VM integration tests** — install that APK in the official OpenWrt
   25.12.5 x86_64 guest, then exercise SSH authentication, SOCKS bind safety,
   strict numeric parsing, single and concurrent direct-tcpip transfers.
4. **Backpressure and recovery** — force a 32 MiB c2s upload through a stalled,
   small-window receiver; run four simultaneous 8 MiB uploads; then throttle
   the S2C reader during a 32 MiB download. Both directions verify exact
   lengths and SHA-256. The tests assert that c2s and s2c buffers never exceed
   their 32 KiB capacity and drain to zero after the receiver resumes.
5. **TCP half-close and sustained stress** — use a statically linked client
   cross-compiled by the OpenWrt SDK to test client-FIN-first and server-FIN-first
   sequences. The host fixture independently verifies that each FIN arrives
   and that the opposite write direction remains usable. Then run four
   concurrent workers for 90 seconds, verify every 1 MiB transfer by SHA-256,
   and monitor peak RSS and FD counts.
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
