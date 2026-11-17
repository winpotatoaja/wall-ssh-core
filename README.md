# Passwall SSH Core

A non-blocking libssh2 client that opens one SSH session and multiplexes local
SOCKS5 clients over SSH `direct-tcpip` channels.

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
- `VERIFY_TLS=0` remains the compatibility default. TLS is encrypted but
  certificate and hostname validation are not performed in this mode. Set
  `VERIFY_TLS=1` when the endpoint has a valid certificate and the OpenWrt
  CA store is installed.
- `HOSTKEY` optionally pins the SSH host-key fingerprint. Without a pin, the
  fingerprint is informational; server rotation is not blocked by a known_hosts
  database.
- `MAX_CLIENTS` defaults to 64 and is capped at 256.
- `IDLE_TIMEOUT` defaults to 600 seconds; set it to 0 to disable idle expiry.

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
   the S2C reader during an 8 MiB download. Both directions verify exact
   lengths and SHA-256. The tests assert that c2s and s2c buffers never exceed
   their 32 KiB capacity and drain to zero after the receiver resumes.
5. **Disconnect and repeated-connection checks** — abort an in-flight client
   request, verify that the service remains usable, then open and close 12
   more SOCKS connections while checking process RSS and file-descriptor
   counts for material growth.

The workflow is a single sequential job for push-triggered runs: SDK build
must finish successfully before the VM stage downloads and installs its APK.
The guest test script is syntax-checked before the VM boots, and the host HTTP
fixture is Python-compiled before it starts. The job has a 60-minute hard
timeout; individual transfers also have explicit curl timeouts.

For diagnosis, the workflow still exposes a manual `workflow_dispatch` route
for running one isolated stage (`parser`, `sdk`, or `vm`). The manual VM
stage requires the run ID of a successful SDK-stage artifact from the same
repository. A green workflow result means all stages and all guest assertions
completed successfully; a timeout or skipped test is not considered a pass.
