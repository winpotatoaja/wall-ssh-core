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

## Tests: run one stage at a time

The native HTTP parser regression test is
`tests/http_parser_test.c`.

Use the GitHub Actions workflow
`.github/workflows/passwall-ssh-core-openwrt25-vm.yml`. The dispatcher is also
present on the repository default branch so GitHub exposes the manual trigger.
In **Run workflow**, select branch `passwall-ssh-core`, then choose exactly one
stage from the `workflow_dispatch` input:

1. **parser** — compiles and runs the HTTP parser tests on Debian. This is the
   first, inexpensive gate.
2. **sdk** — cross-compiles the C client into an OpenWrt APK. On success, the
   workflow uploads `passwall-ssh-core-openwrt-apk` for seven days and prints
   its workflow run ID.
3. **vm** — enter the successful SDK run ID in `sdk_run_id`. The workflow
   downloads that APK, verifies the APK checksum and confirms that the compiled
   `ssh-core.c` and package `Makefile` match the selected branch, then boots the
   official OpenWrt 25.12.5 x86_64 guest in QEMU TCG and exercises
   the SSH/SOCKS relay. The workflow prepares the host-side OpenSSH privilege
   separation directory (/run/sshd) before starting its temporary test server.

The VM checks SSH password authentication, the SOCKS non-loopback bind guard,
numeric configuration overflow rejection, a 1 MiB download, and four concurrent
channels. Its backpressure fixture caps the host sshd TCP send buffers,
constrains the HTTP receiver's TCP receive buffer/window, pauses reads after
request headers, and drains a 32 MiB upload slowly. The client checks
`libssh2_channel_window_write_ex()` when `libssh2_channel_write()` returns
`LIBSSH2_ERROR_EAGAIN`; it records a true zero-window event only when the
reported writable channel window is zero, then waits for inbound SSH window
adjustment data before retrying the pinned write. The VM requires at least one
such event and verifies the complete remote SHA-256. Window-block messages are
transition-logged (not repeated on every EAGAIN); a recovery message is emitted
only after a channel write succeeds again. The VM checks that each logged block
has a matching recovery, that the c2s ring is empty when the channel closes,
and that its high-water mark never exceeds the fixed 32 KiB buffer capacity.
The concurrent test waits only for its curl worker PIDs; it must not wait on
the long-running `ssh-core` service process.

The workflow is manual-only: ordinary pushes do not start Actions. Run
`parser` first; only proceed to `sdk` after it passes, then run `vm` with
the successful SDK run ID. A build or VM test is only considered passed when
its corresponding stage completes successfully.
