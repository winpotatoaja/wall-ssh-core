# R24 in-process pthread workers

## Configuration

The default worker count is automatic. At startup the core counts the CPUs
available to the process, preferring the Linux scheduler affinity mask and
falling back to `sysconf(_SC_NPROCESSORS_ONLN)`. It selects one worker per
available logical CPU and caps the pool at four:

| Available CPUs | Automatic workers |
| ---: | ---: |
| 1 | 1 |
| 2 | 2 |
| 3 | 3 |
| 4 or more | 4 |

A one-worker configuration keeps the event loop on the main thread and does
not create an additional pthread. Configure an explicit override only when
needed:

- `WORKERS=1..4` in the env file passed with `-env`
- `-workers 1..4` on the executable command line

The command-line option takes precedence over the env-file value. When neither
override is supplied, CPU-based automatic selection is used.

Example:

```sh
/usr/bin/passwall-ssh-core -env /tmp/passwall-ssh.env -workers 4 \
  -log /tmp/etc/passwall-ssh.log -log-perf 1
```

or set `WORKERS=4` in `/tmp/passwall-ssh.env` and omit `-workers`.

## Ownership and synchronization

The process creates one pthread for each configured worker. Each worker owns
its own upstream TCP socket, optional SSL_CTX/SSL objects, libssh2 session,
epoll instance, listener socket, upstream context, pending libssh2 operation,
client list, ring buffers, performance counters, and TLS callback state.

The mutable former process-global relay state is thread-local. No worker calls
libssh2 on another worker's session. The listeners bind the same SOCKS address
and port with `SO_REUSEPORT`, allowing the kernel to distribute new TCP
connections among worker listeners.

The following are intentionally process-wide:

- Stop request: atomic, shared by all workers and safe for signal delivery.
- Client admission count: atomic, preserving the configured `MAX_CLIENTS`
  limit across the complete process rather than multiplying it per worker.
- libssh2 lifecycle: `libssh2_init()` runs once before thread creation;
  `libssh2_exit()` runs once after every worker has joined.
- Payload rotation and failure-marker file writes: protected by mutexes.

A worker that fails during startup or runtime requests a coordinated process
stop; the parent joins all threads and reports a failed exit status. Shutdown
logs include `Worker N/TOTAL` and each worker's accepted-client count.

## VM validation matrix

The OpenWrt 24.10.7 `mipsel_24kc` workflow installs the R24 IPK and compares
the process-isolated reference tests with in-process pthread tests. For each
of TCP and TLS/SNI it executes 2-worker and 4-worker cases using four real
pthread download clients. All download clients must receive exactly 32 MiB and
match the expected SHA-256 digest.

For in-process cases the guest additionally verifies:

- Exactly one `passwall-ssh-core` PID is launched for the configured pool.
- `/proc/PID/status` reports at least `worker_count + 1` threads (the parent
  plus all worker threads).
- The expected number of SOCKS listeners successfully bind the same port.
- All sixteen client connections are accepted in total by the worker group, with
  at least two active workers in the 2-worker case and at least three in the
  4-worker case, based on each worker's accepted-client shutdown counter.
- All download byte-count and SHA-256 checks pass.

The guest also runs once without any `WORKERS` setting and checks that the
detected CPU count selects the expected number of listeners and process
threads. Native regressions exercise synthetic CPU counts from one through
sixteen, including the four-worker cap.

The guest sampler captures per-thread CPU ticks, process RSS/context switches,
per-core CPU use, TCP queue/drop counters, socket queues, softirqs, and
per-worker `[PERF]` counters.

## Limits

The first release caps workers at four to match the MT7621 four-core test
target and to bound per-session memory use. Four workers are not automatically
the best production setting: they increase session and TLS memory, and the VM
benchmark must be followed by tests on the physical router. QEMU/TCG throughput
is useful for controlled relative comparisons, not as a prediction of physical
router MiB/s.

The R24 implementation is experimental until the complete MIPS SDK build and
VM integration workflow has passed. Keep R23 as the known single-session
fallback while validating R24.

## SDK artifact used for VM run

The R24 MIPS SDK build completed successfully in GitHub Actions run
[44837594314](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/44837594314).
The uploaded IPK is `passwall-ssh-core_1.0.0-r24_mipsel_24kc.ipk`, with package
architecture `mipsel_24kc`. The IPK, half-close helper, and pthread downloader
checksums were verified before launching the VM stage. The VM stage reuses this
SDK artifact and checks that the compiled sources match its build-source SHA.
