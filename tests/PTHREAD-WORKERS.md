# Phase 3 I/O Worker Pool

## Architecture status

This document replaces the historical R24 per-worker SSH-session design.
That design is obsolete and must not be used as the Phase 3 target.

The required ownership model is:

- Exactly one SSH Owner owns the sole `LIBSSH2_SESSION`, all SSH channels,
  channel state, and all calls into libssh2.
- Exactly one TLS Engine owns the upstream TLS socket and every `SSL*`
  operation.
- The I/O Worker Pool performs bounded local-socket I/O tasks only. Workers
  must not call libssh2, OpenSSL, or access mutable SSH-Owner client objects.
- The SSH Owner submits copied task records and consumes copied completion
  records. A completion is accepted only when its client ID and generation
  still match the live client.
- Client descriptors and ring-buffer storage must remain alive until every
  task referencing them has completed or been canceled and acknowledged.

CPU detection controls the number of auxiliary I/O workers, capped at four.
It must never change the number of SSH sessions or TLS Engines.

The r47 ChaCha path adds a separate, bounded packet-local crypto pool owned by
the inbound libssh2 ChaCha context. The SSH Owner remains the only caller of
libssh2; it authenticates a complete packet first, then splits only the
independent ChaCha20 payload blocks across at most three background lanes while
processing one lane itself. Poly1305 verification, SSH packet sequencing,
channel state and all libssh2 calls remain on the Owner. Small packets and
pool-creation failures use the original serial ChaCha implementation. The
crypto pool is destroyed with the ChaCha cipher context, including on rekey.

## Implemented foundation

The current branch contains:

- A bounded per-worker SPSC task, completion, and control queue.
- eventfd task and completion notifications.
- Round-robin task assignment with bounded outstanding credits.
- Copied task/completion payloads and immutable task/client/generation tokens.
- Bounded completion draining with eventfd re-arming.
- Cancel-pending and drain-pending shutdown modes.
- Retryable bounded worker join.
- A standalone SPSC byte-ring implementation.

The standalone worker-pool and ring-buffer components are foundations only.
They are not evidence that the pool is integrated into the live SOCKS relay.

## Remaining Phase 3 work

1. Audit queue/eventfd wakeups, queue saturation, fatal-worker paths, and
   shutdown/join behavior on the MIPS target.
2. Integrate local client socket reads/writes through worker tasks while
   preserving the single SSH Owner and dedicated TLS Engine.
3. Use SPSC byte rings for cross-thread byte ownership; do not share mutable
   `client_conn` pointers with worker callbacks.
4. Add explicit in-flight operation accounting and generation validation.
   Do not close/recycle a client FD or free its ring storage while a worker can
   still reference it.
5. Integrate completion eventfds into the SSH Owner's epoll loop and ensure
   stale completions cannot mutate a newly allocated client.
6. Exercise queue-full backpressure, partial I/O, EINTR/EAGAIN, client reset,
   graceful half-close, FD reuse, worker failure, and bounded shutdown.
7. Run native sanitizers, the OpenWrt mipsel_24kc SDK build, MT7621 QEMU runtime
   regressions, and then physical MT7621 validation.

## Validation boundary

The MIPS SDK/QEMU results for the current foundation validate compilation and
the existing baseline relay behavior. They do not validate live I/O Worker
Pool integration or prove a multi-worker relay speedup.

The historical R24 test matrix that expected multiple independent SSH
sessions/listeners per worker is not a valid Phase 3 acceptance test.
