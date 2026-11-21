## Unreleased
- Add SSH serialized-pending diagnostics (operation, libssh2 block directions, C2S/S2C occupancy, channel write window, and worker in-flight state); enable backpressure/performance counters in the x86 QEMU relay run to identify the full-duplex stall without changing relay behavior.
- Start MT7621 mipsel_24kc QEMU runtime validation using the successful SDK artifact from run 44908474616; source changes remain documentation-only.
- Start OpenWrt 25.12.5 x86_64 QEMU runtime validation using the successful SDK artifact from run 44908474679; source changes remain limited to documentation.
- Defer client FD closure whenever either relay direction still owns a worker reference; the final completion performs the pending close, preventing one direction from closing a descriptor still used by the other.
- Wire one bounded I/O worker pool into the live SSH Owner epoll loop for asynchronous C2S reads and S2C writes. Completion identity is validated by the Owner before C2S ring commit or S2C ring-head advancement; partial writes commit only accepted bytes, client lifetime references defer teardown, and pending HUP/RDHUP drains are serialized with worker reads. Consolidated native/MIPS/QEMU validation is pending.
- Detach client FDs from epoll on failed lifetime finalization to prevent stale retired-client events.
- Harden client teardown: lifetime finalization must succeed before the FD, ring buffers, or client object are freed; retired clients remain queued if finalization cannot be confirmed. This is a safety prerequisite for live worker integration; validation is pending.
- MIPS OpenWrt 24.10.7 SDK build r36 succeeded in GitHub Actions run 44900327596; the MIPS IPK and worker-pool/completion-tracker helpers are ready for MT7621 QEMU validation. [sdk_run_id=44900327596] [mips-stage=vm]
- Implement `io_worker_pool_select_worker()` and `io_worker_pool_submit_to_worker()` so the SSH Owner selects a worker, registers the full task/client/generation/worker identity with the completion tracker, and only then publishes the copied task. This closes the race where a fast worker could complete before the Owner had registered its lifetime reference.
- Add an end-to-end native and MIPS regression that waits on the worker completion eventfd, drains the completion, and consumes it against the pre-registered tracker identity.
- Bump the OpenWrt package release to r36.

## Unreleased
- Add an SSH-Owner-only bounded completion tracker keyed by task ID. A completion must match task ID, client ID, generation, and worker assignment before it can consume a task reference; duplicate and malformed completions cannot decrement another task's lifetime reference.
- Add rollback for task registrations when worker submission fails, plus native regressions for exact-once completion, stale/mismatched identity, bounded capacity, and rollback.
- Refuse to destroy the completion tracker while accepted tasks remain outstanding. The tracker is currently a tested Owner-side primitive; eventfd registration/draining and worker submission are not yet wired into `ssh-core.c`.
- Add native and MIPS/QEMU regression coverage for completion identity, exactly-once consumption, bounded capacity, rollback, and shutdown guards.
- MIPS OpenWrt 24.10.7 SDK build r35 succeeded in GitHub Actions run 44897393502; the completion tracker helper was cross-compiled for mipsel_24kc and included in the VM test artifact.
- Bump OpenWrt package release to r35.

## Unreleased
- Defer client FD, ring-buffer, and object destruction while worker references remain; retire detached clients and reap them only from the SSH Owner after references drain.
- Make shutdown use the same deferred-destruction path instead of closing client FDs before lifetime accounting.


# Passwall SSH Core changelog

## Unreleased

- Add a dedicated client epoll-cookie encoder/decoder and regression coverage for invalid IDs, boundary IDs, and pointer-tag separation. The SSH Owner now decodes tagged client IDs and resolves them through the active client list; stale client cookies are ignored without dereferencing freed client pointers. Package preparation now installs the helper header. Native and MT7621 static MIPS tests required. [mips-stage=sdk]

- Introduce process-wide monotonic client IDs and generation fields, and encode client IDs in epoll event cookies. SSH Owner resolves client cookies through its active-client list, ignoring stale events instead of dereferencing freed `client_conn_t` pointers. This remains synchronous; no worker tasks or deferred client destruction are enabled. Native and MT7621 QEMU validation required. [mips-stage=sdk]
- Complete MT7621 OpenWrt 24.10.7 QEMU validation for the standalone client lifetime helper using SDK artifact run `44891359077` (QEMU run `44892754687`); the full VM workflow succeeded.

- Extend the MT7621 gate to compile and execute the client lifetime regression as a static `mipsel_24kc` helper; include the lifetime header/source in SDK-to-VM source provenance and artifact checksum validation.
- Add SSH-Owner-only client lifetime accounting primitives and native/MIPS regression coverage: immutable client identity plus generation token, task-reference acquisition/release, stale-completion rejection, close deferral until the final reference drains, and guarded finalization. This is a tested foundation only; it is not yet wired into `client_conn_t`, epoll dispatch, or live worker submissions.
