- **Stage 3 QEMU integration passed:** run `44976854992` completed successfully for SDK artifact from run `44975775354` (SDK source SHA `9dbda79c93d659be6ba02d81343120594bfcdf78`). Idle client TCP RST followed by 8 fresh SOCKS reconnects passed with exact 1 MiB size and SHA-256 per transfer; half-close, post-EOF upload, full-duplex and concurrent TCP/TLS client suites passed. This validates the pre-rollback-hardening source; final source patch still requires a fresh full gate.
- **Stage 3 rollback audit correction:** both C2S and S2C task publication failure paths now verify completion-tracker cancellation and lifetime-reference release instead of discarding return values. Native/MIPS SDK/QEMU validation of this latest source is pending. [mips-stage=sdk]
- **Stage 3 MIPS SDK/native gate passed:** Actions run `44975775354` built the OpenWrt 24.10.7 `mipsel_24kc` IPK and static regression helpers from source SHA `9dbda79c93d659be6ba02d81343120594bfcdf78`; native regression steps also passed. Artifact `14736136175` is the input for the matching MT7621 QEMU integration run. [mips-stage=vm] [mips_sdk_run_id=44975775354]
- **Stage 3 validation batch queued:** native regression and OpenWrt 24.10.7 SDK build are triggered from this documentation commit. The matching QEMU run will be triggered using the SDK run ID after it completes. [mips-stage=sdk]
- **Stage 3 RST/reconnect/FD-reuse regression added (workflow commit `36d667fd`):** MIPS QEMU fixture now provides a delayed idle response for the RST helper, followed by eight new SOCKS transfers checking exact 1 MiB length and SHA-256. Validation remains pending; stage 3 is not marked passed until this workflow completes successfully against the matching source SHA.
- **Stage 4 diagnostic correction (source commit `852c6f5d`):** perf metric `s2c_epollout_missing` now excludes clients with an asynchronous S2C worker write in-flight. Owner intentionally does not arm `EPOLLOUT` while that worker owns the socket write, so those cases were previously counted as missing epoll wakeups and could skew diagnosis. Native/SDK/QEMU validation of this correction is pending.
- Native regression and OpenWrt 24.10.7 mipsel_24kc SDK validation passed for the worker fallback invariant batch in Actions run `44964541444`; artifact `14730609580` is available for the matching MT7621 QEMU run. Fixed the SDK workflow's TLS-source assertion to inspect the workspace `ssh-core.c` and fail if that file is missing. QEMU runtime validation remains pending.
- Restrict synchronous C2S/S2C socket fallback to temporary worker queue pressure only (`submit_rc == 1` / `EAGAIN`). Fatal submit/tracker/lifetime errors now fail the affected client path closed instead of silently running synchronous I/O; the shared S2C flush helper propagates fatal submission errors. Native/MIPS/QEMU validation pending.
- Treat duplicate/stale worker completions (`ENOENT`) as already-consumed records, but fail the relay closed on malformed/mismatched completion identity, missing retained client-generation, lifetime-release failure, or a completion with no matching C2S/S2C in-flight task. Completion drain now propagates invariant failures to the SSH Owner so it exits with failure instead of continuing with inconsistent lifetime/task state. Native/MIPS/QEMU validation pending.

## Unreleased
- MT7621 QEMU integration run `44965112117` completed successfully for source SHA `0f1d484604fb2d2f1d0e53ee5603f90fe71995f2`: TCP/TLS baseline, multi-client single-session transfers, 32 MiB C2S/S2C checksums, half-close/full-duplex, keepalive and graceful shutdown passed; guest test status is 0. Stage 3 remains open pending explicit RST/reconnect/FD-reuse coverage and final audit.
- Correct the MIPS QEMU C2S upload assertion: validate exact cumulative received/committed byte accounting and absence of retained channel data, rather than requiring optional zero-window log transitions that did not occur in this run.
- Re-run MT7621 QEMU using the verified MIPS IPK from SDK run `44957061334` after correcting workflow artifact selection.
- Fix the MIPS QEMU workflow to consume its dedicated `[mips_sdk_run_id=RUN_ID]` artifact instead of accidentally reusing the x86 SDK run ID.
- Rebuilt the diagnostic-enabled source successfully for OpenWrt 25.12.5 x86_64 (APK) and OpenWrt 24.10.7 mipsel_24kc (IPK); queue QEMU validation against these exact SDK artifacts.
- Queue fresh OpenWrt 25.12.5 x86_64 and OpenWrt 24.10.7 mipsel_24kc SDK builds for the pending-operation diagnostic update; QEMU stages must consume these new source-matched artifacts.
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
