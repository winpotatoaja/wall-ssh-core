# R68 — Changelog

## 2026-11-27 — R68-E combined queue evidence and optimization gate

- Synthesize R68-A/B/C/D packet accounting, TLS fairness, queue occupancy, S2C episode age, and TCP_INFO/SIOCOUTQNSD evidence.
- R68-A/B confirms the libssh2 current queue-byte counter measures unread payload, excluding the 9-byte CHANNEL_DATA and 13-byte EXTENDED_DATA framing headers; lifecycle and reset invariants pass.
- R68-C TLS/SNI multi-client download evidence: 17,709,104 RX bytes in 1,098 ms, RX service elapsed time 564,865 us, TLS RX ring full at 262,144 bytes, 100 full-ring observations, and upstream kernel Recv-Q 301,351 bytes.
- Interpret `poll_both=183`, `rx_both_ready=183`, and `tx_both_ready=0` in light of the source's explicit RX-first loop. Successful RX service returns to the event loop before a TX attempt; TX still completed 90 calls / 3,312 bytes, including 90 calls while RX data was buffered. The counters do not prove persistent TX starvation.
- A separate TCP interval recorded 409,600 bytes / 17 packets in the libssh2 unread-payload queue. Do not merge this TCP snapshot with the TLS download interval into one causal timeline.
- R68-D controlled slow-receiver fixture: S2C ring 262,144 bytes; active non-empty episode 1,503,966 us (TCP) / 1,429,447 us (TLS); SOCKS Send-Q and SIOCOUTQNSD both 2,556,032 bytes; active TCP_INFO snapshots showed zero unacked segments and zero retransmissions.
- Decision: these results identify ingress TLS handoff pressure in one QEMU download scenario and downstream client-socket backpressure in a separate deliberate slow-receiver fixture. They do not establish one production root cause, crypto saturation, packet loss, or permanent TLS TX starvation.
- No runtime code, scheduler, cipher, buffer, worker topology, backpressure policy, or package version changed. Package remains `1.0.0-r68`.
- Next evidence step before R69 optimization: reproduce the user's one-client download stall on physical MT7621 hardware with R68 and correlate `[PERF]`, `[TLSFAIR]`, `[QUEUE]`, `[S2CAGE]`, and `[TCPINFO]` by interval. If needed, R69 may add TLS RX ring and libssh2 packet-queue residence age, with MIPS 32-bit-safe cross-thread publication.
- Documentation-only update; no SDK/QEMU Actions run was triggered.

---

## 2026-11-27 — libssh2 packet queue payload accounting

- Correct the R43 diagnostic enqueue hook to add `data_len - data_head`, so current and cumulative queue-byte counters measure unread payload rather than SSH framing headers.
- Keep the existing partial-read, packet-ask, and channel-flush subtraction paths; they now share the same payload-byte unit as enqueue and the enable-time queue baseline.
- Add a regression test that compiles the actual inline accounting helpers extracted from the R43 patch template and exercises CHANNEL_DATA, EXTENDED_DATA, partial reads, packet removal, flush, and control packets.
- Preserve relay behavior, crypto profile, socket I/O, buffers, and worker topology. This is a diagnostic-accounting correction only.
- Package release: `1.0.0-r68`.
- Expand the R68 regression harness to compile the actual enable/snapshot API templates and verify existing-queue baseline, non-reset snapshots, empty/non-empty reset semantics, peak rebasing to current, re-enable/disable, NULL arguments, and saturating underflow behavior.
- Verify generated `session.c` contains the exact enable/snapshot API template used by the native lifecycle test.
- R68-B native lifecycle/snapshot regression: **PASS** (Actions #935); generated libssh2 1.11.1 source integration: **PASS**; OpenWrt 24.10.7 SDK/IPK: **PASS**.
- MT7621 QEMU integration in Actions #935: **PASS**; SDK and VM jobs both completed successfully, guest reported `MIPS TEST STATUS: 0`, and TCP/TLS multi-client, half-close, full-duplex and checksum regressions passed.
- SDK OpenWrt 24.10.7 / mipsel_24kc: **PASS** (Actions #934, source `2f2af74b7db68c9cd13e569ecb577fae302f19e7`).
- MT7621 QEMU integration: **PASS**; guest installed `1.0.0-r68`, and runtime integration finished with `MIPS TEST STATUS: 0`.
- IPK SHA-256: `cbcb8dfbcd5b1d2c686cd5d7c6370754323917194f8bac9616932fd721940563`.
- R68-B packet lifecycle and snapshot/reset invariants: **PASS** on native regression, generated-source integration, OpenWrt SDK/IPK and MT7621 QEMU (Actions #935).
- R68-C TLS Engine fairness telemetry: **PASS** on native regression, source gate, OpenWrt 24.10.7 SDK/IPK, and MT7621 QEMU (Actions #949). Native duplex transfer measured 4 MiB each direction; snapshot reset and NULL-argument invariants passed; guest `[TLSFAIR]` runtime verifier passed and guest reported `MIPS TEST STATUS: 0`.
- Runtime analysis: on a representative 4-client TLS/SNI download interval (1,098 ms), TLS RX processed 17,709,104 bytes and TX 3,312 bytes; RX/TX service times were 564,865/24,719 us. `poll_both=183`, `rx_both_ready=183`, `tx_both_ready=0` reflects the existing RX-first service order when both socket directions are ready; TX still progresses on subsequent writable events.
- Queue evidence: in that interval the TLS RX ring was full at 262,144 bytes and upstream kernel Recv-Q was 301,351 bytes. A full-duplex interval recorded TLS RX/TX 1,544,704/8,936,060 bytes, S2C ring maximum 262,144 bytes, and SOCKS kernel Send-Q 2,556,032 bytes. This indicates queue pressure requiring age/TCP context; it is not by itself proof of loss or deadlock.
- R68-C is diagnostic only, not throughput tuning. No Datapacket Internet bandwidth benchmark was run. R68-D has now measured S2C episode age and TCP not-yet-sent queue state; R68-E analysis remains pending before any scheduling change.

- R68-D: add per-client S2C non-empty episode age tracking on both channel-read enqueue paths and the single client flush path; report [S2CAGE] interval values in microseconds.
- R68-D: add owner-thread TCP_INFO snapshots (RTT, RTT variance, unacked, congestion window, retransmissions) with returned-structure length validation.
- R68-D: add compile-time guarded SIOCOUTQNSD not-yet-sent byte sampling with support/sample/failure fields, separate from the existing SIOCOUTQ total send queue.
- Keep all R68-D instrumentation read-only and gated by -log-perf 1; no changes to socket send/receive behavior, backpressure, ring capacities, scheduling, cipher, or worker topology.
- Native/source regression and runtime parsers for [S2CAGE] and [TCPINFO]: PASS. OpenWrt 24.10.7 SDK/IPK and MT7621 QEMU (Actions #951): PASS; guest MIPS TEST STATUS: 0.
- Runtime evidence under the intentional QEMU backpressure fixture: S2C ring 262,144 bytes, active episode age 1,503,966 us (TCP) / 1,429,447 us (TLS), SOCKS Send-Q and SIOCOUTQNSD both 2,556,032 bytes. Corresponding TCP_INFO RTT was 9,623 us / 7,804 us; active snapshots showed zero unacked segments and zero retransmissions.
- IPK passwall-ssh-core_1.0.0-r68_mipsel_24kc.ipk, SHA-256 60cc28ddb9943bac9d689a1b7a97bda58cb450b73a7d5ced77ea20cf76668956. QEMU validates the fixture only, not physical MT7621 hardware or Internet throughput.
- R68-E remains pending: synthesize R68-A/B/C/D evidence before selecting any optimization.

---

## R67-DIAG — Historical baseline

## 2026-11-27 — R67-DIAG queue telemetry (based on R66)

- Keep the validated R66 crypto profile unchanged: R64 in-place AES-CTR RX + copy, R65-B HMAC context reuse, and R66 authenticated packet padding/MAC cleanup.
- Keep relay flow, ring capacities, worker topology, SSH window policy and socket read/write behavior unchanged.
- Add read-only kernel TCP Recv-Q/Send-Q snapshots for the upstream transport and each active SOCKS relay client, gated by the existing `-log-perf 1` switch.
- Add TLS Engine queue snapshot API for TLS SPSC ring occupancy and upstream socket kernel queues. The snapshot uses the TLS Engine mutex to serialize ioctl sampling against final socket close; TLS socket I/O remains exclusively owned by the TLS thread.
- Add `[QUEUE]` interval records with sample validity, aggregate and maximum per-SOCKS queue sizes, TLS ring occupancy/capacity, and existing C2S/S2C ring occupancy.
- Add native/source/runtime checks for queue snapshot values and TCP/TLS guest telemetry.
- Package release: `1.0.0-r67`.
- SDK/QEMU validation: pending.

