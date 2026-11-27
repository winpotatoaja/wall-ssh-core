# R68 — Changelog

## 2026-11-27 — libssh2 packet queue payload accounting

- Correct the R43 diagnostic enqueue hook to add `data_len - data_head`, so current and cumulative queue-byte counters measure unread payload rather than SSH framing headers.
- Keep the existing partial-read, packet-ask, and channel-flush subtraction paths; they now share the same payload-byte unit as enqueue and the enable-time queue baseline.
- Add a regression test that compiles the actual inline accounting helpers extracted from the R43 patch template and exercises CHANNEL_DATA, EXTENDED_DATA, partial reads, packet removal, flush, and control packets.
- Preserve relay behavior, crypto profile, socket I/O, buffers, and worker topology. This is a diagnostic-accounting correction only.
- Package release: `1.0.0-r68`.
- SDK OpenWrt 24.10.7 / mipsel_24kc: **PASS** (Actions #934, source `2f2af74b7db68c9cd13e569ecb577fae302f19e7`).
- MT7621 QEMU integration: **PASS**; guest installed `1.0.0-r68`, and runtime integration finished with `MIPS TEST STATUS: 0`.
- IPK SHA-256: `cbcb8dfbcd5b1d2c686cd5d7c6370754323917194f8bac9616932fd721940563`.
- R68-B snapshot/reset invariants remain incomplete; R68-C/D diagnostics and R68-E analysis have not started.

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

