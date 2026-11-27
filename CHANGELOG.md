# R67-DIAG — Changelog

## 2026-11-27 — R67-DIAG queue telemetry (based on R66)

- Keep the validated R66 crypto profile unchanged: R64 in-place AES-CTR RX + copy, R65-B HMAC context reuse, and R66 authenticated packet padding/MAC cleanup.
- Keep relay flow, ring capacities, worker topology, SSH window policy and socket read/write behavior unchanged.
- Add read-only kernel TCP Recv-Q/Send-Q snapshots for the upstream transport and each active SOCKS relay client, gated by the existing `-log-perf 1` switch.
- Add TLS Engine queue snapshot API for TLS SPSC ring occupancy and upstream socket kernel queues. The snapshot uses the TLS Engine mutex to serialize ioctl sampling against final socket close; TLS socket I/O remains exclusively owned by the TLS thread.
- Add `[QUEUE]` interval records with sample validity, aggregate and maximum per-SOCKS queue sizes, TLS ring occupancy/capacity, and existing C2S/S2C ring occupancy.
- Add native/source/runtime checks for queue snapshot values and TCP/TLS guest telemetry.
- Package release: `1.0.0-r67`.
- SDK/QEMU validation: pending.

