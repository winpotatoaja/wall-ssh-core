# R65-E change log

## 2026-11-27 — realistic AES-CTR RX workload investigation

- Created isolated branch \`experiment/r65e-aes-ctr-realistic-bench\` from validated R65-D commit \`e0406352787b22aa5a0dad663f6c6ee4d3d50096\`.
- Recomputed R65-D runtime bulk RX averages from guest logs: non-ETM 16,105 bytes/call; ETM 28,938 bytes/call, unlike the previous 16 KiB-only microbenchmark.
- Added runtime 4 KiB call-size histogram and exact min/max packet lengths.
- Added backend-only EVP timing and separated it from total bridge/dispatch/outer-call timing. The timer is optional and enabled only for diagnostics.
- Added MIPS benchmark matrix: 3 observed alignment pairs × 3 update sizes (16/29/32 KiB) × 3 working sets (256 KiB/4 MiB/32 MiB) × 5 trials. Baseline is in-place EVP plus packet-by-packet memcpy; candidate is out-of-place EVP.
- Production cipher operation remains unchanged. SDK/QEMU validation: pending.
