# R65-D change log

## 2026-11-27 — AES-128-CTR alignment investigation

- Branch `experiment/r65d-aes-ctr-alignment` dibuat dari R65-C commit `a0defe54e7fe8b1bb47d3a8af3c463b6ac0ebfc1`.
- Analisis ulang log mentah R65-B/R65-C QEMU: non-ETM R65-B total EVP + copy 51.05 ms/MiB, R65-C out-of-place EVP 52.46 ms/MiB (+2.76%). ETM R65-B 42.66 ms/MiB, R65-C 44.31 ms/MiB (+3.88%).
- Ditambahkan telemetry residue modulo 16 untuk source dan destination pada jalur AES-CTR RX bulk R65-C. Telemetry disalurkan melalui diagnostic snapshot dan PERF-CTR.
- Ditambahkan benchmark OpenSSL 3 untuk 256 pasangan source/destination alignment, membandingkan EVP in-place + copy dengan EVP out-of-place. Setiap metode memverifikasi plaintext; kandidat out-of-place juga memastikan ciphertext sumber tidak berubah.
- Operasi cipher produksi tetap tidak berubah. SDK dan same-run MT7621 QEMU validation: pending.
