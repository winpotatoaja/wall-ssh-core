# R65-E — AES-CTR RX real-workload investigation

Terakhir diperbarui: 2026-11-27  
Branch: \`experiment/r65e-aes-ctr-realistic-bench\`  
Basis: R65-D commit \`e0406352787b22aa5a0dad663f6c6ee4d3d50096\`

## Tujuan

Mencari penyebab perbedaan antara benchmark mikro R65-D (out-of-place lebih cepat) dan waktu EVP saat transfer SSH nyata (belum membaik). R65-E tetap diagnostic/benchmark-only: tidak mengganti algoritma, framing, atau jalur produksi.

## Bukti awal dari R65-D

Log transfer MT7621 QEMU 32 MiB memberi ukuran rata-rata bulk RX berikut:

| Mode | Bulk bytes | Panggilan | Rata-rata per panggilan |
|---|---:|---:|---:|
| AES-CTR non-ETM | 33,611,728 | 2,087 | 16,105 bytes |
| AES-CTR ETM | 33,597,136 | 1,161 | 28,938 bytes |

Benchmark R65-D hanya memakai update 16 KiB dan working set 256 KiB. Jadi ia belum memodelkan ukuran operasi ETM dan working set transfer 32 MiB.

## Pekerjaan R65-E

1. Tambah histogram ukuran aktual bulk RX dalam bucket 4 KiB, serta minimum/maksimum per interval.
2. Pisahkan waktu EVP backend \`EVP_CipherUpdate\` dari waktu total pemanggilan melalui bridge. Selisihnya mencakup validasi context/pointer, dispatch, dan biaya pengukuran luar.
3. Tambah benchmark MIPS dengan tiga working set (256 KiB, 4 MiB, 32 MiB), tiga ukuran update (16 KiB, 29 KiB, 32 KiB), dan tiga pasangan alignment yang teramati pada transfer.
4. Setiap konfigurasi membandingkan baseline in-place EVP yang langsung diikuti memcpy pada setiap paket dengan EVP out-of-place; lima sampel median, urutan metode berselang-seling, verifikasi plaintext, serta checksum ciphertext sumber.
5. Jalankan benchmark native dan MIPS/QEMU; pertahankan transfer integration 32 MiB non-ETM/ETM dan SHA-256.

## Batas perubahan

- Tidak mengubah operasi produksi \`EVP_CipherUpdate(dest, source)\`, pemilihan cipher, HMAC, TX, ChaCha20-Poly1305, AES-GCM, SSH framing, maupun rekey.
- Timer backend hanya aktif saat diagnostics aktif.
- Histogram dan bridge timing hanya menambah telemetry.
- Package experiment tetap memakai \`PKG_RELEASE=65\`; penomoran final R66 dilakukan di branch R66.

## Validasi

- [ ] Patcher R65-E, source validator, native benchmark lulus.
- [ ] IPK OpenWrt 24.10.7 \`mipsel_24kc\` dibangun; helper R65-E MIPS cross-compile lulus.
- [ ] Benchmark 27 konfigurasi × 5 sampel lulus di MT7621 QEMU.
- [ ] Histogram ukuran dan backend/bridge timing muncul saat transfer 32 MiB.
- [ ] AES-CTR non-ETM dan ETM tetap lulus SHA-256 di QEMU.

## Status

R65-D sudah lulus SDK dan MT7621 QEMU, tetapi microbenchmark 16 KiB/256 KiB tidak menjelaskan perbedaan terhadap transfer nyata. R65-E menguji ukuran update yang teramati dan working set sampai 32 MiB, serta memisahkan backend EVP dari bridge. Hasil branch ini belum dinyatakan sampai Actions selesai.
