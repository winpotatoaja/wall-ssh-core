# R66 Final — Passwall SSH Core (OpenWrt 24.10.7 mipsel_24kc)

Tanggal: 2026-11-27  
Branch: **release/r66-final**  
Basis final: R65-B commit dc0454d93a93afc94e8024f6346b54eb3ccd07d7  
Paket: **1.0.0-r66**

## Profil crypto final

R66 mengunci kombinasi yang paling kuat didukung hasil pengujian MT7621 QEMU:

- AES-128-CTR RX memakai **in-place EVP lalu memcpy** ke destination paket, yaitu jalur R64.
- HMAC-SHA256 memakai **per-direction/key-epoch EVP_MAC context reuse** dari R65-B, termasuk fallback kompatibilitas OpenSSL 3.0.0–3.0.2 dan fail-closed handling.
- Cipher default tidak diubah. ChaCha20-Poly1305 tetap mengikuti preferensi produksi saat ini; AES-CTR dipaksa hanya pada pengujian validasi.

R65-C out-of-place tidak disertakan. R65-D/E hanya alat eksperimen dan tidak ikut diterapkan dalam firmware final.

## Bukti keputusan dari R65-E

Actions #918, run 45942020408, commit R65-E 163d85697b2368e3a02753a1597fd66938c1c959, lulus SDK dan MT7621 QEMU. Guest menggunakan OpenSSL 3.0.22.

Benchmark MIPS membandingkan in-place EVP yang langsung diikuti memcpy per paket terhadap EVP out-of-place. Matriks: 3 pasangan alignment teramati, update 16/29/32 KiB, working set 256 KiB/4 MiB/32 MiB, lima sampel per konfigurasi.

| Working set | Median out-of-place lebih lambat daripada in-place + copy |
|---:|---:|
| 256 KiB | +8.55% |
| 4 MiB | +6.74% |
| 32 MiB | +6.00% |

Pada working set 32 MiB, seluruh 9 kombinasi ukuran update/alignment mengunggulkan in-place + copy; selisih out-of-place +5.84% sampai +6.23%. Seluruh 27 konfigurasi lulus verifikasi plaintext dan keutuhan ciphertext sumber.

Transfer AES-CTR QEMU 32 MiB lulus SHA-256:
- Non-ETM: 9.747 MiB/s; bulk RX 33,612,080 byte / 2,088 panggilan (rata-rata 16,098 byte per panggilan).
- ETM: 9.624 MiB/s; bulk RX 33,596,544 byte / 1,205 panggilan (rata-rata 27,881 byte per panggilan).

Pemisahan waktu R65-E:
- Non-ETM: EVP backend 51.04 ms/MiB; bridge/dispatch sekitar 0.32 ms/MiB.
- ETM: EVP backend 44.36 ms/MiB; bridge/dispatch sekitar 0.22 ms/MiB.

Tidak ada alasan performa yang tervalidasi untuk mempromosikan jalur out-of-place. Angka di atas adalah hasil QEMU/CI, bukan klaim throughput router fisik.

## Perubahan release R66

1. Naikkan package release OpenWrt menjadi **1.0.0-r66**.
2. Pertahankan R64 in-place AES-CTR + copy serta R65-B HMAC context reuse.
3. Pertahankan R65-A diagnostics; timer/counter tetap mengikuti flag diagnostics.
4. Pastikan workflow final tidak menjalankan patcher R65-C/D/E.
5. Jalankan native regressions, OpenWrt 24.10.7 mipsel_24kc SDK/IPK, lalu MT7621 QEMU memakai artifact SDK dari workflow run yang sama.
6. Tambahkan R66 source gate untuk mencegah regresi jalur crypto final dan salah penamaan IPK/artifact.

## Validasi final

- [ ] R66 source gate memastikan AES-CTR in-place + copy aktif, HMAC reuse aktif, dan R65-C/D/E tidak diterapkan.
- [ ] SDK menghasilkan passwall-ssh-core_1.0.0-r66_mipsel_24kc.ipk dengan control metadata 1.0.0-r66.
- [ ] Job VM memvalidasi artifact SDK, checksum, dan ELF MIPS.
- [ ] MT7621 OpenWrt 24.10.7 QEMU lulus regresi TCP/TLS, AES-CTR non-ETM/ETM, dan checksum.
- [ ] SDK dan VM sukses pada satu workflow run serta source commit yang sama.

## Status

R65-E: PASS — Actions #918 (SDK + MT7621 QEMU).  
R66: final source disiapkan; SDK/QEMU release gate menunggu hasil Actions.
