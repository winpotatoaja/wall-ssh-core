# R65-D — AES-128-CTR alignment investigation (MIPS)

Terakhir diperbarui: 2026-11-27  
Branch: `experiment/r65d-aes-ctr-alignment`  
Basis: R65-C commit `a0defe54e7fe8b1bb47d3a8af3c463b6ac0ebfc1`

## Tujuan

Menyelidiki mengapa jalur AES-128-CTR RX out-of-place R65-C lebih lambat daripada jalur R65-B `EVP decrypt in-place + memcpy` pada MT7621 QEMU. R65-D hanya menambah observabilitas alignment dan benchmark EVP terisolasi. Tidak ada algoritma atau operasi crypto produksi yang diganti.

## Baseline yang diuji

Nilai berikut dihitung dari log mentah transfer QEMU 32 MiB pada artifact R65-B (#901) dan R65-C (#905). Total waktu R65-B adalah EVP + copy; R65-C mengukur EVP out-of-place saja karena copy sudah dihilangkan.

| Mode | R65-B EVP | R65-B copy | R65-B total | R65-C out-of-place EVP | Selisih total |
|---|---:|---:|---:|---:|---:|
| AES-CTR non-ETM | 48.88 ms/MiB | 2.17 ms/MiB | 51.05 ms/MiB | 52.46 ms/MiB | +2.76% |
| AES-CTR ETM | 40.64 ms/MiB | 2.02 ms/MiB | 42.66 ms/MiB | 44.31 ms/MiB | +3.88% |

R65-C menghapus copy RX bulk, tetapi total waktu jalur dekripsi sedikit memburuk. Hasil ini berasal dari MT7621 QEMU/CI, bukan pengukuran router fisik.

## Pekerjaan R65-D

1. Catat residue modulo 16 dari pointer source ciphertext dan destination plaintext pada setiap panggilan bulk RX ketika diagnostic timing aktif.
2. Akumulasikan residue tersebut ke dua bitmask: `ctr_rx_src_align_mask` dan `ctr_rx_dst_align_mask`. Bit ke-`n` berarti setidaknya satu panggilan pada interval itu menggunakan alamat dengan residue `n`.
3. Salurkan mask melalui snapshot diagnostic dan cetak pada record `[PERF-CTR]`.
4. Tambahkan benchmark AES-128-CTR standalone dengan 256 pasangan alignment source/destination. Setiap pasangan memakai update 16 KiB, stream 256 KiB, dan lima sampel; dibandingkan median waktu in-place EVP + copy terhadap EVP out-of-place.
5. Verifikasi plaintext pada kedua metode dan pastikan input ciphertext kandidat out-of-place tidak berubah.

## Hasil R65-D — MT7621 QEMU

Guest menggunakan OpenSSL 3.0.22. Matriks MIPS 16 × 16 selesai: seluruh 256 pasangan alignment lulus verifikasi plaintext dan keutuhan ciphertext sumber.

| Pengukuran median | In-place EVP + copy | Out-of-place EVP | Selisih |
|---|---:|---:|---:|
| Semua 256 pasangan | 52,726,548 ns/MiB | 41,650,284 ns/MiB | -21.01% |

Pada semua 256 pasangan, kandidat out-of-place lebih cepat di benchmark terisolasi (rentang delta -7.53% sampai -37.62%). Untuk alignment yang benar-benar terlihat pada transfer SSH, hasil pasangan spesifiknya:
- Non-ETM, source residue 12 → destination residue 11: -15.29%; ada interval non-ETM lain yang juga mencatat source residue 4 → destination residue 11.
- ETM, source residue 4 → destination residue 15: -16.04%.

Telemetry PERF-CTR selama transfer mengonfirmasi:
- Non-ETM: `ctr_rx_src_align_mask=0x1000` (residue 12), kadang `0x1010` (residue 12 dan 4); `ctr_rx_dst_align_mask=0x0800` (residue 11).
- ETM: `ctr_rx_src_align_mask=0x0010` (residue 4); `ctr_rx_dst_align_mask=0x8000` (residue 15).

Tes transfer end-to-end masing-masing mengunduh 32 MiB dan SHA-256 cocok:
- Non-ETM: 9.541 MiB/s; total bulk RX 32.055 MiB, EVP 52.44 ms/MiB.
- ETM: 9.240 MiB/s; total bulk RX 32.041 MiB, EVP 44.95 ms/MiB.
- Kedua mode mencatat `ctr_rx_copy_calls=0` dan `ctr_rx_copy_bytes=0`.

**Interpretasi:** benchmark mikro MIPS mendukung hipotesis bahwa pasangan pointer/alignment out-of-place dapat menguntungkan, tetapi pengukuran transfer SSH tidak menunjukkan peningkatan EVP/end-to-end yang sejalan. Waktu EVP transfer R65-D praktis setara R65-C; jika dibandingkan dengan total EVP+copy R65-B, hasil ini malah sedikit lebih tinggi. Perbandingan antar-run QEMU belum merupakan A/B terkontrol, sehingga belum cukup untuk mengklaim peningkatan throughput. R65-D tetap investigasi; belum ada perubahan strategi cipher yang dipromosikan.

## Batas perubahan

- Tidak mengubah R65-C `EVP_CipherUpdate(dest, source)`, R65-B HMAC reuse, cipher TX, ChaCha20-Poly1305, AES-GCM, SSH framing, rekey, atau preferensi cipher.
- Mask alignment hanya diperbarui ketika diagnostics aktif.
- Benchmark memakai OpenSSL dari OpenWrt 24.10.7 SDK dan dijalankan di guest MT7621 QEMU. Hasilnya untuk diagnosis alignment/EVP, bukan klaim performa router fisik.
- Tidak memilih atau mengaktifkan strategi produksi baru sebelum hasil alignment dan benchmark dianalisis.

## Validasi

- [x] Patcher dan source validator lulus pada OpenWrt SDK libssh2 1.11.1.
- [x] Native benchmark lulus 256 pasangan.
- [x] Helper MIPS32r2 little-endian lulus di MT7621 QEMU pada 256 pasangan.
- [x] Mask source/destination terekam pada PERF-CTR transfer AES-CTR RX.
- [x] AES-CTR non-ETM dan ETM integration QEMU lulus checksum 32 MiB.
- [x] IPK OpenWrt 24.10.7 `mipsel_24kc` dan helper berasal dari artifact SDK pada run yang sama.

## Status

R65-C sebagai baseline: SDK dan MT7621 QEMU lulus pada Actions #905.

R65-D: SDK dan MT7621 QEMU jobs SUCCESS pada Actions #909 (run `45937284912`). Patcher, source test, build IPK, MIPS helper, matriks alignment 256 pasangan, telemetry runtime, dan transfer AES-CTR non-ETM/ETM lulus. Hasil numerik dan batas interpretasinya dicatat pada bagian Hasil R65-D.
