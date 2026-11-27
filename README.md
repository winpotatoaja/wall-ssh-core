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

## Batas perubahan

- Tidak mengubah R65-C `EVP_CipherUpdate(dest, source)`, R65-B HMAC reuse, cipher TX, ChaCha20-Poly1305, AES-GCM, SSH framing, rekey, atau preferensi cipher.
- Mask alignment hanya diperbarui ketika diagnostics aktif.
- Benchmark memakai OpenSSL dari OpenWrt 24.10.7 SDK dan dijalankan di guest MT7621 QEMU. Hasilnya untuk diagnosis alignment/EVP, bukan klaim performa router fisik.
- Tidak memilih atau mengaktifkan strategi produksi baru sebelum hasil alignment dan benchmark dianalisis.

## Validasi

- [ ] Patcher dan source validator lulus.
- [ ] Native benchmark lulus 256 pasangan.
- [ ] Helper yang sama dikompilasi untuk MIPS little-endian dan lulus di MT7621 QEMU.
- [ ] Mask source/destination muncul pada record PERF-CTR selama AES-CTR RX bulk.
- [ ] AES-CTR non-ETM dan ETM existing integration lulus checksum.
- [ ] IPK OpenWrt 24.10.7 `mipsel_24kc` dan QEMU berasal dari commit/artifact SDK yang sama.

## Status

R65-C sebagai baseline: SDK dan MT7621 QEMU lulus pada Actions #905.  
R65-D: source, benchmark, dan workflow telah dipush; hasil SDK/QEMU masih pending.
