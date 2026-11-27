# R67-DIAG — Passwall SSH Core

Tanggal: 2026-11-27  
Branch: **experiment/r67-diag**  
Commit final: \`41b101378ebda17e211d03be7ea7e7709f04f0ab\`  
Basis crypto: R65-B commit \`dc0454d93a93afc94e8024f6346b54eb3ccd07d7\`  
Paket: **1.0.0-r67**

## Profil crypto final

R66 mengunci kombinasi yang paling kuat didukung hasil pengujian MT7621 QEMU:

- AES-128-CTR RX memakai **in-place EVP lalu memcpy** ke destination paket, yaitu jalur R64.
- HMAC-SHA256 memakai **per-direction/key-epoch EVP_MAC context reuse** dari R65-B, termasuk fallback kompatibilitas OpenSSL 3.0.0–3.0.2 dan fail-closed handling.
- Cipher default tidak diubah. ChaCha20-Poly1305 tetap mengikuti preferensi produksi saat ini; AES-CTR dipaksa hanya pada pengujian validasi.

R65-C out-of-place tidak disertakan. R65-D/E hanya alat eksperimen dan tidak ikut diterapkan dalam firmware final.

## Bukti keputusan dari R65-E

Actions #918, run \`45942020408\`, commit R65-E \`163d85697b2368e3a02753a1597fd66938c1c959\`, lulus SDK dan MT7621 QEMU. Guest menggunakan OpenSSL 3.0.22.

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

## Hasil final R66 — Actions #919

<badge color="success">SDK PASS</badge> <badge color="success">MT7621 QEMU PASS</badge>

Run: [Actions #919 — \`45944954879\`](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45944954879)  
Source SHA: \`41b101378ebda17e211d03be7ea7e7709f04f0ab\`

Kedua job (\`sdk\` dan \`vm\`) berakhir **SUCCESS** pada source SHA yang sama. Semua langkah wajib SDK dan seluruh langkah VM selesai tanpa gagal; hanya job bandwidth datapacket opsional yang dilewati.

Validasi package:
- IPK dibangun: \`passwall-ssh-core_1.0.0-r66_mipsel_24kc.ipk\`
- Control metadata diverifikasi sebagai \`Version: 1.0.0-r66\`.
- SHA-256 IPK: \`3b67a40af48c532d3bd61394a843ec90504fb5123379a89254a1f78e956e3d9f\`
- SDK artifact ID: \`15174341956\`
- QEMU/guest artifact ID: \`15174981023\`

Validasi crypto dan guest:
- Source gate R66 lulus: R64 in-place AES-CTR + copy aktif, R65-B HMAC context reuse aktif, patch marker R65-C/D/E tidak ada.
- Helper AES-CTR MIPS lulus **72 kasus**: bulk, in-place, loop 16-byte, irregular split, dekripsi, offset/alignment, dan counter-wrap.
- Helper HMAC-SHA256 lulus untuk **2 arah × 2.048 pesan**.
- AES-CTR **non-ETM dan ETM** sama-sama lulus transfer checksum; log verifikasi memastikan cipher ternegosiasi pada kedua arah, bulk-only counters, dan counter reuse HMAC.
- Default SSH cipher tetap \`chacha20-poly1305@openssh.com\`; TLS 1.3 berhasil menegosiasikan \`TLS_CHACHA20_POLY1305_SHA256\`.
- Uji single SSH session dengan 4 klien SOCKS menyelesaikan 4 × 32 MiB, semua SHA-256 cocok, aggregate **12.675 MiB/s** pada MT7621 QEMU.
- Uji TCP full-duplex, half-close, reconnect setelah RST, serta uji TLS/SNI juga lulus.

Artifact:
- [IPK OpenWrt 24.10.7 mipsel_24kc](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45944954879/artifacts/15174341956)
- [Hasil integrasi MT7621 QEMU](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45944954879/artifacts/15174981023)

## Lingkup release R66

1. Package release OpenWrt ditetapkan ke **1.0.0-r66**.
2. Mempertahankan R64 in-place AES-CTR + copy serta R65-B HMAC context reuse.
3. Mempertahankan R65-A diagnostics; timer/counter tetap mengikuti flag diagnostics.
4. Workflow final tidak menjalankan patcher R65-C/D/E.
5. SDK, IPK, dan firmware MT7621 QEMU divalidasi dalam satu workflow run dan satu source commit.
6. Source gate R66 mencegah regresi jalur crypto final serta salah versi IPK/artifact.

## R67-DIAG — instrumentasi antrean

R67-DIAG mempertahankan profil kriptografi, jalur relay, ukuran buffer, worker, dan kebijakan backpressure R66 tanpa perubahan perilaku transfer. Perubahannya hanya diagnostik yang aktif melalui `-log-perf 1`:

- Snapshot kernel TCP upstream: Recv-Q dan Send-Q.
- Snapshot kernel TCP untuk setiap SOCKS relay client: Recv-Q dan Send-Q, termasuk jumlah sampel sukses/gagal dan nilai agregat/puncak.
- Untuk transport TLS, snapshot socket dilakukan melalui API TLS Engine agar ownership socket tetap pada thread TLS; dua ring buffer TLS juga dicatat.
- Baris `[QUEUE]` dikeluarkan bersama interval `[PERF]`; tanpa `LOG_PERF`, pengambilan snapshot tidak berjalan.

Tujuan diagnostik adalah membedakan penumpukan pada socket upstream, ring buffer TLS, ring S2C/C2S, dan socket SOCKS. Nilai Recv-Q/Send-Q merupakan snapshot sesaat, bukan counter byte kumulatif.

**R67-DIAG adalah build diagnostik, bukan optimasi throughput.** Hasil benchmark hardware harus dibandingkan dengan R66 pada kondisi client dan durasi yang sama.

## Status

**R67-DIAG — SDK/QEMU validation pending.**
