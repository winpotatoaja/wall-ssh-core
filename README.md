# R68 — Passwall SSH Core Queue Accounting

Tanggal: 2026-11-27  
Branch: **experiment/r68-queue-accounting**  
Basis source: R67-DIAG commit `b12970a1095169447a7ce358e4a5c642dbf7d95c`  
Basis crypto: R65-B commit `dc0454d93a93afc94e8024f6346b54eb3ccd07d7`  
Paket: **1.0.0-r68**

## R68 — koreksi accounting antrean libssh2

R68 memulai perbaikan diagnostik antrean yang ditemukan saat audit R67:

- `packet_queue_bytes_current` dan `packet_queue_enqueued_bytes` memakai satuan payload yang belum dikonsumsi, bukan ukuran paket termasuk header SSH.
- Hook enqueue memakai `packet->data_len - packet->data_head`. Untuk CHANNEL_DATA ini mengecualikan 9 byte framing; untuk EXTENDED_DATA mengecualikan 13 byte. Paket kontrol dengan `data_head == 0` tetap dihitung seluruhnya.
- Jalur partial read mengurangi byte yang benar-benar dikonsumsi; packet-ask dan channel-flush mengurangi payload yang tersisa saat node dihapus.
- Baseline saat diagnostics diaktifkan tetap dihitung dari `data_len - data_head`, sehingga konsisten dengan accounting setelah enable.

Regression R68-A/B menguji satuan payload serta lifecycle enqueue/consume/dequeue dan invariant snapshot/reset. Pada Actions #935, native regression, generated-source libssh2 1.11.1, build SDK/IPK, serta integrasi runtime MT7621 QEMU lulus; kedua job SUCCESS dan guest melaporkan `MIPS TEST STATUS: 0`.

R68-A sampai R68-D telah lulus validasi native/source, SDK, serta MT7621 QEMU. R68-D menambahkan umur episode ring S2C dan snapshot `TCP_INFO`/`SIOCOUTQNSD`, tetap hanya saat `-log-perf 1`. Actions #951 membuktikan kedua job SDK dan VM SUCCESS serta guest `MIPS TEST STATUS: 0`. Pada fixture backpressure, ring S2C mencapai 256 KiB dan kernel Send-Q/not-sent mencapai sekitar 2,56 MB, dengan umur episode sekitar 1,43–1,50 detik. Belum ada perubahan scheduler atau optimasi transfer.

## Roadmap pengerjaan R68-A sampai R68-E

Urutan ini memisahkan koreksi accounting, pembuktian invariant, instrumentasi tambahan, dan keputusan optimasi. Tahap B wajib diselesaikan sebelum data diagnostik C/D dijadikan dasar keputusan.

| Tahap | Pekerjaan | Status / keputusan |
|---|---|---|
| **R68-A** | Koreksi counter libssh2 yang sebelumnya memasukkan header 9 byte (CHANNEL_DATA) dan 13 byte (EXTENDED_DATA) ke hitungan payload | **Selesai dan tervalidasi.** Bug accounting diperbaiki; helper native dan source libssh2 1.11.1 hasil patch lulus, IPK r68 berhasil dibangun, dan integrasi MT7621 QEMU lulus. |
| **R68-B** | Uji seluruh lifecycle packet dan invariant snapshot | **Lulus native, generated-source, SDK, dan MT7621 QEMU.** Actions #935: kedua job SUCCESS; guest `MIPS TEST STATUS: 0`. |
| **R68-C** | Telemetry kondisi dan fairness TLS worker | **Lulus native, source, SDK, dan MT7621 QEMU (Actions #949).** `[TLSFAIR]` runtime tervalidasi; ditemukan pola RX-preferred saat dua arah siap dan antrean TLS RX/S2C yang perlu ditelusuri di R68-D. |
| **R68-D** | Durasi antrean S2C, TCP_INFO, dan SIOCOUTQNSD | **Lulus native/source, SDK, dan MT7621 QEMU (Actions #951).** `[S2CAGE]` dan `[TCPINFO]` tervalidasi; SIOCOUTQNSD tersedia pada guest dan sampel active-backpressure menunjukkan antrean kernel not-sent. Diagnostik saja. |
| **R68-E** | Analisis hasil sebelum optimasi | **Belum dilakukan.** Gabungkan hasil A/B/C/D, identifikasi lokasi bottleneck berdasarkan bukti, lalu tentukan apakah optimasi memang diperlukan. Tidak ada optimasi spekulatif sebelum tahap analisis ini. |

**Aturan R68:** A memperbaiki satuan accounting; B wajib membuktikan lifecycle dan invariant sebelum instrumentasi lanjutan dipakai. C dan D hanya mengumpulkan bukti, bukan tuning performa. E menjadi gerbang keputusan. Tidak ada perubahan cipher, buffer, scheduler, worker, prioritas RX/TX, atau kebijakan backpressure dalam tahapan diagnostik ini.

## Progress pengerjaan R68

**Update: 2026-11-27**

| Pemeriksaan | Status | Catatan |
|---|---|---|
| Branch R68 dari R67-DIAG | Selesai | `experiment/r68-queue-accounting` |
| R68-A: koreksi enqueue menjadi payload tersisa | Selesai | Counter memakai `data_len - data_head`; header DATA 9 byte dan EXTENDED_DATA 13 byte tidak ikut dihitung |
| R68-A: helper regression native | Lulus | Actions #934: helper C aktual hasil ekstraksi template patch diuji dengan GCC |
| R68-A: integrasi source libssh2 1.11.1 hasil patch | Lulus | Semua assertion R68 source-level lulus untuk packet.c, channel.c, session.c, dan libssh2_priv.h |
| R68-B: lifecycle packet yang sudah dicakup | Lulus untuk kasus saat ini | Enqueue, partial read, packet-ask, channel-flush, DATA 9-byte header, EXTENDED_DATA 13-byte header, control packet, cumulative bytes, dan peak |
| R68-B: regression snapshot/lifecycle | **Lulus native + generated source + SDK** | Semua case enable baseline, snapshot reset=0/1, reset kosong/nonkosong, peak rebase ke current, re-enable, disable, NULL arguments, underflow, dan packet drain setelah reset lulus di Actions #935 |
| R68-C: telemetry TLS worker fairness | **Lulus native + source + SDK + QEMU** | Actions #949: native duplex 4 MiB tiap arah, reset/NULL invariants, `[TLSFAIR]` runtime log lulus. RX ring full hingga 103 observasi per interval aktif; antrean kernel upstream dan SOCKS Send-Q ikut terekam |
| R68-D: umur antrean S2C + TCP_INFO + SIOCOUTQNSD | **Lulus native + source + SDK + QEMU** | Actions #951: runtime verifier TCP/TLS menerima `[S2CAGE]` dan `[TCPINFO]`; umur episode aktif 1,43–1,50 s, S2C ring 256 KiB, kernel not-sent hingga 2.556.032 byte; TCP_INFO/SIOCOUTQNSD tidak gagal |
| R68-E: analisis sebelum optimasi | Belum dilakukan | Menunggu sintesis bukti A/B/C/D; belum ada optimasi |
| Source gate profil crypto final + identitas paket R68 | Lulus | Profil R64/R65-B/R66 tetap dijaga; ekspektasi release/artifact disesuaikan ke r68 |
| Build package SDK OpenWrt 24.10.7 / IPK R68 | **Lulus** | Actions #934 dan #935; IPK `1.0.0-r68`, metadata dan checksum diverifikasi |
| QEMU MT7621 | **Lulus** | Actions #934 dan #935; #935 kedua job SUCCESS, guest `MIPS TEST STATUS: 0`, TCP/TLS duplex, half-close, multi-client dan checksum checks lulus |
| Benchmark throughput / Datapacket Internet benchmark | Belum dijalankan | Tidak ada benchmark bandwidth opsional dan tidak ada tuning performa R68 |

### Detail kegagalan Actions #933

Run: [Actions #933 — `45981132744`](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45981132744)  
Commit pemicu: `63810db3a20d9ed51bc68546f81dcf0e4e3b4abe`

Yang sudah lulus sebelum job berhenti:
- Native regression relay-core/SPSC, termasuk regression helper R68.
- Download dan verifikasi checksum OpenWrt 24.10.7 SDK.
- Regression R68 terhadap source libssh2 1.11.1 yang sudah menerima patch R43.
- Pemeriksaan source crypto dan transport yang dijalankan sebelum final profile gate.

Penyebab dua assertion gagal:
- `OpenWrt package release is exactly r66`
- `SDK/VM artifact names and embedded IPK metadata target r66`

Keduanya merupakan ekspektasi versi/nama dari source gate final R66 yang belum disesuaikan untuk cabang paket R68. Tidak ada assertion accounting R68 yang gagal pada log run ini. Karena shell menggunakan fail-fast, build IPK R68 tidak mencapai tahap selesai; job VM/QEMU kemudian berstatus skipped.

**Perbaikan source gate:** commit `94042ba13363f46729fe106bae510b4f3ce97f5f` mengubah ekspektasi release/artifact stale menjadi identitas paket R68 pada `tests/r66_final_profile_source_test.py`. Pemeriksaan profil crypto final tetap utuh: R64 in-place AES-CTR + copy, R65-B HMAC context reuse, dan absennya patcher eksperimen R65-C/D/E.



### R68-B — cakupan regression yang ditambahkan

Harness `tests/r68_packet_queue_accounting_test.py` kini mengompilasi helper queue dan implementasi `libssh2_session_diag_timing_enable()` / `libssh2_session_diag_timing_snapshot()` langsung dari template patch R43 yang digunakan untuk menghasilkan source libssh2. Model list kecil hanya menyediakan struktur list/session; fungsi C yang diuji tetap diambil dari template aktual.

Matriks tambahan:
- Enable dari queue yang sudah berisi DATA, EXTENDED_DATA, dan control packet; baseline current serta peak harus sama dengan jumlah unread payload.
- Snapshot `reset=0` harus mengembalikan data tanpa mengubah current/peak/cumulative counters.
- Snapshot `reset=1` saat queue kosong harus mengembalikan interval sebelumnya lalu mengosongkan cumulative counters dan merebase peak ke current (nol).
- Snapshot `reset=1` saat queue masih berisi data harus mempertahankan current, menghapus cumulative totals, dan merebase peak ke current yang tersisa, bukan mempertahankan peak interval lama.
- Setelah reset, packet drain tetap harus mencapai current nol tanpa mengubah high-water mark interval baru.
- Re-enable harus membangun ulang baseline dari packet list dan membersihkan counter lama; disable harus mengosongkan counter dan mematikan tracking.
- API snapshot menolak pointer NULL; over-consume/duplicate dequeue tidak boleh menyebabkan unsigned counter wrap.
- Integrasi source memeriksa bahwa `session.c` hasil patch memuat persis API enable/snapshot yang dikompilasi dan diuji oleh native harness.

Test tambahan ini belum dianggap lulus sampai job CI R68 selesai.

### Hasil validasi R68-B — Actions #935 (SDK/source)

Run: [Actions #935 — `45987495420`](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45987495420)  
Source SHA: `0889a47063e8cb3b76a45c0eb1818248ac88b11c`

<badge color="success">Native regression PASS</badge> <badge color="success">Generated-source integration PASS</badge> <badge color="success">SDK/IPK PASS</badge>

Bukti R68-B yang sudah lulus:
- Native harness mengekstrak helper packet queue dan API enable/snapshot aktual dari template patch R43, mengompilasinya dengan GCC `-Wall -Wextra -Werror`, lalu menjalankan seluruh skenario lifecycle.
- Baseline saat enable dihitung dari unread payload: DATA 9-byte header, EXTENDED_DATA 13-byte header, dan control packet.
- Snapshot `reset=0` tidak mengubah counter live; `reset=1` mengembalikan nilai interval sebelum reset, mempertahankan current, mengosongkan cumulative totals, dan merebase peak ke current.
- Reset saat antrean kosong maupun saat masih ada packet, drain setelah reset, re-enable/disable, NULL arguments, dan saturating underflow lulus.
- Generated source libssh2 1.11.1 diverifikasi: enqueue, partial read, packet unlink, packet-ask, flush, enable baseline, dan API snapshot sesuai template yang diuji.
- SDK OpenWrt 24.10.7 / mipsel_24kc berhasil membangun OpenSSL, libssh2, dan IPK R68; source gate final crypto tetap lulus.

**Status QEMU Actions #935: PASS.** Job SDK dan VM sama-sama berakhir SUCCESS. Guest memasang IPK `1.0.0-r68` pada `mipsel_24kc`, melewati regression TCP/TLS multi-client, ChaCha default, AES-CTR, half-close dan full-duplex dengan verifikasi checksum, lalu melaporkan `MIPS TEST STATUS: 0`. Ini adalah validasi MT7621 QEMU, bukan pengujian router fisik.

### R68-C — telemetry fairness TLS Engine

R68-C mempertahankan TLS Engine sebagai satu pemilik `SSL*`; jalur transfer dan prioritas RX tetap tidak diubah. Saat `-log-perf 1` aktif, SSH Owner membaca snapshot counter atomik per interval dan menulis `[TLSFAIR]`. Metrik meliputi poll wait/wakeup, kesiapan socket dua arah, RX/TX calls/bytes/service time, WANT_READ/WANT_WRITE, burst sukses berturut-turut, antrean lintas arah, dan observasi ring RX penuh. `rx_service_us`/`tx_service_us` adalah durasi service operasi, bukan CPU time; burst maksimum adalah jumlah operasi sukses berurutan, bukan byte.

Snapshot memakai counter 32-bit, reset interval atomik, dan tidak melakukan socket I/O atau operasi SSL. Regression native menguji transfer duplex 4 MiB per arah dan reset/NULL invariants; source gate memastikan telemetry diaktifkan sebelum thread dimulai dan hanya lewat `LOG_PERF`; runtime verifier memastikan `[TLSFAIR]` benar-benar tercatat dalam log TLS MT7621.

### Hasil validasi R68-C — Actions #949

Run: [Actions #949 — `45995903871`](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45995903871)  
Source SHA: `26fd5a54f8b03f80ffd4c23c2e6d4f736c865803`  
**SDK: SUCCESS · MT7621 QEMU: SUCCESS · MIPS TEST STATUS: 0**

- Native TLS Engine test: `poll=887`, `rx_bytes=4194304`, `tx_bytes=4194304`, `rx_burst_max=4`, `tx_burst_max=3`. Snapshot reset mengembalikan interval lama dan interval berikutnya kosong; argumen NULL menghasilkan `EINVAL` seperti yang diwajibkan.
- Generated-source/source gate lulus. OpenWrt 24.10.7 `mipsel_24kc` membangun IPK `1.0.0-r68`; SHA-256 `ee020bfde3789d15c03a7eac43c4b2bfdd582a34cbca37e79b1f7c417a07e318`. [IPK artifact](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45995903871/artifacts/15196580554) · [QEMU runtime artifact](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45995903871/artifacts/15196133157).
- Guest runtime verifier lulus: `TLSFAIR interval poll=27 rx_bytes=1839 tx_bytes=1641 rx_burst_max=2 tx_burst_max=2`. Selain itu log selama 4 klien TLS/SNI memperlihatkan interval download 1.098 s dengan RX `17,709,104` byte, TX `3,312` byte, RX service `564,865 us`, dan TX service `24,719 us`.
- Pada contoh download tersebut, `poll_both=183`, `rx_both_ready=183`, `tx_both_ready=0`, sementara TLS RX ring mencapai `262,144/262,144` byte dan upstream kernel Recv-Q `301,351` byte. Pola serupa muncul pada beberapa interval multi-client: pembacaan RX diprioritaskan saat kedua readiness muncul; TX tetap berjalan pada event writable berikutnya. Nilai `tx_both_ready=0` konsisten dengan urutan RX-first yang memang ada di loop, bukan counter yang tidak terpasang.
- Pada satu interval full-duplex 1.88 s, TLS RX `1,544,704` byte dan TX `8,936,060` byte; `poll_both=171`, `rx_ring_full=15`, S2C ring mencapai `262,144` byte dan SOCKS kernel Send-Q `2,556,032` byte. Ini menunjukkan jalur dua arah aktif, tetapi snapshot akhir interval menangkap tekanan antrean S2C/client-send.
- Sebagian besar interval bulk tidak menunjukkan WANT_READ/WANT_WRITE yang berulang. Asimetri byte RX/TX pada download/upload sesuai arah payload test dan tidak boleh dibaca sebagai pembagian CPU antar-thread.

**Analisis / keputusan:** R68-C lulus sebagai instrumentasi diagnostik, bukan sebagai optimasi atau benchmark bandwidth Internet. Bukti mengarah ke dua tempat yang perlu diberi umur antrean dan konteks TCP: TLS RX ring/upstream Recv-Q saat download dan S2C ring/SOCKS Send-Q saat full-duplex atau client lambat. R68-D tepat dilanjutkan untuk umur data S2C serta `TCP_INFO`/`SIOCOUTQNSD`; jangan mengubah scheduling hanya dari hitungan `poll_both` ini.

### Hasil validasi berhasil — Actions #934

Run: [Actions #934 — `45982721268`](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45982721268)  
Source SHA: `2f2af74b7db68c9cd13e569ecb577fae302f19e7`

<badge color="success">SDK PASS</badge> <badge color="success">MT7621 QEMU PASS</badge>

**SDK dan IPK**
- OpenWrt SDK: **24.10.7**, target **ramips/mt7621**, ABI **mipsel_24kc**.
- OpenSSL **3.0.22** dan libssh2 **1.11.1** berhasil dibangun dengan patch diagnostik/crypto yang diperlukan.
- Native regression relay-core/SPSC, regression helper accounting R68, integrasi R68 ke source libssh2, dan source gate profil crypto final seluruhnya lulus.
- IPK: `passwall-ssh-core_1.0.0-r68_mipsel_24kc.ipk`.
- Metadata `Package`, `Version: 1.0.0-r68`, dan `Architecture: mipsel_24kc` diverifikasi.
- SHA-256 IPK: `cbcb8dfbcd5b1d2c686cd5d7c6370754323917194f8bac9616932fd721940563`.

**Guest MT7621 QEMU**
- IPK r68 berhasil diunduh, checksum diverifikasi, lalu dipasang oleh `opkg` sebagai `1.0.0-r68`.
- Runtime integration berakhir dengan `MIPS TEST STATUS: 0`.
- Satu SSH session TCP melayani 4 klien SOCKS secara bersamaan; 4 × 32 MiB selesai dan seluruh SHA-256 cocok.
- Satu SSH session TLS/SNI melayani 4 klien pthread; semua transfer dan SHA-256 cocok. TLS menegosiasikan `TLSv1.3 / TLS_CHACHA20_POLY1305_SHA256`.
- AES-128-CTR non-ETM dan ETM lulus transfer checksum serta pemeriksaan cipher dua arah dan bulk counters.
- Pemeriksaan QUEUE TCP dan TLS lulus; TCP half-close, TLS half-close, upload 8 MiB setelah EOF, dan full-duplex upload 8 MiB / download 32 MiB juga lulus.

Catatan: tes transfer di atas merupakan functional/integration checks dengan verifikasi isi; **bukan benchmark throughput**. Datapacket Internet bandwidth benchmark sengaja tidak dijalankan. QEMU pass juga tidak berarti uji hardware router fisik telah dilakukan.

Artifact:
- [IPK R68 dan hasil SDK (artifact #15189988439)](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45982721268/artifacts/15189988439)
- [Hasil integrasi guest MT7621 QEMU (artifact #15190004476)](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45982721268/artifacts/15190004476)



### R68-D — umur episode S2C dan TCP/kernel send queue

R68-D menambahkan diagnostik read-only pada SSH Owner, hanya ketika -log-perf 1 aktif:

- s2c_nonempty_since_ns dimulai pada transisi ring S2C kosong menjadi berisi data, baik melalui jalur pending-read maupun relay pump. Timer dibersihkan saat jalur flush klien membuat ring kosong kembali.
- [S2CAGE] melaporkan jumlah client relay yang saat snapshot masih memiliki data, jumlah sampel umur, umur rata-rata, dan maksimum dalam mikrodetik.
- Definisi umur: ini adalah durasi episode ring tetap non-empty sejak transisi kosong-ke-terisi, bukan timestamp individual untuk setiap byte dan bukan akumulasi semua episode yang selesai di antara dua snapshot. Interpretasikan sebagai umur episode antrean yang masih aktif saat interval diamati.
- [TCPINFO] mengambil getsockopt(TCP_INFO) pada socket SOCKS yang dimiliki SSH Owner. Pembacaan memvalidasi panjang struktur sebelum memakai field RTT, RTT variance, unacked segments, send congestion window, dan total retransmission.
- SIOCOUTQNSD diambil secara terpisah dari SIOCOUTQ. Fitur dikompilasi hanya jika macro tersedia; record menyebut support flag, jumlah sampel, dan kegagalan ioctl. Nilainya menunjukkan data pada TCP send queue yang belum dikirim, bukan jumlah byte yang sudah diakui peer.
- Semua pengukuran bersifat observasional. Tidak ada perubahan pada send, receive window, backpressure, ring capacity, scheduler, cipher, maupun worker topology.

### Hasil validasi R68-D — Actions #951

Run: [Actions #951 — 46000210513](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/46000210513)  
Source SHA: 171fb772a8e1bd8cfb07c0973ba6eb88e37daf20  
**SDK: SUCCESS · MT7621 QEMU: SUCCESS · MIPS TEST STATUS: 0**

- Native/source regression lulus. Source gate memeriksa dua jalur enqueue S2C, jalur flush, pembacaan panjang struktur TCP_INFO, compile-time fallback SIOCOUTQNSD, serta LOG_PERF gating. Runtime verifier menerima record TCP dan TLS untuk [S2CAGE] dan [TCPINFO].
- IPK OpenWrt 24.10.7 / mipsel_24kc: passwall-ssh-core_1.0.0-r68_mipsel_24kc.ipk; metadata 1.0.0-r68. SHA-256: 60cc28ddb9943bac9d689a1b7a97bda58cb450b73a7d5ced77ea20cf76668956.
- Artifact IPK: [#15197269934](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/46000210513/artifacts/15197269934). Artifact hasil MT7621 QEMU: [#15198965861](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/46000210513/artifacts/15198965861).
- Pada satu interval TCP dengan tekanan penerima terkontrol: S2C ring 262,144/262,144 byte, umur episode 1,503,966 us, SOCKS Send-Q 2,556,032 byte, dan SIOCOUTQNSD juga 2,556,032 byte. Snapshot TCP_INFO menunjukkan RTT 9,623 us, RTT variance 17,007 us, unacked 0, congestion window 10 segmen, dan retransmission 0.
- Pada satu interval TLS: S2C ring kembali 262,144/262,144 byte, umur episode 1,429,447 us, SOCKS Send-Q dan not-sent sama-sama 2,556,032 byte. TCP_INFO mencatat RTT 7,804 us, RTT variance 14,316 us, unacked 0, dan retransmission 0.
- SIOCOUTQNSD dilaporkan tersedia pada guest; sampel runtime tidak mencatat kegagalan ioctl TCP_INFO maupun not-sent. Kecocokan nilai SIOCOUTQ dan SIOCOUTQNSD pada snapshot aktif menunjukkan sebagian besar antrean send tersebut masih berada di sisi not-yet-sent kernel, bukan data yang sedang menunggu retransmission. Ini konsisten dengan skenario backpressure penerima yang disengaja dalam fixture QEMU; bukan bukti packet loss atau klaim bahwa semua koneksi produksi selalu memiliki kondisi yang sama.

**Analisis / keputusan:** R68-D berhasil menangkap episode S2C aktif dan membedakan antrean aplikasi dari antrean TCP yang belum dikirim. Pada fixture ini, tekanan paling jelas berada di ring S2C dan send queue lokal menuju klien, sementara snapshot aktif tidak menunjukkan retransmission. Hasil ini belum membuktikan sumber jeda pada jaringan/hardware nyata; QEMU bukan uji router fisik dan validasi ini bukan benchmark throughput Internet. Lanjutkan ke R68-E untuk menyatukan bukti R68-A/B/C/D sebelum menentukan apakah ada optimasi yang didukung data.

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

**R68-A/B/C/D selesai dan tervalidasi pada native/source/SDK/MT7621 QEMU (Actions #935, #949, dan #951). R68-D merekam episode S2C hingga 1,50 s dan kernel not-sent hingga 2,56 MB pada fixture backpressure. R68-E menjadi tahap berikutnya untuk analisis gabungan sebelum optimasi. Tidak ada tuning performa atau benchmark Internet pada R68-D.**
