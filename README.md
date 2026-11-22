# Passwall SSH Core — Progres Pengerjaan Tahap 1–5

Dokumen ini adalah **catatan progres utama proyek**. Semua pekerjaan, hasil validasi,
keputusan, dan pekerjaan tersisa dicatat berdasarkan lima tahap di bawah. Status
hanya boleh dinaikkan menjadi **LULUS** setelah seluruh kriteria tahap tersebut
dibuktikan oleh hasil pengujian yang tercatat.

Terakhir diperbarui: 2026-11-22  
Branch pengerjaan: `phase3/io-worker-pool-foundation`

## Ringkasan status

| Tahap | Fokus | Status |
|---|---|---|
| 1 | Fondasi koneksi dan arsitektur single SSH session | **LULUS** |
| 2 | TLS Engine, pemisahan kepemilikan TLS/SSH, dan fondasi antrean | **LULUS** |
| 3 | Integrasi local socket I/O worker ke relay aktif | **LULUS** |
| 4 | Validasi terpadu, perbaikan, tuning, dan retest throughput | **PERLU RETEST PERFORMA** |
| 5 | Validasi perangkat OpenWrt MT7621 fisik | **BELUM DIMULAI** |

> Status di atas menggambarkan keadaan source dan catatan pengujian yang tersedia.
> Build atau cross-compile saja tidak sama dengan keberhasilan runtime QEMU, dan
> keberhasilan QEMU tidak menggantikan pengujian pada router fisik.

---

## Aturan pencatatan progres

Setiap kali satu tahap atau sub-tahap selesai dan lolos:
1. Ubah status tahap/sub-tahap di README ini pada batch perubahan yang sama.
2. Catat perubahan kode atau konfigurasi yang benar-benar selesai.
3. Catat perintah/workflow dan target pengujian: native, OpenWrt SDK MIPS,
   QEMU MIPS, QEMU x86_64, atau perangkat MT7621.
4. Catat hasil aktual, commit/source SHA, serta tautan atau nomor GitHub Actions run
   bila tersedia.
5. Tuliskan masalah yang belum selesai dan kriteria kelulusan berikutnya.
6. Jangan tandai **LULUS** jika pengujian dilewati, timeout, gagal, memakai artifact
   dari source SHA berbeda, atau hasilnya belum dapat diverifikasi.

Pekerjaan yang belum lolos boleh dicatat sebagai selesai di sisi implementasi,
tetapi status validasinya harus tetap terbuka. README diperbarui bersama batch
perubahan yang relevan; tidak perlu membuat commit terpisah untuk setiap edit kecil.

## Prinsip arsitektur yang wajib dipertahankan

- Tepat satu koneksi upstream TCP/TLS dan satu autentikasi SSH per proses,
  terlepas dari jumlah CPU atau nilai konfigurasi worker lama.
- Satu SSH Owner menjadi satu-satunya pemilik dan pelaksana seluruh operasi
  `LIBSSH2_SESSION` dan channel. Operasi libssh2 tidak boleh dijalankan paralel.
- Satu TLS Engine menjadi satu-satunya pemilik `SSL*` dan I/O TLS.
- I/O worker hanya melakukan operasi socket lokal yang terbatas dan non-blocking.
  Worker tidak boleh mengakses `client_conn_t`, ring buffer, libssh2, atau TLS.
- Hasil worker dikirim kembali sebagai completion. SSH Owner memvalidasi identitas
  task/client/generation/worker sebelum mengubah state atau ring buffer.
- Maksimal satu operasi in-flight per client untuk setiap arah; C2S dan S2C
  mempunyai penanda serta task ID terpisah.
- Lifetime reference melindungi client dan FD sampai completion diterima atau
  dibatalkan secara aman. Penutupan FD dan pelepasan storage tidak boleh mendahului
  worker yang masih memegang referensi.
- Backpressure, partial I/O, half-close, reset, reconnect, dan shutdown harus
  mempertahankan integritas byte serta tidak menyebabkan use-after-free,
  double-release, atau FD reuse yang salah.

---

## Tahap 1 — Fondasi koneksi dan arsitektur single SSH session

<badge color="success">LULUS</badge>

**Tujuan:** memastikan proses menggunakan satu upstream SSH session dan seluruh
client SOCKS berbagi session tersebut melalui channel `direct-tcpip`.

Pekerjaan yang telah diselesaikan:
- Menetapkan satu koneksi upstream dan satu autentikasi SSH per proses.
- Menjaga operasi libssh2 tetap terserialisasi pada SSH Owner.
- Memastikan deteksi CPU dan konfigurasi worker lama tidak menggandakan login SSH.
- Menetapkan batas client dan perilaku dasar listener SOCKS.
- Mempertahankan kompatibilitas parameter launcher lama tanpa mengubah kebijakan
  satu session.

**Kriteria kelulusan:**
- Source dan pengujian memastikan satu upstream session per proses.
- Beberapa client SOCKS dapat memakai session yang sama.
- Jumlah CPU atau nilai worker tidak meningkatkan jumlah autentikasi SSH.

**Catatan:** tahap ini dinyatakan selesai berdasarkan progres proyek sebelumnya.
Jika perubahan berikutnya menyentuh kebijakan session, regresi tahap ini wajib
dijalankan kembali.

## Tahap 2 — TLS Engine dan fondasi komunikasi lintas thread

<badge color="success">LULUS</badge>

**Tujuan:** memisahkan kepemilikan TLS dari SSH Owner tanpa membuat operasi
libssh2 berjalan paralel.

Pekerjaan yang telah diselesaikan:
- TLS Engine pthread membuat, menggunakan, dan membebaskan `SSL*` secara eksklusif.
- SSH Owner tetap memiliki satu session libssh2 dan seluruh channel.
- Pertukaran plaintext menggunakan SPSC ring/queue dan notifikasi eventfd.
- Menangani handshake, record I/O, readiness retry, receive terminal, half-close,
  `close_notify`, dan shutdown TLS berbatas waktu.
- Menyediakan fondasi SPSC dengan indeks atomik dan pengujian wrap/rollover.

**Kriteria kelulusan:**
- TLS tidak diakses langsung dari SSH Owner.
- Operasi SSH tetap terserialisasi.
- Regression native, build MIPS SDK, dan validasi runtime yang menjadi bagian
  tahap ini telah diselesaikan pada progres sebelumnya.

**Catatan:** tahap ini dinyatakan selesai berdasarkan progres proyek sebelumnya.
Perubahan pada TLS Engine atau queue tetap harus menjalankan regression terkait.

## Tahap 3 — Integrasi local socket I/O worker ke relay aktif

### Validasi Stage 3 final

<badge color="success">LULUS FINAL</badge>

- Native regression dan OpenWrt 24.10.7 SDK `mipsel_24kc` lulus pada gate terbaru; SDK run `44978923453`, artifact IPK/test helper `14736718226`.
- Rollback-hardening source `f3a85dc43722bfb6f38045a70a1f16dffd3bdcc2` diuji pada MT7621 QEMU run `44980515142` (workflow/documentation head `cb07179b00363d685aabe9ca5e4468a6c7548b1f`); hasil guest `MIPS TEST STATUS: 0`, workflow `success`, artifact hasil `14737509442`.
- QEMU mencakup idle TCP RST, 8 SOCKS reconnect dengan exact 1 MiB dan SHA-256/FD reuse, TCP/TLS half-close, upload 8 MiB setelah remote EOF, full-duplex 8 MiB upload/32 MiB download, empat client TCP bersamaan, empat client TLS/SNI, dan graceful SIGTERM SSH/TLS shutdown.
- Audit source mengonfirmasi rollback C2S/S2C memeriksa cancel tracker dan lifetime release; completion memvalidasi identitas dan pelepasan reference; reaper hanya membebaskan storage setelah `client_lifetime_finalize()` berhasil.

**Kriteria Tahap 3 terpenuhi.** Tahap 3 ditutup sebagai LULUS. Tahap 4 tetap terpisah dan belum dianggap selesai.


<badge color="success">LULUS FINAL</badge>

**Tujuan:** memindahkan operasi socket lokal C2S dan S2C ke worker terbatas,
sementara SSH Owner tetap mengendalikan seluruh state client dan ring buffer.

Implementasi yang sudah ada pada branch ini:
- SSH Owner membuat bounded I/O worker pool dan mendaftarkan completion eventfd
  ke epoll.
- C2S client socket read dan S2C client socket write dikirim sebagai task worker.
- Task membawa salinan metadata/payload dan identitas immutable; worker tidak
  menerima pointer client atau ring buffer.
- Completion tracker mendaftarkan task sebelum task dipublikasikan ke worker.
- C2S bytes baru dimasukkan ke ring setelah completion tervalidasi.
- S2C payload disalin ke task; ring head/generation dipertahankan sampai completion,
  dan hanya byte yang benar-benar terkirim yang di-commit.
- Penanda in-flight dan task ID C2S/S2C terpisah.
- Client lifetime reference, retired-client list, dan deferred FD close melindungi
  client saat worker masih memegang task.
- Pool awal menggunakan **1 I/O worker** sebagai baseline. Ini berbeda dari
  konfigurasi worker proses lama dan bukan berarti empat I/O worker sudah aktif.

**Perbaikan source terbaru (native, SDK, dan QEMU tervalidasi):**
- Completion yang ditolak tracker karena task tidak dikenal (`ENOENT`) diperlakukan sebagai duplikat/stale dan diabaikan tanpa melepas reference lagi.
- Completion dengan identitas yang tidak cocok (`EPROTO`/error tracker lain), client-generation yang tidak ditemukan setelah tracker menerima task, kegagalan release lifetime, atau task tanpa arah in-flight yang cocok kini menjadi invariant failure. Drain mengembalikan error; SSH Owner menghentikan relay dengan exit status gagal, bukan melanjutkan dengan state yang tidak konsisten.
- Fallback socket I/O sinkron pada Owner hanya diizinkan ketika submit worker mengembalikan status antrean sementara (`1`/`EAGAIN`). Kegagalan submit internal (`-1`) tidak lagi disamarkan sebagai queue-full; client ditutup secara aman dan jalur flush S2C mengembalikan error ke pemanggil.
- Jalur drain saat shutdown/startup juga memeriksa hasil invariant. Native regression dan build OpenWrt 24.10.7 `mipsel_24kc` lulus pada Actions run `44964541444`; runtime MT7621 QEMU untuk source SHA `0f1d484604fb2d2f1d0e53ee5603f90fe71995f2` juga lulus pada run `44965112117` (artifact `14730729725`).
- Pemeriksaan workflow TLS kini memakai path eksplisit `$GITHUB_WORKSPACE/ssh-core.c` dan memverifikasi file ada, sehingga pemeriksaan tidak lagi dapat memberi PASS palsu ketika dijalankan dari direktori SDK.
- QEMU MIPS membuktikan transfer TCP 1 MiB, half-close 8 MiB, full-duplex 8 MiB upload/32 MiB download, upload C2S 32 MiB SHA-256, empat client download bersamaan masing-masing 32 MiB dalam satu SSH session, TLS/SNI dengan empat client download bersamaan, ChaCha20-Poly1305 TLS 1.3, TLS keepalive, half-close/full-duplex TLS, serta graceful SIGTERM/shutdown. Semua helper regression MIPS termasuk worker pool 50.000 task, eventfd re-arm, backpressure, lifetime, completion tracker, SPSC rollover, dan TLS Engine lulus; `MIPS TEST STATUS: 0`.

**Audit dan validasi yang masih wajib:**
- Menuntaskan audit semua jalur completion: sukses, partial write, EAGAIN,
  error terminal, completion stale/duplikat, dan identitas client yang tidak ditemukan.
- Membuktikan S2C kembali berjalan setelah EAGAIN dan setelah client melanjutkan
  pembacaan; memastikan EPOLLOUT/rearm tidak macet.
- Membuktikan C2S kembali berjalan setelah EAGAIN dan setelah ring memiliki ruang.
- Memastikan task yang diterima selalu berakhir dengan pelepasan lifetime reference
  tepat satu kali, termasuk jalur shutdown dan invariant failure.
- Memastikan timeout join tidak menyebabkan worker mengakses storage yang sudah
  dibebaskan atau FD yang sudah dipakai ulang.
- Regresi RST/reconnect/FD reuse kini ditambahkan pada workflow MT7621 QEMU: helper mengirim RST pada client idle saat fixture menunda body, lalu delapan transfer SOCKS baru berurutan memverifikasi byte dan SHA-256. **Workflow baru belum dijalankan pada source SHA ini.**
- Menyamakan cakupan assertion native, MIPS, dan QEMU.

**Gerbang kelulusan tahap 3:**
- Audit source selesai dan seluruh temuan kritis diperbaiki.
- Regression native lengkap lulus.
- Cross-build OpenWrt 24.10.7 `mipsel_24kc` lulus.
- Runtime QEMU MIPS menjalankan artifact yang cocok dengan source SHA dan seluruh
  assertion worker/relay lulus.
- Tidak ada task/reference tertinggal, ring buffer yang tidak terkuras, atau
  kegagalan integritas data pada skenario uji.

**Validasi source terbaru:**
- Native regression dan OpenWrt 24.10.7 `mipsel_24kc` SDK lulus pada run `44978923453` (SDK artifact `14736718226`).
- MT7621 QEMU run `44980515142` lulus menggunakan artifact SDK tersebut; workflow checkout commit `cb07179b00363d685aabe9ca5e4468a6c7548b1f`, dengan source rollback C2S/S2C dari `f3a85dc43722bfb6f38045a70a1f16dffd3bdcc2`.
- RST idle channel berhasil, lalu 8 reconnect SOCKS masing-masing memverifikasi payload 1 MiB dan SHA-256. Half-close dua arah, upload pasca-EOF 8 MiB, upload TCP 32 MiB, empat client TCP bersamaan 4 × 32 MiB, empat client TLS/SNI bersamaan, dan full-duplex upload 8 MiB/download 32 MiB lulus. `MIPS TEST STATUS: 0`.
- Artifact runtime QEMU: `14737509442`.

**Status saat ini:** Tahap 3 telah ditutup **LULUS FINAL** setelah native regression, MIPS SDK, MT7621 QEMU (`MIPS TEST STATUS: 0`), dan audit source/invariant selesai. Pekerjaan selanjutnya berada di Tahap 4.

## Tahap 4 — Validasi terpadu, perbaikan, dan tuning native/MIPS/QEMU

<badge color="warning">VALIDASI FUNGSIONAL LULUS — RETEST THROUGHPUT TERBUKA</badge>

### Retest internet 100 MiB dengan batas 50 detik — hasil terverifikasi

- Actions run `45067089485` selesai `success`; artifact `14771936584`.
- OVHcloud Singapore `https://sin1-sgp.speedtest.network.ovh.net/files/100Mb.dat`: direct menerima tepat `104.857.600` byte (100 MiB) dalam `37,297 s`, rata-rata curl `2,63 MiB/s`; SOCKS5 menerima tepat `104.857.600` byte dalam `30,494 s`, rata-rata curl `3,12 MiB/s`. Keduanya HTTP 200 dan pasangan byte identik.
- DigitalOcean endpoint `speedtest-sgp1.digitalocean.com` gagal resolusi DNS (`curl_rc=6`, 0 byte); bukan timeout 50 detik. Endpoint tersebut dihapus dari skrip dan diganti dengan Datapacket Singapore `http://sgp.download.datapacket.com/100mb.bin` untuk run berikutnya.
- Benchmark dijalankan dengan hard timeout 50 detik per request, connect timeout 15 detik, tanpa retry; endpoint direct yang gagal tidak dilanjutkan ke SOCKS5.
- Log core menunjukkan satu autentikasi password dan satu `Session Keys Established`; startup menegaskan `SSH_sessions=1`. Empat worker I/O tambahan tidak membuat sesi SSH tambahan. `errors.log` kosong.
- Ringkasan aktual disimpan dalam artifact; hasil OVH adalah bukti 100 MiB yang selesai, bukan proyeksi. Hasil Datapacket masih menunggu run setelah penggantian URL.

### Retest r39 S2C direct-send — SDK, MT7621 QEMU, dan benchmark 10 MB lulus; retest 100 MB disiapkan

- Native regression dan OpenWrt 24.10.7 `mipsel_24kc` SDK lulus pada run `45020186643`; IPK artifact `14753870688`, versi `1.0.0-r39`, source SHA `0d48d4e5d5d2298ed057d3e5af7fc147fec5f7a0`, SHA-256 `702b00fc6c5da703a9fb848f39e0a7418d7766df10746d960e5dca032eba9350`.
- MT7621 QEMU run `45020754464` berhasil; workflow artifact `14754055916`. Guest melaporkan `MIPS TEST STATUS: 0` dan menggunakan IPK r39 tersebut.
- CPU guest terdeteksi 4; log startup menegaskan `SSH_sessions=1`. Pool I/O lokal berisi 4 worker, tetapi setiap proses relay tetap hanya memakai satu upstream/session SSH.
- Empat client TCP menerima 128 MiB dengan checksum cocok, agregat `5.670 MiB/s`; empat client TLS juga menerima 128 MiB dengan checksum cocok, agregat `5.848 MiB/s`. Half-close dan full-duplex (8 MiB upload/32 MiB download) juga lulus.
- **Internet benchmark r39 10 MB lulus:** Actions run `45023412793` berstatus success; artifact `14755140496`. Keempat unduhan mendapat HTTP 200 dan ukuran penuh, tanpa retry; `errors.log` kosong.
- Cherry Servers `10.485.760` byte: direct `3,332163 s / 3,00 MiB/s`; lewat SOCKS5 `4,145460 s / 2,41 MiB/s`.
- NewMedia Express `10.000.000` byte: direct `3,123224 s / 3,06 MiB/s`; lewat SOCKS5 `3,959693 s / 2,41 MiB/s`.
- Rata-rata berbobot dari dua transfer: direct `3,03 MiB/s`; SOCKS5 `2,41 MiB/s`. SOCKS5 mencapai sekitar `79,6%` dari direct (selisih sekitar `20,4%`). Ini adalah pengukuran file pendek 10 MB, bukan klaim throughput berkelanjutan untuk transfer 100 MB atau lebih.
- Validasi session: startup core mencatat `SSH_sessions=1`; log core mencatat tepat satu `authentication accepted` dan satu `Session Keys Established`; host sshd mencatat satu autentikasi password sukses. Dua request SOCKS diproses berurutan di sesi yang sama. CPU guest terdeteksi 4 dan memilih 4 auxiliary I/O workers.
- S2C backpressure sempat memenuhi buffer 128 KiB dan kemudian terkuras sampai 0 pada kedua koneksi; tidak ada log ERROR/FATAL/invariant dan `errors.log` kosong.
- Hasil 10 MB ini adalah pengukuran file pendek. Retest 100 MB berikutnya menemukan bahwa transfer Vultr memang hanya sekitar 300 KB/s dan selesai sangat lambat; lihat catatan percobaan 100 MB serta kebijakan timeout/skip di bawah. Jangan mencampur angka dua jenis pengujian tersebut.
- Benchmark internet memakai dua file sekitar 10 MB dari server Singapura: Cherry Servers `https://speedtest.sg.cherryservers.com/test-10mb` (10.485.760 byte) dan NewMedia Express `https://sg1.newmediaexpress.com/10MB.test` (10.000.000 byte). Setiap file diunduh sekali direct dan sekali lewat SOCKS5, sehingga total payload target sekitar 40 MB untuk empat transfer.
- Batas pengaman benchmark 10 MB yang telah selesai: curl `--max-filesize 11000000`, `--max-time 120`, `--connect-timeout 15`, tanpa retry otomatis. Setiap transfer menerima minimal 9.500.000 byte dan jumlah byte direct/SOCKS5 identik.

- **Percobaan 100 MB pertama terukur lambat dan tidak lulus:** Actions run `45065615639`, artifact `14770769522`. Vultr Singapore mengirim `104.857.600` byte dalam `340,196` detik (`308.228 B/s`, sekitar `0,29 MiB/s`). Linode Singapore gagal sebelum menerima data (`curl_rc=28`, sekitar 15 detik, HTTP `000`), sehingga tahap SOCKS5 tidak dijalankan. Artefak juga mengonfirmasi tepat satu autentikasi SSH sukses pada host dan satu SSH session di core.
- **Retest 100 MB dengan endpoint alternatif disiapkan (hasil belum tersedia):** DigitalOcean Singapore `http://speedtest-sgp1.digitalocean.com/100mb.test` dan OVHcloud Singapore `https://sin1-sgp.speedtest.network.ovh.net/files/100Mb.dat`. DigitalOcean Singapore dicantumkan sebagai endpoint file uji 100 MB dalam daftar speedtest; halaman resmi OVHcloud Singapore mendokumentasikan file uji statis mulai 1 MiB sampai 10 GiB dan menyediakan URL file 100Mb.
- Batas keras setiap transfer adalah `50` detik (connect timeout `15` detik), file cap `110.000.000` byte, minimum hasil lengkap `95.000.000` byte, dan tanpa retry. Jika direct gagal/timeout, SOCKS5 endpoint yang sama dilewati; workflow lanjut ke endpoint berikutnya. Jika direct lolos tetapi SOCKS5 timeout, pasangan itu dicatat SKIP dan workflow tetap lanjut. Run dinyatakan lulus hanya jika minimal satu endpoint menyelesaikan pasangan direct+SOCKS5 dengan jumlah byte identik.
- Pengujian tetap hanya workflow bandwidth khusus, dengan satu proses core dan satu SSH session. Maksimum empat percobaan transfer; endpoint lambat tidak menahan job lebih dari 50 detik per request. Hasil 10 MB tetap data historis, bukan klaim throughput 100 MB.



**Tujuan:** membuktikan implementasi akhir pada target arsitektur, memperbaiki
regresi yang ditemukan, lalu melakukan tuning berdasarkan pengukuran.

Urutan kerja:
1. Jalankan regression terpadu native untuk baseline Tahap 4.
2. Build paket dengan OpenWrt 24.10.7 SDK untuk `mipsel_24kc`.
3. Jalankan paket hasil build tersebut di MT7621 QEMU; verifikasi artifact/source SHA.
4. Jalankan QEMU OpenWrt x86_64 sebagai pembanding bila workflow terkait berubah.
5. Evaluasi hasil throughput, CPU/thread, RSS, FD, queue occupancy, backpressure,
   retransmission, dan latensi; lakukan tuning hanya berdasarkan hasil terukur.
6. Setelah perubahan tuning, ulangi regression yang terdampak dan validasi akhir.

**Cakupan pengujian minimum:**
- Transfer dasar dan multi-client dengan satu SSH session.
- C2S upload dan S2C download berukuran besar dengan SHA-256 serta panjang byte tepat.
- S2C reader throttling dan C2S receiver stall/backpressure; ring harus pulih dan
  terkuras setelah sisi penerima melanjutkan operasi.
- Full-duplex upload/download secara bersamaan.
- Client-FIN-first dan server-FIN-first tanpa mematikan arah sebaliknya.
- RST/abort di tengah transfer, kemudian proxy tetap dapat melayani client baru.
- Reconnect berulang, pemeriksaan RSS dan jumlah FD, serta skenario FD reuse.
- SIGTERM/shutdown ketika worker sedang menjalankan task; semua thread harus selesai
  atau storage yang masih direferensikan harus tetap aman.
- Tidak ada mismatch checksum, byte hilang/ganda, ring tertahan, atau task reference
  yang tidak terselesaikan.

**Perbaikan diagnostik Tahap 4:** source commit `852c6f5dc8c4be9179e56f9cd1a47ec33fdf9068` mengecualikan client dengan `s2c_worker_inflight` dari hitungan `s2c_epollout_missing`, karena EPOLLOUT memang sengaja dilepas selama worker menulis. Perubahan ini mencegah false positive pada metrik, bukan mengubah jalur data.

**Validasi baseline Tahap 4 — lulus pada source code `e2f150f27b3218022559f15a59a4a6fd59de70c0`:**
- Native regression/parser: Actions run `44984703377`, berhasil.
- OpenWrt 24.10.7 `mipsel_24kc` SDK: run `44984703379`, berhasil; IPK artifact `14739159030`, SHA-256 `3f06e0e58bc654bef90bcbffd946b956d20a7755d28ad86bf45d5d813a2154f1`.
- MT7621 QEMU: run `44985100177`, workflow checkout `74bc19850024605d4f8d737f5cfbd57233744cfd` (perubahan setelah source code hanya dokumentasi); memakai SDK artifact di atas. Workflow `success`, guest `MIPS TEST STATUS: 0`; hasil artifact `14739727217`, SHA-256 `dd72bfa741231f69aa21ce9cce428aa47f4c67e6885255a777f00dfe9132a42a`.
- Empat client TCP masing-masing mengunduh 32 MiB: 128 MiB total, empat checksum identik dan benar, `workers=1`, `failures=0`, agregat `1.455 MiB/s` selama 87.952 s.
- Empat client TLS/SNI masing-masing mengunduh 32 MiB: 128 MiB total, empat checksum identik dan benar, `workers=1`, `failures=0`, agregat `1.554 MiB/s` selama 82.386 s.
- Satu autentikasi password SSH diterima pada setiap proses relay; worker log menunjukkan satu worker process (`Worker 1/1`). Nilai konfigurasi `WORKERS=2` bukan jumlah I/O worker; pool aktif tetap satu worker sesuai invariant implementasi.
- Sampel TCP (73 sampel): proses relay 2 thread, RSS 4,956–14,784 KiB; CPU process delta sekitar 136.6 CPU-second selama transfer 87.95 s (sekitar 1.55 core). Sampel TLS (70 sampel): 3 thread, RSS 5,876–15,532 KiB; CPU delta sekitar 132.4 CPU-second selama 82.39 s (sekitar 1.61 core). Angka CPU merupakan estimasi dari tick `/proc` 100 Hz, bukan pengukuran perf hardware.
- Metrik `s2c_epollout_missing=0` pada seluruh 392 interval PERF TCP. TCP retransmit counter: 8 segmen pada TCP dan 9 pada TLS. Backpressure S2C mengisi buffer 131,072/131,072 byte dan kemudian kembali ke 0; log TCP mencatat 15 kejadian penuh dan 14 drain, TLS 2 penuh dan 1 drain selama sampel.
- Ini adalah baseline pengukuran pertama pada beban empat client yang sama, bukan bukti peningkatan dibanding baseline lama yang memakai beban berbeda. Tidak ada tuning datapath yang diklaim atau dilakukan. Tidak ada dasar terukur untuk mengubah worker count/buffer saat ini; pertahankan satu worker dan gunakan angka ini sebagai baseline pembanding.

**Audit akhir dan keputusan tuning:**
- Audit source mengonfirmasi `s2c_worker_inflight` sengaja menonaktifkan EPOLLOUT selama worker write; metrik `s2c_epollout_missing` kini mengecualikan state tersebut. Jalur epoll mengaktifkan kembali EPOLLOUT setelah completion ketika masih ada data S2C. Ini sesuai dengan ownership worker dan tidak mengubah datapath.
- Seluruh 392 interval PERF TCP mencatat `s2c_epollout_missing=0`; tidak ada `epoll_ctl_add_fail`, `epoll_ctl_mod_fail`, atau errno pada interval akhir yang direkam. Backpressure S2C mencapai 128 KiB dan kembali kosong setelah client melanjutkan pembacaan.
- Regression guest mencakup worker pool 50.000 task/eventfd, completion tracker, client lifetime, token, SPSC, TLS Engine, TCP idle RST lalu delapan reconnect dengan SHA-256, TCP/TLS half-close, full-duplex, upload 32 MiB, empat client download bersamaan, TLS 1.3/SNI, dan graceful SIGTERM. Guest melaporkan `MIPS TEST STATUS: 0`.
- Keputusan: **tidak melakukan tuning datapath**. Pengukuran ini adalah baseline pertama untuk empat client pada satu SSH session; tidak ada A/B yang sebanding untuk membuktikan bahwa perubahan buffer, worker count, atau scheduler akan meningkatkan hasil. Mengubah parameter tanpa pembanding akan menjadi tebakan. Pertahankan satu I/O worker dan kapasitas queue saat ini sebagai baseline.
- QEMU TCG adalah validasi fungsional dan perbandingan relatif; throughput di emulator bukan prediksi throughput router MT7621 fisik.

**Status Tahap 4 diperbarui:** gerbang fungsional native, OpenWrt 24.10.7 MIPS SDK, dan MT7621 QEMU yang tercatat tetap lulus untuk source lama. Audit bandwidth internet kemudian menemukan batas payload S2C worker 120 byte/task yang menjelaskan throughput sekitar 500 KB/s. Karena itu validasi performa Tahap 4 dibuka kembali; status LULUS FINAL belum berlaku untuk datapath setelah temuan ini. Tahap 5 tetap membutuhkan pengujian pada router MT7621 fisik.

## Tahap 5 — Validasi perangkat OpenWrt MT7621 fisik

<badge color="secondary">BELUM DIMULAI</badge>

**Tujuan:** memastikan paket final berjalan stabil pada router MT7621 fisik,
bukan hanya pada emulator.

Prasyarat:
- Tahap 3 berstatus LULUS dan retest throughput Tahap 4 harus selesai sebelum Tahap 5.
- Paket IPK dibangun dari source SHA final yang telah divalidasi.
- Konfigurasi, akun/endpoint SSH, dan prosedur pemulihan router siap.

Rencana validasi perangkat:
- Instalasi, upgrade, restart service, dan uninstall/reinstall paket.
- Verifikasi arsitektur binary dan dependensi pada OpenWrt 24.10.7.
- Uji satu SSH session dengan beberapa client SOCKS bersamaan.
- Uji upload/download, full-duplex, backpressure, half-close, RST, dan reconnect.
- Uji operasi jangka panjang serta penggunaan CPU, RAM, thread, dan FD.
- Uji kestabilan ketika LTE/WAN terputus dan tersambung kembali bila skenario
  jaringan memungkinkan.
- Uji SIGTERM/restart service saat transfer aktif.
- Catat log, throughput, checksum, suhu/performa perangkat bila tersedia,
  serta seluruh kendala yang hanya muncul pada perangkat fisik.

### Sub-tahap: penskalaan I/O worker berdasarkan CPU — LULUS

Tujuan tambahan sebelum validasi perangkat fisik adalah memakai kapasitas CPU yang
tersedia untuk operasi socket client tanpa menggandakan sesi SSH.

Implementasi pada source:
- Deteksi CPU memakai affinity/cpuset proses terlebih dahulu, lalu fallback ke
  jumlah CPU online melalui `sysconf`.
- Jumlah I/O worker otomatis = jumlah CPU yang terdeteksi, dibatasi 1–4 worker.
- Pool dan completion tracker memakai jumlah worker runtime yang sama; seluruh
  completion eventfd didaftarkan ke epoll dan semua worker dipantau saat idle.
- Tetap hanya ada satu SSH Owner, satu upstream TCP/TLS, dan satu autentikasi/
  sesi SSH. Opsi legacy `-workers` tidak mengubah jumlah sesi SSH.
- Log CPU mempertahankan format diagnostik single-session yang dipakai regression
  harness; jumlah auxiliary I/O worker dilaporkan pada baris `[IO worker]` terpisah.
- Worker tetap hanya menjalankan operasi socket client; libssh2 dan TLS Engine
  tetap berada pada owner masing-masing.

Status: **LULUS pada native, MIPS SDK, dan MT7621 QEMU**.

- Regression mapping CPU→I/O worker lulus untuk input 1/2/3/4 dan nilai di luar
  rentang; pemetaan 1/2/3/4 worker dan cap maksimum 4 diverifikasi.
- Native regression dan OpenWrt 24.10.7 MIPS SDK lulus pada run
  `44987910879`. Artifact IPK `14740154895`, 897,968 byte, SHA-256
  `ef506b22d3453b6ef51175adada0d6a4a70dc7d566de793d8e5f285e885535c3`.
- MT7621 QEMU lulus pada run `44988206417`, artifact hasil
  `14741740494` (10,073,315 byte), SHA-256
  `9a85658ebddac7927c6d9ab5b3d5e4b4fe9dc9b4ddea3a62a5963a73f5606eda`.
- Guest QEMU melaporkan `CPU topology: detected=4 selected=1 mode=auto max=4`
  dan `IO worker pool started: 4 workers (CPU detected=4, cap=4), one SSH session`.
  Artinya satu sesi SSH tetap dipakai sementara empat worker I/O dibuat.
- Guest berakhir dengan `MIPS TEST STATUS: 0`; transfer full-duplex 8 MiB
  upload/32 MiB download dan SHA-256 cocok, backpressure mencapai kapasitas
  128 KiB lalu terkuras, dan `s2c_epollout_missing=0`.

Sub-tahap penskalaan CPU→I/O worker dinyatakan lulus untuk native dan MT7621
QEMU. Validasi pada router MT7621 fisik tetap termasuk Tahap 5 dan belum
dinyatakan selesai.

**Gerbang kelulusan:** seluruh skenario wajib lulus pada router fisik dan tidak ada
regresi stabilitas atau integritas data. Hasil QEMU saja tidak cukup untuk meluluskan
tahap ini.

---

## Riwayat validasi terbaru

| Target | Status | Keterangan |
|---|---|---|
| Native regression | **Lulus** | Run `44984703377`, source `e2f150f27b3218022559f15a59a4a6fd59de70c0` |
| OpenWrt 24.10.7 MIPS SDK | **Lulus** | Run `44984703379`, artifact `14739159030`, source `e2f150f27b3218022559f15a59a4a6fd59de70c0` |
| MT7621 QEMU | **Baseline lulus** | Run `44985100177`, artifact `14739727217`; SDK artifact `14739159030`; guest `MIPS TEST STATUS: 0`; code SHA `e2f150f27b3218022559f15a59a4a6fd59de70c0` |
| CPU-aware I/O worker MT7621 QEMU | **Lulus** | Run `44988206417`, artifact `14741740494`; source `1f62cba8a464e734547cdd8db9476e35e65ffb05`; guest `detected=4`, `4 I/O workers`, satu SSH session, `MIPS TEST STATUS: 0` |
| OpenWrt 25.12.5 x86_64 QEMU | Pembanding | Tidak menggantikan target MIPS maupun router fisik |
| Router MT7621 fisik | Belum diuji pada tahap ini | Tahap 5 |

Nomor run dan SHA hanya akan ditambahkan setelah diverifikasi dari GitHub Actions.
Hasil lama tidak boleh dianggap mewakili source terbaru jika ada perubahan sesudahnya.

## Aturan pembaruan berikutnya

- Setelah setiap sub-tahap lulus, perbarui tabel ringkasan, bagian tahap terkait,
  dan riwayat validasi di README ini.
- Jika pengujian gagal, catat sebagai gagal/terbuka beserta penyebab dan tindakan
  berikutnya; jangan menaikkan status.
- Setelah semua gerbang Tahap 3 lulus, ubah status Tahap 3 menjadi **LULUS**.
- Setelah seluruh validasi dan tuning Tahap 4 lulus, ubah status Tahap 4 menjadi
  **LULUS**.
- Tahap 5 hanya dapat dinyatakan lulus setelah pengujian pada router MT7621 fisik.

**Tahap 4 LULUS FINAL:** native regression run `44984703377`, OpenWrt 24.10.7 MIPS SDK run `44984703379` (artifact `14739159030`), dan MT7621 QEMU run `44985100177` (artifact `14739727217`) lulus. Kode yang diuji: `e2f150f27b3218022559f15a59a4a6fd59de70c0`; QEMU checkout `74bc19850024605d4f8d737f5cfbd57233744cfd` hanya menambahkan catatan dokumentasi. Pengukuran CPU/RSS/backpressure serta keputusan tidak melakukan tuning tanpa A/B yang sebanding dicatat pada bagian Tahap 4. Tidak ada klaim speedup. Tahap 5 adalah validasi pada router MT7621 fisik.


### Audit performa download GitHub Actions — retest diperlukan

Audit artifact MT7621 QEMU run `44988206417` menemukan bahwa benchmark empat klien
TCP dan TLS hanya mencatat sekitar 1.59–1.61 Mbps per klien (sekitar 0.76 MiB/s
agregat). Penyebab yang ditemukan berada pada fixture HTTP CI, bukan bukti bahwa
relay telah mencapai batas performanya: endpoint `/slow-download` memasang
`SO_SNDBUF=32768` pada socket server dan mengirim data per 16 KiB disertai
`flush()`. Dengan demikian angka tersebut mengukur jalur dengan send-buffer
sengaja dipersempit, bukan throughput normal.

Perbaikan fixture pada commit `081c4bc8a120f0fd0e896b2d3ee05377f3408da8`:
- Menghapus batas socket send-buffer dari endpoint throughput.
- Mengubah chunk pengiriman menjadi 256 KiB dan menghapus flush per chunk.
- Skenario backpressure khusus tetap memakai buffer kecil pada endpoint
  `/duplex-backpressure`, sehingga pengujian tekanan tidak hilang.

Status: **retet belum lulus**. Hasil baru harus menunjukkan throughput direct
baseline dan TCP/TLS relay dengan checksum cocok sebelum angka performa dapat
dinilai. Jangan memakai angka 1.59–1.61 Mbps dari fixture lama sebagai hasil
throughput normal atau klaim performa relay.


## Audit hardening batch — 2026-11-22

Patch batch on `phase3/io-worker-pool-foundation`:
- Payload `[rotate=...]` and `[random=...]` expansion now handles empty selectors without dereferencing a null buffer and advances past inserted replacement text rather than recursively parsing it.
- C2S worker completion treats `EAGAIN` with a pending HUP/RDHUP as the terminal client EOF, preventing immediate re-submission/re-arm loops. Queued C2S bytes remain owned by the SSH Owner and are drained before sending channel EOF.
- Client teardown consistently uses `detach_client_fd()`, so a descriptor held by either direction's worker is marked for deferred close instead of only being removed from epoll.
- TCP connect completion rejects `POLLERR`, `POLLHUP`, and `POLLNVAL` even if `POLLOUT` is also present.
- Normal shutdown guards the upstream descriptor before closing it.
- Added native regressions for empty/populated rotate/random selectors and HUP/RDHUP worker-EAGAIN handling.
- Payload buffer allocation and size-overflow failures now propagate as errors instead of terminating the process.
- Upstream inactivity/keepalive, SOCKS handshake, and EMFILE throttling use monotonic millisecond clocks.
- A shared EPOLLIN gate suppresses client read re-arming while HUP/RDHUP, EOF, an in-flight C2S task, or a full C2S ring is present.
- Package release bumped to r38.

**Validation status:** pending fresh native + OpenWrt 24.10.7 `mipsel_24kc` SDK and matching MT7621 QEMU runs. This patch does not change the one-SSH-session architecture. Physical MT7621 router validation remains separate and is not claimed here.


## Perbaikan workflow benchmark internet MT7621 QEMU — 2026-11-22

Audit GitHub Actions run [45011761935](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45011761935):

- Artifact IPK r38 berhasil diunduh dan validasi versi `1.0.0-r38` serta arsitektur `mipsel_24kc` lolos.
- ImageBuilder menyelesaikan finalisasi root filesystem, pembuatan SquashFS, dan padding image.
- Job berhenti pada target terakhir ImageBuilder, `checksum`, tepat setelah log `Calculating checksums...` (exit code 1). Langkah boot QEMU, SSH forwarding, dan benchmark internet belum dijalankan. Run ini **bukan** hasil benchmark bandwidth.
- Perbaikan workflow membuat target manifest checksum tetap dicoba, tetapi kegagalannya tidak lagi menggagalkan build QEMU karena manifest tersebut bukan input emulator. File sysupgrade tetap wajib ditemukan, tidak kosong, dan SHA-256-nya dicatat sebelum firmware diserahkan ke pembuat flash NAND.
- Validasi ulang QEMU/bandwidth masih menunggu hasil run setelah patch ini. Status Tahap 4/5 tidak dinaikkan berdasarkan run yang gagal ini.



## Audit bottleneck throughput SSH/SOCKS — 2026-11-22

**Penyebab teridentifikasi pada source r38:** `io_worker_pool.h` menetapkan
`IO_WORKER_POOL_PAYLOAD_SIZE=128`. Delapan byte payload dipakai untuk FD dan
panjang data, sehingga `IO_WORKER_SOCKET_WRITE_MAX` hanya **120 byte per task**.
Jalur S2C di `ssh-core.c:submit_s2c_worker_write()` membatasi setiap pengiriman
sesuai nilai tersebut; worker melakukan satu `send()` nonblocking, lalu Owner
harus menunggu completion sebelum mengirim task berikutnya.

Batas itu cocok secara kuantitatif dengan benchmark lama: sekitar 4.000–4.900
task/event per detik dikalikan maksimum 120 byte menghasilkan sekitar 0,46–0,56
MB/s, dekat dengan hasil SOCKS sekitar 500 KB/s. Log juga menunjukkan
`socks_tx_eagain=0` dan `pend_blk=0`; ini bukan gejala socket lokal sering
menolak data. Backpressure dari worker kecil tersebut dapat merambat ke ring S2C
dan window SSH sehingga turut membatasi data yang diterima dari upstream.

**Perbaikan source yang diterapkan:** ukuran payload worker dinaikkan menjadi
16 KiB, sehingga satu task socket write dapat membawa 16,376 byte, bukan 120 byte.
Worst-case ruang antrean task+completion untuk empat worker dan 64 slot per worker
sekitar 8 MiB. Regression socket worker ditambah untuk mengirim dan memverifikasi
satu payload penuh 16 KiB.

**Validasi masih terbuka:** perubahan harus lulus native regression dan OpenWrt
24.10.7 `mipsel_24kc` SDK build, lalu benchmark MT7621 QEMU harus memakai IPK
yang dibangun dari source SHA perubahan ini. Workflow bandwidth khusus juga
dibandingkan pada URL identik secara langsung dari guest dan melalui r38 SOCKS5:
Vultr 100 MB serta Linode 100 MB. Jangan memakai hasil run lama atau artifact
sebelum patch sebagai bukti throughput perbaikan.


## r38 build status

Release r38 carries the S2C I/O worker payload increase from 128 bytes to 16 KiB and the full-size worker socket-write regression. The OpenWrt 24.10.7 `mipsel_24kc` SDK build is queued from the `[mips-stage=sdk]` commit. Do not install or benchmark this release until the SDK job publishes the IPK and its checksum.


## Optimasi S2C: direct nonblocking send oleh SSH Owner — 2026-11-22

Audit lanjutan terhadap bottleneck download pada r38 menemukan bahwa S2C masih
menggunakan model stop-and-wait: satu client hanya boleh memiliki satu tugas
worker S2C aktif, setiap tugas membawa maksimal 16 KiB, lalu SSH Owner harus
menunggu completion sebelum mengirim potongan berikutnya. Model ini menambahkan
copy payload, antrean worker, eventfd, dan completion untuk setiap potongan,
meskipun socket client sudah nonblocking.

Patch r39 mengubah jalur download S2C sebagai berikut:

- S2C sekarang dikirim langsung oleh **satu SSH Owner** menggunakan
  `send()` nonblocking melalui `send_from_rb()`. Flag
  `MSG_DONTWAIT | MSG_NOSIGNAL` memastikan pengiriman tidak menunggu kapasitas
  socket dan tidak memicu SIGPIPE.
- EPOLLOUT tetap dipantau oleh epoll selama ring S2C masih berisi data. Jika
  socket belum siap, data tetap berada di ring dan dikirim kembali saat
  EPOLLOUT berikutnya; urutan dan commit byte tetap dikendalikan SSH Owner.
- Menghapus tugas S2C dari worker pool, salinan payload S2C, state in-flight,
  serta penanganan completion khusus S2C. Batas ring S2C tetap 128 KiB.
- Worker pool tetap tersedia untuk operasi baca socket arah C2S. Worker
  auxiliary tidak membuat sesi SSH tambahan.
- Arsitektur tetap **tepat satu SSH Owner, satu upstream, satu autentikasi,
  dan satu sesi SSH**. Fungsi pemetaan sesi tetap mengembalikan satu sesi
  (`ssh_session_count_for_cpu_count() = 1` dan `*out_count = 1`);
  deteksi CPU hanya menentukan jumlah auxiliary I/O worker (maksimum empat).
- Nomor rilis paket dinaikkan menjadi `1.0.0-r39`.

**Status validasi: menunggu native regression dan build OpenWrt
24.10.7 `mipsel_24kc`.** Setelah SDK berhasil, IPK yang source-SHA-nya cocok
harus diuji pada MT7621 QEMU. Kecepatan hanya boleh dinyatakan membaik setelah
benchmark download langsung dan melalui SOCKS memakai endpoint serta durasi
yang sama, disertai pemeriksaan ukuran dan SHA-256. Patch ini belum diklaim
lulus benchmark bandwidth.


- Workflow alignment: the MT7621 SDK/QEMU version guard and the separate direct-vs-SOCKS bandwidth workflow now target r39, preventing an r38 IPK from being mistaken for the S2C direct-send patch.


## Validasi r39 — OpenWrt 24.10.7 MIPS SDK — 2026-11-22

**Status: LULUS (native regression + MIPS SDK build).**

- GitHub Actions SDK run: [45020186643](https://github.com/winpotatoaja/wall-ssh-core/actions/runs/45020186643).
- Source SHA yang dibangun: `0d48d4e5d5d2298ed057d3e5af7fc147fec5f7a0` (patch S2C direct nonblocking).
- Artifact ID: `14753870688`; nama artifact `passwall-ssh-core-openwrt-24.10.7-mipsel-ipk`.
- IPK: `passwall-ssh-core_1.0.0-r39_mipsel_24kc.ipk`, ukuran 45,024 byte.
- Metadata IPK diverifikasi: Package `passwall-ssh-core`, Version `1.0.0-r39`, Architecture `mipsel_24kc`.
- SHA-256 IPK: `702b00fc6c5da703a9fb848f39e0a7418d7766df10746d960e5dca032eba9350`.
- Native regression lulus: HTTP/SOCKS/core state, SPSC normal + counter rollover, TLS Engine duplex/graceful close, I/O worker pool (termasuk stress 50,000 task), client lifetime, completion tracker, dan client event token.
- Cross-compile MIPS dan packaging IPK selesai sukses. Warning `STAGING_DIR not defined` muncul pada helper cross-compile terpisah; semua helper tetap dibuat dan artifact terunggah.

**Gerbang berikutnya:** MT7621 QEMU harus menginstal IPK r39 dari artifact SDK di atas. Validasi mencakup integritas transfer, half-close, full-duplex, multi-client pada satu sesi SSH, dan pemeriksaan versi paket. Belum ada klaim throughput r39 sebelum QEMU dan benchmark bandwidth khusus selesai.
