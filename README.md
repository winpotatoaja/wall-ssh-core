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
| 4 | Validasi terpadu, perbaikan, dan tuning native/MIPS/QEMU | **LULUS FINAL** |
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

<badge color="success">LULUS FINAL — VALIDASI DAN AUDIT SELESAI</badge>

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

**Status akhir Tahap 4:** seluruh gerbang native, OpenWrt 24.10.7 MIPS SDK, MT7621 QEMU, pemeriksaan source metrik, dan analisis baseline telah selesai. Tidak ada tuning yang terbukti perlu dilakukan, sehingga Tahap 4 ditutup **LULUS FINAL** tanpa klaim speedup. Tahap 5 membutuhkan pengujian pada router MT7621 fisik. Benchmark beberapa proses/SSH session di `tests/MIPS-MT-BENCHMARK.md` tetap hanya pembanding kapasitas dan bukan bukti worker pool satu-session lebih cepat.

## Tahap 5 — Validasi perangkat OpenWrt MT7621 fisik

<badge color="secondary">BELUM DIMULAI</badge>

**Tujuan:** memastikan paket final berjalan stabil pada router MT7621 fisik,
bukan hanya pada emulator.

Prasyarat:
- Tahap 3 dan Tahap 4 berstatus LULUS.
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

### Sub-tahap: penskalaan I/O worker berdasarkan CPU (implementasi, validasi pending)

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
- Worker tetap hanya menjalankan operasi socket client; libssh2 dan TLS Engine
  tetap berada pada owner masing-masing.

Status implementasi: **sudah diterapkan pada source** dan regression mapping
CPU→I/O worker telah ditambahkan untuk input 1/2/4 serta nilai di luar rentang;
validasi build/runtime tetap pending. Gerbang berikutnya adalah native regression,
OpenWrt 24.10.7 MIPS SDK, dan MT7621 QEMU pada source yang sama. Pengujian harus
membuktikan konfigurasi 1/2/4 CPU menghasilkan 1/2/4 I/O worker (dengan cap 4),
seluruh completion terlayani, dan jumlah sesi SSH tetap satu. Hasil QEMU tidak menggantikan validasi
router fisik Tahap 5.

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
