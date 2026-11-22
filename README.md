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
| 3 | Integrasi local socket I/O worker ke relay aktif | **IMPLEMENTASI ADA — QEMU BASELINE LULUS, VALIDASI PATCH ROLLBACK TERBUKA** |
| 4 | Validasi terpadu, perbaikan, dan tuning native/MIPS/QEMU | **BERJALAN — BASELINE VALID, DIAGNOSTIK/TUNING DILANJUTKAN** |
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

### Validasi Stage 3 terbaru

- Native regression dan OpenWrt 24.10.7 SDK MIPS lulus pada source SHA
  `9dbda79c93d659be6ba02d81343120594bfcdf78` (Actions SDK run
  `44975775354`).
- MT7621 QEMU lulus pada run `44976854992`, memakai artifact SDK yang cocok
  dari run `44975775354`. Pengujian RST idle berhasil, kemudian 8 reconnect SOCKS
  masing-masing memverifikasi ukuran 1 MiB dan SHA-256; half-close, post-EOF
  upload 8 MiB, full-duplex 8 MiB upload/32 MiB download, serta multi-client
  TCP/TLS juga lulus.
- Audit menemukan rollback task/lifetime pada jalur gagal-submit mengabaikan
  hasil cancel tracker dan release reference. Kedua arah C2S/S2C kini memakai
  rollback terverifikasi dan mencatat kegagalan invariant. Patch source terbaru
  masih harus lulus native, SDK, dan QEMU sebelum Stage 3 ditutup.


<badge color="warning">IMPLEMENTASI ADA — VALIDASI PATCH TERAKHIR TERBUKA</badge>

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

**Status saat ini:** native regression, OpenWrt SDK cross-build, dan MT7621 QEMU runtime telah lulus untuk source SHA sebelumnya. Assertion RST/reconnect/FD reuse sudah ditambahkan ke workflow, tetapi belum tervalidasi pada source SHA terbaru. Tahap 3 tetap terbuka sampai suite terbaru lulus dan audit completion/lifetime invariant ditutup.

## Tahap 4 — Validasi terpadu, perbaikan, dan tuning native/MIPS/QEMU

<badge color="warning">BERJALAN — BASELINE VALID, DIAGNOSTIK/TUNING DILANJUTKAN</badge>

**Tujuan:** membuktikan implementasi akhir pada target arsitektur, memperbaiki
regresi yang ditemukan, lalu melakukan tuning berdasarkan pengukuran.

Urutan kerja:
1. Selesaikan satu batch audit/perbaikan source Tahap 3 dan test yang terkait.
2. Jalankan seluruh regression native dalam satu rangkaian.
3. Build paket dengan OpenWrt 24.10.7 SDK untuk `mipsel_24kc`.
4. Jalankan paket hasil build tersebut di MT7621 QEMU; verifikasi artifact/source SHA.
5. Jalankan QEMU OpenWrt x86_64 sebagai pembanding bila workflow terkait berubah.
6. Evaluasi hasil throughput, CPU/thread, RSS, FD, queue occupancy, backpressure,
   retransmission, dan latensi; lakukan tuning hanya berdasarkan hasil terukur.
7. Setelah perubahan tuning, ulangi regression yang terdampak dan validasi akhir.

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

**Status saat ini:** baseline native regression, MIPS SDK, dan MT7621 QEMU telah terverifikasi pada run/source yang tercatat. Tahap 4 tetap terbuka untuk konsolidasi suite, audit edge case Stage 3, dan tuning berbasis metrik. Tidak ada klaim kelulusan penuh Stage 4 sebelum batch validasi final.

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

**Gerbang kelulusan:** seluruh skenario wajib lulus pada router fisik dan tidak ada
regresi stabilitas atau integritas data. Hasil QEMU saja tidak cukup untuk meluluskan
tahap ini.

---

## Riwayat validasi terbaru

| Target | Status | Keterangan |
|---|---|---|
| Native regression | Perlu konsolidasi akhir | Helper worker/lifetime/token/tracker telah memiliki test tersendiri; jalankan kembali sebagai satu suite setelah batch final |
| OpenWrt 24.10.7 MIPS SDK | **Lulus** | Run `44964541444`; artifact dipakai untuk baseline QEMU. Build bukan bukti runtime dengan sendirinya |
| MT7621 QEMU | **Baseline lulus** | Run `44965112117` berhasil; source SHA `0f1d484604fb2d2f1d0e53ee5603f90fe71995f2`; Stage 3/4 masih membutuhkan audit edge case dan rerun pada perubahan code terbaru |
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
