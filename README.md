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

### Perbaikan diagnostik bottleneck CPU dan jaringan — self-test lulus; retest terfokus menunggu

- **Retest diagnostik pertama (run `45073574300`, artifact `14774960533`) menyelesaikan pasangan Datapacket:** direct `100.000.000` byte dalam `4,566 s` (`20,90 MiB/s`); SOCKS5 `100.000.000` byte dalam `17,818 s` (`5,35 MiB/s`), HTTP 200 dan byte identik. Namun audit pasca-run melihat per-thread CPU di atas 100% (normalisasi clock belum benar) dan sampel jaringan pertama masih mencakup unduhan direct. Data throughput curl tetap valid, tetapi metrik CPU/network run ini tidak dipakai untuk menyimpulkan bottleneck. Parser denominator dan reset baseline diperbaiki; satu retest Datapacket lagi menunggu.
- Pemeriksaan artifact run 45068073173 menemukan proc_cpu=0.0% pada semua sampel akibat parser /proc/PID/stat yang salah menghapus kolom command; data CPU per proses pada artifact lama tidak valid.
- Pembacaan CPU kini mengambil field utime dan stime sesudah pemisah command ), menghitung delta terhadap waktu sampel aktual, dan merekam CPU tiap TID/thread core beserta nama thread. Persentase proses bisa melebihi 100% bila beberapa thread berjalan paralel; angka per TID menunjukkan penggunaan satu vCPU.
- Pengukuran jaringan tidak lagi mengunci ke eth0. Script mendeteksi interface default route dari /proc/net/route, membaca RX/TX semua interface non-loopback dari /sys/class/net/*/statistics, memberi tanda pada interface default, dan menghitung MiB/s dari delta counter.
- Self-test deterministik memvalidasi parser stat dengan nama proses berisi spasi/tanda kurung, perhitungan CPU per TID, deteksi default route, serta RX/TX interface. Self-test dijalankan lokal dan workflow memeriksanya sebelum provisioning QEMU. Audit run `45073574300` menemukan dua koreksi lanjutan: normalisasi CPU memakai delta total tick rata-rata per-vCPU dari `/proc/stat` (bukan `CLK_TCK` dan detik epoch kasar), serta baseline CPU/network di-reset tepat sebelum SOCKS5 supaya transfer direct tidak ikut masuk ke sampel proxy. TID proses utama kini diberi label `ssh_owner`.
- Koreksi interpretasi: sampel lama yang menunjukkan satu vCPU 100% adalah pemakaian CPU guest per-vCPU, bukan bukti bahwa thread SSH Owner/core yang memakainya. proc_cpu=0.0% dan RX/TX eth0=0 dari artifact lama tidak boleh dipakai untuk menyimpulkan bottleneck. Atribusi proses/thread dan interface jaringan baru akan tersedia dari retest berikutnya.
- Retest berikutnya tetap hanya satu benchmark Datapacket melalui SOCKS5; timeout 50 detik, tanpa retry, satu proses core, satu SSH session. Belum ada hasil baru yang diklaim pada catatan ini.

### Retest internet 100 MB — dua endpoint lulus, empat transfer di bawah 50 detik

- Actions run `45068073173` selesai `success`; job `137348615690`; artifact `14772606003`. Hasil juga dipublikasikan pada GitHub Actions Step Summary.
- **Datapacket Singapore** `http://sgp.download.datapacket.com/100mb.bin`: tepat `100.000.000` byte (100 MB desimal / 95,37 MiB). Direct `5,036 s`, `18,94 MiB/s`; SOCKS5 `13,483 s`, `7,07 MiB/s`. Kedua respons HTTP 200, byte identik; SOCKS5 mencapai 37,3% dari direct pada endpoint ini.
- **OVHcloud Singapore** `https://sin1-sgp.speedtest.network.ovh.net/files/100Mb.dat`: tepat `104.857.600` byte (100 MiB). Direct `28,358 s`, `3,53 MiB/s`; SOCKS5 `31,092 s`, `3,22 MiB/s`. Kedua respons HTTP 200, byte identik; SOCKS5 mencapai 91,2% dari direct.
- Semua empat transfer selesai dalam batas keras `50` detik; tidak ada endpoint yang dilewati. `PAIR_COUNT=2`, `SAMPLE_COUNT=43`, `skipped.log` dan `errors.log` kosong.
- Session invariant terbukti: core startup mencatat `SSH_sessions=1`; core log mencatat tepat satu `authentication accepted` dan satu `Session Keys Established`; host sshd mencatat satu `Accepted password`. CPU guest 4 dan memilih 4 auxiliary I/O workers tanpa menambah SSH session.
- Pengukuran merupakan hasil pada runner GitHub Actions + MT7621 QEMU untuk dua server uji Singapura, bukan jaminan kecepatan pada jaringan/operator atau router fisik. Angka throughput menggunakan `curl speed_download / 1.048.576`; output formatter berikutnya juga menggunakan label eksplisit `curl_avg_MiBps`.
- DigitalOcean sebelumnya gagal DNS (`curl_rc=6`) dan telah diganti dengan Datapacket. Percobaan Vultr terdahulu memang terukur lambat sekitar `0,29 MiB/s`; itu bukan hasil dari endpoint pengganti ini.

