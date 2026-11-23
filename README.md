# Passwall SSH Core — Progres Pengerjaan Tahap 1–5

Dokumen ini adalah **catatan progres utama proyek**. Semua pekerjaan, hasil validasi,
keputusan, dan pekerjaan tersisa dicatat berdasarkan lima tahap di bawah. Status
hanya boleh dinaikkan menjadi **LULUS** setelah seluruh kriteria tahap tersebut
dibuktikan oleh hasil pengujian yang tercatat.

Terakhir diperbarui: 2026-11-23  
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

### Hasil benchmark r41 dan instrumentasi bottleneck — r42

- SDK r41 berhasil pada run `45081609577`; benchmark otomatis run `45081951698` (artifact `14777935844`) juga berhasil. Satu objek Datapacket 100.000.000 byte selesai pada direct `14,70 MiB/s` dan SOCKS5 `6,80 MiB/s` (46,3% dari baseline direct), keduanya HTTP 200 dan ukuran byte cocok.
- Selama bulk transfer, `ssh_owner` memakai sekitar 100% satu vCPU; keempat auxiliary worker TID tetap 0%. `tls_rx_calls=0`, `socks_tx_eagain=0`, `socks_tx_partial=0`, `s2c_epollout_missing=0`, dan `pend_blk=0`. Bukti ini menempatkan hambatan pada jalur SSH Owner serial, tetapi belum memisahkan biaya dekripsi OpenSSL dari framing/antrean paket libssh2.
- Perbandingan r39/r40 bukan A/B cipher yang terkontrol: direct baseline internet berubah antar-run. Angka kecepatan itu hanya observasi; belum cukup untuk menyimpulkan perbedaan kecepatan disebabkan oleh cipher.
- r41 mempertahankan AES-128-GCM sebagai preferensi MIPS pertama dan S2C ring 256 KiB. Perubahan ini tidak diubah pada r42 agar pengukuran timing tidak tercampur dengan tuning algoritma atau ukuran buffer.
- r42 menambahkan timing `CLOCK_MONOTONIC` yang hanya aktif ketika `LOG_PERF=1`: `perf_s2c_read_us` mengukur seluruh `libssh2_channel_read()`; `perf_ssh_recv_cb_us` mengukur seluruh callback receive; `perf_ssh_recv_s2c_cb_us` adalah bagian callback yang terjadi di dalam channel read; `perf_s2c_internal_us` adalah selisih channel-read dengan callback nested; `perf_ssh_recv_syscall_us` mengukur syscall `recv()`; dan `perf_socks_tx_us` mengukur drain S2C ke socket lokal.
- `perf_s2c_internal_us` adalah estimasi waktu internal library di luar callback receive (framing, dekripsi/authentication, packet-list/queue handling, copy, dan pekerjaan channel lain), bukan pengukuran AES-GCM murni. Timer berbasis elapsed monotonic time juga mencakup waktu terjadwal dan kernel; overhead instrumentasi perlu diperhitungkan saat membaca hasil.

**Status:** r41 baseline telah selesai divalidasi di SDK dan QEMU; bottleneck performa masih terbuka. r42 adalah diagnostic build, bukan klaim speedup. Validasi perangkat MT7621 fisik tetap belum dilakukan.
 
### Hasil diagnostic r42 — bottleneck di dalam libssh2

- SDK r42 run 45085952466 sukses, artifact IPK 14779263184; QEMU bandwidth run 45086255120 sukses, artifact diagnostic 14779436958. Benchmark memakai source SHA 47d17077d9d71d1b6c4a3cdd90358cd75a179f01, cipher aktual aes128-gcm@openssh.com, satu autentikasi dan satu SSH session.
- Datapacket 100.000.000 byte: direct 23,82 MiB/s; SOCKS5 6,93 MiB/s (29,1% dari direct pada run ini). r41 memperoleh 6,80 MiB/s SOCKS5; kenaikan absolut r42 hanya sekitar 1,9%. Direct baseline r41/r42 berbeda besar dan remote IP berbeda, jadi perbandingan rasio tidak boleh diperlakukan sebagai A/B yang terkontrol.
- CPU sampling mengonfirmasi ssh_owner sekitar 99,4–102,3% satu vCPU; empat I/O worker tetap 0%. TLS tidak aktif. Local S2C send tidak mengalami EAGAIN atau partial write.
- Agregat 9 interval [PERF] dengan sedikitnya 1 MB S2C data: total span 11.961 ms; S2C data 93.649.852 byte. perf_s2c_read_us=11.448.333; callback receive nested perf_ssh_recv_s2c_cb_us=437.315 (3,82% dari channel-read); residual perf_s2c_internal_us=11.011.010 (96,18%); syscall recv() 386.725 us (3,38% dari channel-read dan 88,4% dari callback); local S2C flush 260.165 us (2,27% dari channel-read). Waktu syscall merupakan bagian dari callback, bukan biaya tambahan yang dijumlahkan lagi.
- Satu interval 1.476 ms mencatat ssh_rx_bytes=7.455.256 vs s2c_read_bytes=5.569.468, selisih 1.885.788 byte. Ini konsisten dengan libssh2 membaca paket transport lebih dulu ke session->packets, lalu baru menguras sebagian payload ke buffer pemanggil. Namun byte residence queue belum diukur langsung, sehingga 1,89 MB bukan angka queue depth yang sudah dipastikan.
- Source libssh2 1.11.0 memang melakukan loop _libssh2_transport_read() sampai EAGAIN sebelum mengiterasi session->packets dan memcpy payload ke buffer channel. OpenSSL backend menjalankan EVP_Cipher() pada jalur _libssh2_cipher_crypt(). Residual r42 mencakup dekripsi/authentication, parsing/framing, packet list, copy/free, serta pekerjaan channel lainnya; bukan waktu AES-GCM murni.

**Kesimpulan:** r42 membuktikan receive syscall dan local send bukan bottleneck utama. Mayoritas waktu S2C berada di dalam pemrosesan libssh2_channel_read(). Tahap diagnostik berikutnya harus memisahkan waktu AES-GCM (_libssh2_cipher_crypt) dari transport packet parsing/queue dan drain session->packets sebelum mengubah cipher, buffer, atau arsitektur thread. QEMU belum menggantikan benchmark pada MT7621 fisik.

### r43 — instrumentasi internal libssh2

- r43 mempertahankan cipher AES-128-GCM dan S2C ring 256 KiB dari r41/r42. Perubahan ini diagnostik; belum ada klaim peningkatan throughput.
- SDK akan membangun ulang source libssh2 **1.11.0** yang dipakai OpenWrt 24.10.7. Patcher `tools/apply_libssh2_r43_diag.py` diterapkan setelah target prepare dan sebelum compile. Paket artifact SDK berisi dua IPK dari commit/source SHA yang sama: `passwall-ssh-core` r43 dan patched `libssh2 1.11.0-1`.
- QEMU benchmark memverifikasi checksum kedua IPK, menginstal ulang patched libssh2 secara paksa, memeriksa simbol API diagnostik pada library runtime, lalu menjalankan satu download Datapacket direct dan satu SOCKS5 seperti sebelumnya. Batas tiap transfer 50 detik; tidak ada retry atau sesi SSH tambahan.
- Metrik baru pada log `[PERF]`:
  - `libssh2_decrypt_path_us`: durasi helper dekripsi tingkat paket, termasuk pemanggilan cipher dan salinan buffer di helper. **Ini bukan waktu EVP/AES murni.**
  - `libssh2_transport_read_us`: seluruh waktu pengumpulan, pembongkaran, dekripsi, dan enqueue paket transport.
  - `libssh2_transport_other_us`: estimasi sisa transport setelah mengurangi decrypt path dan callback receive S2C.
  - `libssh2_packet_drain_us`: waktu scan/drain `session->packets`, termasuk penyalinan payload dan pelepasan node.
  - `libssh2_channel_other_us`: estimasi sisa `libssh2_channel_read()` di luar transport read dan queue drain.
  - `libssh2_packet_queue_current/peak_packets/bytes`: kedalaman antrean saat interval dan puncaknya. Byte current dikurangi pada setiap pembacaan parsial, bukan hanya ketika node dihapus.
- Semua timer dan counter diagnostik di library hanya aktif setelah autentikasi jika `LOG_PERF=1`. Akses ke session tetap pada satu SSH Owner; tidak ada operasi libssh2 paralel.

**Status r43:** perubahan source, package, SDK/QEMU workflow, dan dokumentasi sudah disiapkan. Validasi compile dan benchmark belum selesai sampai workflow SDK dan benchmark keduanya lulus. Hasil QEMU tetap bukan pengganti uji router MT7621 fisik.
