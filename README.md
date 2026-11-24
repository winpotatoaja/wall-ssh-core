# Passwall SSH Core — Progres Pengerjaan Tahap 1–5

Terakhir diperbarui: 2026-11-24

## r50 — dual-core crypto scheduling berbasis physical-core topology

**Status: SDK MIPS #661 dan QEMU bandwidth #76/#77 lulus. MT7621A terdeteksi sebagai 4 VPE / 2 physical core; runtime mengaktifkan 2 worker ChaCha20 + 1 Poly1305. Sampler fixed-deadline mencapai median 254 ms (47 sampel; rentang 242–301 ms) terhadap target 250 ms. Validasi router MT7621 fisik dan pengujian langsung pola stall IDM tetap terbuka.**

### Identitas paket OpenWrt r50

Recipe paket menetapkan `PKG_VERSION:=1.0.0` dan `PKG_RELEASE:=50`. Hasil SDK yang benar harus bernama `passwall-ssh-core_1.0.0-r50_mipsel_24kc.ipk` **dan** memiliki `Version: 1.0.0-r50` di control metadata. Artifact SDK #661 sebelumnya dibuat dari source r50, tetapi masih memakai nama dan metadata paket r49; jangan menganggap artifact lama itu sebagai IPK r50. Paket `libssh2-1_1.11.1-r1_mipsel_24kc.ipk` adalah dependensi terpisah dan versinya tidak ikut berubah.

### Koreksi penting topology MT7621A

MT7621A bukan dua logical CPU. SoC memiliki dua physical core, masing-masing dengan dua VPE, sehingga OpenWrt normalnya melihat empat Linux CPUs (`VPE topology {2,2} total 4`). Karena itu, saran sebelumnya untuk menurunkan QEMU ke `-smp 2` tidak tepat untuk meniru MT7621A: konfigurasi itu menjadi satu physical core / dua VPE (kelas MT7621S). QEMU untuk MT7621A harus tetap memakai empat Linux CPUs.

Kesalahan r50 sebelumnya adalah memakai jumlah logical CPUs untuk menentukan jumlah crypto worker. Dengan empat VPE, core akan memilih empat worker seperti r49, walaupun perangkat hanya memiliki dua physical cores. Perbaikan sekarang memisahkan kedua hitungan:
- Jumlah logical CPUs/affinity tetap dipakai untuk sizing auxiliary I/O workers.
- Jumlah physical cores dihitung dari pasangan `physical_package_id` + `core_id` di `/sys/devices/system/cpu/cpu*/topology`, dibatasi cpuset/affinity proses.
- Satu physical core: serial Owner path.
- Dua physical cores: 3 persistent crypto workers (2 ChaCha20 decrypt + 1 Poly1305).
- Tiga atau lebih physical cores: maksimum 4 worker (3 ChaCha20 decrypt + 1 Poly1305).
- Jika kernel tidak menyediakan topology sysfs lengkap, detektor jatuh kembali ke jumlah logical CPUs; benchmark QEMU berhenti sebelum transfer bila tidak mendapatkan topology MT7621A yang diharapkan (4 Linux CPUs / 2 physical cores).

**Sampling benchmark memakai fixed deadline sekitar 250 ms.** OpenWrt 24.10 BusyBox mengabaikan fractional `sleep`, sehingga helper MIPS statis `diag-timer` menyediakan `clock_gettime(CLOCK_MONOTONIC)` dan `nanosleep()`. Snapshot awal CPU/WAN pada MIPS memakan sekitar 50 ms, sehingga deadline internal disetel 200 ms agar interval timestamp hasil ukur mendekati 250 ms. QEMU #77 mengukur rata-rata 257 ms, median 254 ms, minimum 242 ms, maksimum 301 ms dari 47 sampel. Verifier mensyaratkan minimal 20 sampel, median ≤300 ms, dan maksimum ≤350 ms; kedua worker ChaCha dan worker Poly1305 wajib mencatat CPU nonzero.

### Diagnosis timer guest QEMU #73 dan #74

- QEMU #73 (`45387141473`) berhasil boot, memasang patched `libssh2` dan core r50, tetapi self-test berhenti sebelum benchmark karena satu `sleep 0.05` hanya maju sekitar 0,02 s pada `/proc/uptime`.
- QEMU #74 (`45387898626`) mengulangi preflight setelah mengganti tes menjadi tiga `sleep 0.25`; hasilnya tetap hanya 0,02 s. Ini membuktikan BusyBox OpenWrt guest tidak menjalankan fractional sleep. Kedua run **tidak melakukan download 100 MB**; kegagalan auth/cipher/timing di langkah berikutnya hanya konsekuensi core/benchmark belum dijalankan.
- OpenWrt 24.10 BusyBox config default juga menonaktifkan `USLEEP`, `FEATURE_SH_READ_FRAC`, dan `FLOAT_DURATION`. Maka jangan mengandalkan `sleep 0.25`, `usleep`, atau `read -t` untuk interval sub-detik.
- Helper `tests/diag_timer.c` menyediakan `now-ms` melalui `clock_gettime(CLOCK_MONOTONIC)` dan `sleep-us` melalui `nanosleep()`. SDK #661 membangun helper native untuk self-test dan static MIPS untuk artifact; tiga jeda 250 ms terukur 755 ms di runner, dan ELF/sha diverifikasi. QEMU mengirim helper ke guest dan memakai helper itu pada preflight serta loop sampling. QEMU #76 awalnya mencapai median 306 ms setelah collector proses eksternal diringkas; #77 mengompensasikan biaya snapshot awal dan mencapai median 254 ms dengan maksimum 301 ms.

### Validasi worker dual-core dan sampling — QEMU #75–#77

SDK #661 (`45390163716`) sukses dan membangun core r50 serta helper timer MIPS dari source SHA `b67ddaab17c51523524c0884feda4545c1badff9`. QEMU memakai empat Linux CPU/VPE tetapi sysfs topology menunjukkan dua physical core, dan runtime log membuktikan `crypto_workers=3`, `chacha_payload_workers=2`, `poly1305_workers=1`.

- QEMU #75 (`45390937381`) membuktikan topology/worker plan dan menyelesaikan dua transfer 100 MB, tetapi verifier gagal cadence: 17 sampel median 756 ms. Audit menunjukkan terlalu banyak proses shell/AWK per sampel.
- Collector #76 (`45392730263`) diringkas menjadi satu AWK untuk seluruh thread, satu AWK untuk `/proc/net/dev`, CPU process dihitung dari delta gabungan thread, dan salinan snapshot memakai shell builtins. Semua gerbang lulus; 34 sampel memiliki mean/median sekitar 306 ms (rentang 287–350 ms). Kecepatan direct 23,06 MiB/s dan SOCKS5 9,00 MiB/s, HTTP 200, Datapacket `79.127.235.51`.
- QEMU #77 (`45394102605`, artifact `14920257243`) mengompensasikan sekitar 50 ms biaya snapshot CPU/WAN pada deadline internal. **47 sampel** mengukur mean 257 ms, median **254 ms**, min 242 ms, max 301 ms; verifier yang lebih ketat lulus (minimal 20 sampel, median ≤300 ms, max ≤350 ms).
- Pada #77, transfer direct 100.000.000 byte selesai dalam 3,881 s (**24,58 MiB/s**); SOCKS5 100.000.000 byte selesai dalam 12,182 s (**7,83 MiB/s**), HTTP 200, remote direct `79.127.213.228`. Satu host authentication, satu core authentication/key establishment, satu SSH session, dan cipher `chacha20-poly1305@openssh.com` terverifikasi.
- Sampel #77 memperlihatkan `ssh_owner` rata-rata 54,0% satu VPE; dua worker ChaCha aktif rata-rata 17,5% dan 17,8%; Poly1305 aktif 20,4%. Empat auxiliary I/O workers tidak menunjukkan CPU terukur pada transfer single-client. Counter `socks_tx_eagain=0` dan `socks_tx_partial=0` pada seluruh PERF intervals: tidak terlihat local SOCKS socket backpressure pada tes ini.
- Timing PERF sepuluh interval steady-state terakhir menunjukkan `perf_s2c_read_us` rata-rata sekitar 903 ms per detik, berbanding `perf_socks_tx_us` sekitar 90 ms. Jalur read/processing libssh2 masih dominan; pengiriman socket client bukan bottleneck yang tampak pada pengukuran ini.
- Angka SOCKS5 #77 (7,83 MiB/s) tidak dibandingkan sebagai A/B dengan #76 (9,00 MiB/s), #75 (sekitar 7,42 MiB/s), atau #72 (14,41 MiB/s): setiap run memakai IP Datapacket/variasi jaringan berbeda. Yang telah dibuktikan #77 adalah alokasi physical-core, aktivitas worker, sampling sekitar 250 ms, transfer penuh, dan integritas satu session—not peningkatan throughput.

**Kesimpulan status:** perbaikan deteksi physical-core, worker plan dual-core, timer monotonic, dan sampler 250 ms telah lulus QEMU. Belum ada bukti bahwa jeda download IDM pada router fisik telah hilang. Validasi akhir tetap memerlukan instalasi pada MT7621 fisik serta pengamatan transfer IDM/client selama beberapa menit.
### Hasil bandwidth r50 awal — QEMU #72 (sebelum koreksi topology fisik)

SDK run #634 (45382100045) lulus. Benchmark #72 (45383249234, artifact 14915176986) memakai source SHA `a60d2fe287591c6c9483dd3b6837729df96bc0a9`.

- Direct: 100.000.000 byte, 4,034 s, **23,64 MiB/s**, HTTP 200, remote `79.127.235.8`.
- SOCKS5: 100.000.000 byte, 6,621 s, **14,41 MiB/s**, HTTP 200. Timeout 50 detik tidak terlampaui; byte cocok.
- SOCKS5 naik 61,4% dibanding r49 #70 (8,93 MiB/s), direct turun 5,2% (24,93 ke 23,64 MiB/s). Ini bukan A/B terkontrol karena IP Datapacket berbeda (.8 dibanding .9).
- Tepat satu autentikasi host, satu autentikasi core/key establishment, dan satu SSH session; cipher `chacha20-poly1305@openssh.com`.
- QEMU #72 mendeteksi empat logical CPUs dan memakai 4 crypto workers (3 ChaCha + Poly1305), sama dengan r49. Maka angka 14,41 MiB/s tidak membuktikan alokasi dua-physical-core yang sekarang diperbaiki.
- Pada interval steady-state, `socks_tx_eagain=0` dan `socks_tx_partial=0`; byte SSH yang dibaca sama dengan byte yang dikirim ke SOCKS. Jalur receive/decrypt libssh2 masih mendominasi waktu.
- Sampel WAN sebelumnya hanya 1–2 detik dan bervariasi 9,89–28,93 MiB/s; belum cukup untuk memastikan jeda IDM hilang.

**Langkah berikutnya:** pasang paket r50 yang sudah dibangun dari source SHA `b67ddaab...` pada router MT7621 fisik, lalu uji download IDM selama beberapa menit sambil merekam throughput/CPU. QEMU sudah membuktikan worker plan dua-core dan sampling; hasil itu belum menggantikan validasi fisik.
Dokumen ini adalah **catatan progres utama proyek**. Semua pekerjaan, hasil validasi,
keputusan, dan pekerjaan tersisa dicatat berdasarkan lima tahap di bawah. Status
hanya boleh dinaikkan menjadi **LULUS** setelah seluruh kriteria tahap tersebut
dibuktikan oleh hasil pengujian yang tercatat.

Terakhir diperbarui: 2026-11-24  
Branch pengerjaan: `benchmark/r39-internet-speedtest`

## r49 — Poly1305 dipindahkan ke worker dan overlap dengan dekripsi ChaCha20

**Status: native regression dan OpenWrt 24.10.7 MIPS SDK r49 lulus pada run #615; QEMU standar lulus pada run #619. Datapacket 100 MB benchmark berhasil diukur pada run #70, dan seluruh pemeriksaan artifact-only lulus pada run #71. Semua gerbang SDK, VM, transfer bandwidth, autentikasi, cipher, timing, dan worker telah lulus. Hasil r49 8,93 MiB/s SOCKS5 belum menunjukkan peningkatan terhadap observasi r48 9,58 MiB/s.**

**Hasil validasi awal SDK #609 (45223162174):** native relay regressions lulus,
SDK berhasil diunduh, dan patched libssh2 berhasil dikonfigurasi untuk MIPS.
Regression kriptografi kemudian gagal pada payload 4.096 byte. Audit menemukan
worker r49 memakai `task_kind`, sedangkan jalur fallback satu-worker r48 belum
mengisi task type sehingga worker menyelesaikan task tanpa memproses payload.
Patch r49 diperbaiki untuk menandai task fallback sebagai
`CHACHA_TASK_DECRYPT`; regression kini juga mencetak jumlah worker saat gagal.
Validasi ulang pada SDK run #615 (45224569468) lulus, termasuk regression native, regression ChaCha20-Poly1305, cross-compile MIPS, dan pembuatan IPK. Artifact IPK serta helper tersedia untuk tahap QEMU VM.

**Diagnosis QEMU #616 (45226008108):** firmware MT7621 berhasil dibangun dan boot. Validasi checksum/artifact, helper regression MIPS, SPSC, worker pool, client lifetime, dan TLS Engine lulus. Core gagal saat startup karena VM workflow hanya mengirim dan memasang IPK `passwall-ssh-core`; IPK patched `libssh2-1_1.11.1-r1_mipsel_24kc.ipk` dari SDK artifact tidak ikut dipasang. Firmware ImageBuilder masih memakai libssh2 bawaan OpenWrt, sehingga dynamic linker tidak menemukan empat API r49 (`libssh2_session_diag_timing_snapshot`, `libssh2_session_diag_timing_enable`, `libssh2_session_callback_set2`, `libssh2_session_set_chacha_workers`). Ini adalah kekurangan alur pemasangan dependency pada workflow VM, bukan kegagalan boot, regression kriptografi, atau bukti bug algoritma r49. Perbaikan workflow: transfer IPK patched libssh2, force-reinstall sebelum core, dan verifikasi keempat simbol pada library runtime. Benchmark internet 100 MB tidak dijalankan.

**Hasil QEMU standar #619:** QEMU MT7621 berhasil boot setelah workflow menginstal patched `libssh2-1` dari SDK artifact #615. Pemeriksaan integrasi standar lulus.

**Hasil Datapacket bandwidth benchmark #70 (45229066437):** direct 100.000.000 byte selesai dalam 3,827 s (`24,93 MiB/s`, HTTP 200, endpoint `79.127.235.9`); SOCKS5 100.000.000 byte selesai dalam 10,686 s (`8,93 MiB/s`, HTTP 200). Keduanya selesai jauh di bawah hard timeout 50 detik dan pasangan byte cocok. Retensi SOCKS5 terhadap direct pada run yang sama adalah 35,8%. Host mencatat tepat satu autentikasi, core tepat satu autentikasi/key establishment dan satu SSH session; cipher aktual `chacha20-poly1305@openssh.com`.

Sampel lima interval aktif selama SOCKS5: `ssh_owner` rata-rata 58,2% satu vCPU; `chacha-dec0/1/2` masing-masing sekitar 13,1%, 13,0%, dan 13,4%; `chacha-poly` sekitar 19,5%. Ini menunjukkan kerja crypto memang terdistribusi ke empat worker pada QEMU 4-vCPU. Hasil speed r49 (`8,93 MiB/s`) belum menunjukkan kenaikan terhadap observasi r48 (`9,58 MiB/s`); perbandingan antar-run bukan A/B terkontrol.

**Mengapa run #620 berstatus failure:** langkah transfer bandwidth dan validasi satu SSH session/cipher lulus. Hanya `Verify S2C timing instrumentation` yang gagal karena `log_raw()` memakai buffer pesan 2.048 byte. Baris `[PERF]` terpotong tepat di akhir `libssh2_chacha20_parallel_us`, sehingga dua field berikutnya yang memang diformat oleh source (`libssh2_chacha20_parallel_bytes` dan `libssh2_chacha20_parallel_packets`) tidak sampai ke file log. Verifier kini menggunakan counter `parallel_us` yang terlihat dan mengharuskan CPU nonzero pada TID ketiga worker ChaCha serta worker Poly1305. Mode `verify_only_run_id` mengambil artifact run #70 dan menjalankan ulang pemeriksaan pada run #71, yang sukses. Run #71 tidak membangun QEMU, tidak melakukan boot VM, dan tidak mengulang download 100 MB.


Pada paket S2C minimal 4 KiB dan setidaknya dua crypto worker, r49 memakai satu
worker khusus untuk menghitung Poly1305 dari snapshot ciphertext, sementara
worker sisanya mendekripsi rentang blok ChaCha20 yang terpisah. SSH Owner hanya
menyiapkan state, dispatch, menunggu completion, lalu memeriksa tag; Owner tidak
menghitung payload ChaCha20 maupun Poly1305.

- 1 vCPU: fallback serial pada Owner, tanpa crypto worker.
- 2 vCPU: satu worker Poly1305 + satu worker ChaCha20.
- 3 vCPU: satu worker Poly1305 + dua worker ChaCha20.
- 4 vCPU atau lebih: satu worker Poly1305 + tiga worker ChaCha20; pool tetap dibatasi empat thread.
- Poly1305 membaca snapshot privat hingga batas paket libssh2 35.000 byte. Payload boleh diproses in-place secara bersamaan karena Owner tidak meneruskan paket sebelum semua worker selesai dan tag cocok.
- Tag salah menyebabkan AAD/ciphertext asli dipulihkan sebelum fungsi mengembalikan error. Jika worker gagal dan belum quiescent, buffer bersama tidak dibersihkan di bawah worker yang masih aktif; teardown pool tetap melakukan join.
- Paket kecil atau kondisi di luar batas offload memakai fallback r48: autentikasi serial sebelum transformasi payload.
- PERF menambahkan `libssh2_chacha_poly1305_offloaded_packets` agar pengujian dapat memastikan jalur offload benar-benar dipakai.

Regression membandingkan enkripsi serial dengan dekripsi 1–4 worker, menguji ukuran
di sekitar ambang 4 KiB, tail blok ChaCha, serta memastikan tag rusak ditolak
tanpa perubahan pada buffer paket. Validasi belum boleh dianggap lulus sampai
native regression dan OpenWrt 24.10.7 `mipsel_24kc` SDK berhasil.

## r48 — seluruh payload ChaCha20 dikerjakan worker, bukan SSH Owner

**Status: implementasi disiapkan; menunggu validasi SDK MIPS dan QEMU 4-vCPU.**

r48 mengubah pembagian kerja r47. Untuk paket S2C berukuran minimal 4 KiB,
seluruh blok payload ChaCha20 diproses oleh persistent crypto workers. SSH Owner
hanya menyiapkan state, dispatch pekerjaan, dan menunggu seluruh worker selesai;
tidak ada lane ChaCha payload yang dihitung oleh Owner.

- CPU 1: satu lane serial pada Owner, tanpa worker tambahan.
- CPU 2: dua persistent crypto workers; Owner hanya mengatur dan menunggu.
- CPU 4: empat persistent crypto workers; Owner tidak menghitung payload.
- Batas maksimum pool empat worker; jumlah CPU efektif tetap dideteksi dari
  affinity/cpuset terlebih dahulu, lalu sysconf sebagai fallback.
- Poly1305 authentication tetap dilakukan serial oleh Owner sebelum payload
  disentuh. Header SSH dan state/protokol juga tetap pada Owner.
- Regression mencakup 1, 2, dan 4 worker, ukuran di sekitar batas 4 KiB,
  batas blok 64 byte, tail, serta penolakan tag rusak tanpa memodifikasi packet.

Belum ada klaim kenaikan throughput sebelum hasil QEMU r48 dibandingkan.

## r47 — paralelisme dekripsi ChaCha20 dalam satu paket SSH

**Status: SDK dan QEMU r47 lulus; paralelisme runtime terverifikasi, throughput belum menjadi A/B terkontrol.**

r47 memecah payload ChaCha20 S2C ke lane Owner dan maksimal tiga worker crypto,
tanpa menjalankan libssh2 pada thread lain. Poly1305 masih dijalankan serial oleh
Owner sebelum dekripsi in-place. Worker pool aktif dan dibuat saat key exchange.

### Validasi SDK #586 dan QEMU #68

- SDK #586 / `45205194833`, source SHA `508e3be82433e0838a7b113de3997c11c64aa2a9`,
  berhasil membangun IPK `mipsel_24kc` r47 dan patched libssh2 1.11.1.
- Regression ChaCha serial-encrypt vs parallel-decrypt lulus untuk payload
  0–32 KiB, termasuk batas blok, ambang 4 KiB, satu/tiga worker, dan tag rusak.
  Tag yang gagal diverifikasi ditolak tanpa meninggalkan plaintext di buffer.
- QEMU #68 / `45207007052` lulus: satu autentikasi dan satu SSH session,
  cipher ChaCha20-Poly1305, serta transfer direct/SOCKS5 masing-masing tepat
  100.000.000 byte, HTTP 200.
- Direct 20,30 MiB/s; SOCKS5 9,41 MiB/s; retensi pada run yang sama 46,4%.
  Endpoint direct berbeda dari r46 (79.127.213.245 vs 79.127.235.51), sehingga
  angka tersebut bukan bukti bahwa r47 lebih cepat atau lambat dari r46.
- Empat vCPU terdeteksi. Saat transfer SOCKS5, `ssh_owner` menggunakan sekitar
  86–88% satu vCPU; tiga worker crypto `chacha-dec0..2` masing-masing sekitar
  11–12%; empat worker I/O socket tetap 0%. Ini membuktikan sebagian kerja crypto
  telah keluar dari Owner, tetapi Owner masih merupakan thread terpadat.
- Counter PERF menunjukkan sekitar 94,5 MB payload diproses melalui jalur
  ChaCha paralel pada interval transfer. Poly1305 serial masih memakan sekitar
  180–254 ms per interval aktif satu detik.

**Arah optimasi berikutnya:** r48 menguji apakah penghapusan lane ChaCha payload
milik Owner dapat menurunkan bottleneck thread tersebut. Poly1305 tetap serial
dan baru dapat menjadi sasaran terpisah setelah hasil worker-only ini diukur.
## r46 — gunakan ChaCha20-Poly1305 dari libssh2 upstream

**Status: SDK r46 dan transfer QEMU #67 berhasil; satu pemeriksaan diagnostik workflow sudah diperbaiki.**

### Hasil QEMU #67

- ChaCha20-Poly1305 benar-benar dinegosiasikan.
- Satu autentikasi dan satu SSH session.
- Direct: 100.000.000 byte, 19,07 MiB/s, HTTP 200.
- SOCKS5: 100.000.000 byte, 13,03 MiB/s, HTTP 200.
- Retensi SOCKS5 terhadap direct: 68,3%.
- CPU SSH Owner: sekitar 102,5–106,2% dari satu vCPU saat SOCKS5 aktif; empat auxiliary I/O worker tetap 0%.

**Mengapa workflow QEMU #67 tetap berstatus gagal:** semua tes transfer, sesi SSH, dan cipher lulus. Hanya pemeriksaan `Verify S2C timing instrumentation` yang meminta `libssh2_decrypt_path_*` bernilai positif. Itu syarat yang salah untuk ChaCha20-Poly1305. Di libssh2 1.11.1, cipher ChaCha mengatur `LIBSSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET`; `transport.c` lalu memanggil callback `session->remote.crypt->crypt()` langsung, bukan wrapper `decrypt()` yang dihitung oleh diagnostik r43. Akibatnya counter decrypt legacy bernilai nol meskipun data terenkripsi sudah diproses. Counter S2C, transport-read, packet-drain, dan packet-queue justru aktif.

Verifier sudah disesuaikan: counter decrypt legacy boleh nol untuk cipher full-packet, sementara validasi tetap mewajibkan data S2C, transport-read, dan packet-queue aktif. Run #67 tidak diulang supaya tidak membuang kuota untuk mengunduh dua file 100 MB sekali lagi.

SDK r45 #547 berhasil membangun paket, tetapi benchmark QEMU #66 / 45173949790
gagal sebelum listener SOCKS5 siap. Log core hanya mencapai `Starting Key Exchange`;
belum ada sesi SSH terautentikasi, cipher yang dinegosiasikan, atau hasil transfer.
Karena itu r45 tidak menghasilkan angka bandwidth.

Akar kerumitan r45 adalah OpenWrt 24.10.7 masih mematok libssh2 1.11.0, sedangkan
versi tersebut belum mengimplementasikan `chacha20-poly1305@openssh.com`.
Upstream menambahkan implementasi protokol OpenSSH itu pada libssh2 1.11.1.
r46 menaikkan paket ke 1.11.1, mempertahankan diagnostik r43 saja, dan
memprioritaskan ChaCha20-Poly1305 dengan AES-GCM/AES-CTR sebagai fallback.
Percobaan EIP93/AF_ALG dan dependensi modul kernel terkait tidak lagi dipakai.

Sebelum transfer dimulai, skrip QEMU wajib memastikan log menunjukkan cipher
`chacha20-poly1305@openssh.com`. Jika negosiasi atau handshake gagal, dua
download 100 MB tidak akan dijalankan. Desain satu SSH session dan batas
50 detik per download tetap dipertahankan.

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

### r44 — bulk AES-GCM fragment decrypt

<badge color="success">SDK dan QEMU LULUS — throughput belum meningkat</badge>

**Hasil validasi final (23 November 2026):**

- Native regression termasuk tes in-place AES-GCM 24 KiB, AAD, dan invalid-tag rejection lulus pada SDK run #509 (45095624630). Build OpenWrt 24.10.7 SDK `mipsel_24kc` juga lulus, termasuk libssh2 1.11.0 yang dipatch, core r44, dan helper I/O worker.
- Artifact SDK #509: `14783167575`, source SHA `c2f2f24a52466e00eb116b7904d0ad8def4e8297`. Paket `passwall-ssh-core_1.0.0-r44_mipsel_24kc.ipk` SHA-256 `ab03abc97299c1066e72e28fe77f344b4c7691fe662f417a6da6f702813084be`; paket `libssh2-1_1.11.0-r1_mipsel_24kc.ipk` SHA-256 `264d941f25f6ada6b43444569a02f8bf52528e49440e0a3a36a7bfafef03d050`.
- QEMU run #65 (45095948507) sukses dengan kedua IPK dari source SHA yang sama; artifact hasil `14783835785`. Satu transfer direct dan satu SOCKS5 masing-masing menyelesaikan 100.000.000 byte, HTTP 200, dalam batas 50 detik. Direct 27,05 MiB/s; SOCKS5 8,28 MiB/s. Satu autentikasi, satu key establishment, satu SSH session, dan cipher aktual `aes128-gcm@openssh.com` diverifikasi.
- Hasil SOCKS5 r44 (8,28 MiB/s) praktis sama dengan r43 (8,35 MiB/s; sekitar -0,8%). Direct r44 27,05 MiB/s tidak dapat dibandingkan langsung dengan r43 14,45 MiB/s karena IP node Datapacket berbeda (`79.127.235.11` vs `79.127.213.228`). **Tidak ada klaim speedup throughput untuk r44.**
- Jalur bulk terbukti aktif: pada tujuh interval transfer steady, 88.177.152 byte ciphertext diproses melalui 7.840 callback (rata-rata sekitar 11.247 byte/callback), bukan satu callback per blok AES 16 byte. Namun durasi decrypt path mencapai 7,435 detik dari 8,826 detik interval aktif tersebut (84,2%). Ini menunjukkan pengurangan overhead pemanggilan/copy belum menghilangkan biaya komputasi decrypt AES-GCM.
- Sampling 4 vCPU menunjukkan thread `ssh_owner` sekitar 95–105% satu vCPU, sementara keempat auxiliary I/O worker tetap 0%. Ini konsisten dengan satu SSH Owner yang menjalankan libssh2 secara serial; menambah worker I/O tidak memparalelkan state `LIBSSH2_SESSION`.

**Kesimpulan dan arah berikutnya:** r44 berhasil mengurangi granularitas callback dan menghindari temporary-buffer copy pada jalur AES-GCM, tetapi throughput tetap dibatasi CPU decrypt serial. Tahap optimasi berikutnya harus menargetkan backend/cipher crypto, bukan sekadar menambah worker. Evaluasi offload MT7621 perlu memakai cipher yang memang didukung EIP93 (misalnya AES-CTR plus MAC melalui jalur Crypto API/AF_ALG); driver EIP93 OpenWrt tidak menyediakan AES-GCM untuk jalur SSH ini. Hasil QEMU belum menggantikan validasi router MT7621 fisik.
### r43 — instrumentasi internal libssh2

**Hasil validasi final (23 November 2026):**

- SDK run #505 (45089937167) sukses dari source SHA db67210a0c790fd18e65133bae31bd99bd56654a. Native regression, build OpenSSL/zlib, patched libssh2 1.11.0, ekspor kedua simbol diagnostik, build core r43, dan seluruh cross-build helper MIPS lulus. Artifact 14780852255 berisi passwall-ssh-core_1.0.0-r43_mipsel_24kc.ipk serta libssh2-1_1.11.0-r1_mipsel_24kc.ipk; checksum SHA-256 keduanya diverifikasi.
- QEMU benchmark run #64 (45090529026) sukses dan menggunakan SDK artifact dari source SHA yang sama. Artifact hasil 14781795383. Semua tahapan QEMU lulus, termasuk verifikasi satu autentikasi SSH yang diterima, satu session/key establishment, cipher aktual, dan timing internal libssh2. Run benchmark #63 dibatalkan saat dua dispatch SDK berdekatan; run #64 adalah hasil final.
- Datapacket 100.000.000 byte, HTTP 200: direct 6,602 s / 14,45 MiB/s; SOCKS5 11,428 s / 8,35 MiB/s. Pair lulus dengan byte count sama. SOCKS mempertahankan 57,8% dari direct pada run ini.
- Dibanding r42, hasil SOCKS5 r43 secara mentah naik dari 6,93 menjadi 8,35 MiB/s (+20,5%). Ini belum membuktikan speedup dari perubahan kode: server direct r42 adalah 79.127.235.12, sedangkan r43 79.127.213.228; baseline direct masing-masing 23,82 dan 14,45 MiB/s. Endpoint Datapacket memilih node berbeda dan pengujian bukan A/B pada node yang dikunci.
- Emulator preset MT7621A melaporkan empat vCPU. Selama transfer, ssh_owner berada di sekitar 100–107,5% satu vCPU; empat auxiliary I/O worker tetap 0%. Proses tetap satu SSH Owner, satu autentikasi, dan satu session. Ini mengonfirmasi batas serial pada SSH Owner dalam QEMU, bukan bukti pengukuran pada router MT7621 fisik.

**Hasil instrumentasi internal libssh2:**

Sepuluh interval aktif mencakup 100.000.431 byte S2C. Total perf_s2c_read_us adalah 9,553148 s, dengan pembagian berikut:

| Jalur | Waktu | Porsi libssh2_channel_read() |
|---|---:|---:|
| libssh2_decrypt_path_us | 8,558728 s | **89,59%** |
| Receive callback bersarang | 0,363901 s | 3,81% |
| Sisa transport di luar decrypt dan callback | 0,247212 s | 2,59% |
| Drain packet queue | 0,263848 s | 2,76% |
| Sisa pekerjaan channel | 0,119438 s | 1,25% |

Syscall recv() memakai 0,318516 s (3,33% dari channel-read) dan merupakan bagian dari receive callback, bukan biaya tambahan untuk dijumlahkan lagi. Pengiriman S2C ke socket SOCKS memakai 0,288423 s (3,02% dari channel-read) dan tidak menunjukkan EAGAIN atau partial write. Artinya, local socket send dan packet-queue drain bukan bottleneck dominan pada run ini.

**Interpretasi penting:** libssh2_decrypt_path_us adalah durasi helper decrypt(), termasuk pemanggilan crypto backend, loop, dan copy buffer. Ini bukan waktu AES/EVP murni. Namun source libssh2 1.11.0 mengungkap titik yang sangat layak dioptimalkan:

- src/crypt.c mendefinisikan blocksize AES-GCM sebesar 16 byte.
- src/transport.c memproses data melalui loop per blocksize dan memanggil callback cipher untuk tiap potongan.
- src/openssl.c menjalankan EVP_Cipher() pada potongan tersebut, menyalin hasil dari temporary buffer, lalu jalur transport menyalinnya lagi ke destination buffer.

Dengan sekitar 100,16 MB pada decrypt helper, jalur ini memproses pada orde 6,26 juta potongan 16-byte. Jadi bottleneck yang tampak bukan semata-mata AES MIPS lambat; biaya pemanggilan EVP yang sangat kecil-kecil dan salinan berulang kemungkinan berperan besar. Timing r43 belum memisahkan waktu EVP murni dari loop/copy, sehingga pembagian itu masih perlu dibuktikan.

Sumber upstream: [transport.c](https://github.com/libssh2/libssh2/blob/libssh2-1.11.0/src/transport.c), [crypt.c](https://github.com/libssh2/libssh2/blob/libssh2-1.11.0/src/crypt.c), dan [openssl.c](https://github.com/libssh2/libssh2/blob/libssh2-1.11.0/src/openssl.c).

**Antrean internal:** puncak byte queue yang tercatat 2.383.182 byte (sekitar 2,27 MiB); rata-rata snapshot current di batas interval sekitar 939 KB. Ada selisih kecil pada accounting akhir: enqueue dikurangi dequeue menunjukkan satu packet/37.493 byte tersisa, sedangkan gauge akhir melaporkan 0 packet/37.476 byte. Karena itu, angka queue berguna untuk menunjukkan read-ahead yang besar, tetapi packet-count/current-byte gauge masih perlu dirapikan sebelum diperlakukan sebagai accounting eksak.

**Arah optimasi berikutnya:** eksperimen r44 sebaiknya memprioritaskan jalur bulk AES-GCM—memproses ciphertext packet sebagai buffer besar melalui EVP, dengan perlakuan khusus yang benar untuk AAD 4 byte, authentication tag 16 byte, IV/nonce per packet, dan verifikasi tag. Jangan mengganti cipher atau mengubah ring buffer sekaligus. Setelah bulk path terbukti benar lewat tes vector/interoperabilitas SSH, lakukan A/B pada node Datapacket yang sama. Implementasi chacha20-poly1305@openssh.com tetap eksperimen terpisah karena libssh2 1.11.0 belum mendukungnya.

**Status r43:** SDK MIPS dan QEMU bandwidth/diagnostic benchmark LULUS. Optimasi throughput dan validasi pada router MT7621 fisik tetap terbuka.

### r45 — eksperimen offload AES-128-CTR melalui MT7621 EIP93

**IMPLEMENTASI DI-BRANCH — SDK/QEMU DAN UJI FISIK MENUNGGU**

**Tujuan:** mengurangi beban decrypt serial pada satu SSH Owner dengan menggunakan akselerator AES MT7621 bila driver kernel benar-benar tersedia. EIP93 tidak mendukung AES-GCM untuk jalur ini, sehingga eksperimen r45 menggunakan AES-128-CTR dengan MAC SSH terpisah. AES-GCM tetap menjadi fallback otomatis.

Perubahan yang disiapkan:
- Paket MIPS mipsel_24kc menambahkan dependensi kmod-crypto-user dan kmod-crypto-hw-eip93.
- Saat startup, core bind AF_ALG ke nama driver spesifik ctr(aes-eip93), menetapkan salg_feat/salg_mask ke CRYPTO_ALG_KERN_DRIVER_ONLY agar hanya algoritma driver-only yang cocok, memasang kunci AES-128, lalu menjalankan request enkripsi 1 KiB dengan timeout 2 detik. Nama generik ctr(aes) tidak pernah dipakai untuk mendeteksi hardware. Driver yang hanya bisa di-bind tetapi tidak dapat menyelesaikan request tidak akan dipilih.
- Jika driver spesifik tidak tersedia, urutan cipher tetap memprioritaskan aes128-gcm@openssh.com. Jika tersedia, AES-128-CTR diprioritaskan; cipher aktual setelah KEX tetap dicatat dalam log.
- Patcher libssh2 1.11.0 menambahkan backend AF_ALG yang hanya meminta ctr(aes-eip93). Potongan di bawah 1 KiB memakai OpenSSL software sambil meneruskan counter IV; fragmen besar yang block-aligned diproses sebagai satu operasi AF_ALG. Jalur encrypt dan decrypt dibatch agar tidak mengirim potongan 16 byte ke driver.
- Karena konfigurasi OpenWrt menetapkan software fallback AES-128 sampai 512 byte, batas 1 KiB dipakai untuk menghindari jalur request kecil yang sengaja dialihkan ke software oleh driver.
- Diagnostik membedakan eip93_ctr_hw_bytes dan eip93_ctr_sw_bytes. Non-zero hardware bytes hanya dicatat setelah operasi pada backend driver spesifik berhasil, bukan hanya karena nama cipher dipilih.
- Native test tests/afalg_ctr_test.c menguji AES-CTR NIST known-answer, operasi 32 KiB (sesuai ukuran paket SSH), kontinuitas IV antara batch 1 KiB, dan decrypt round-trip. SDK juga membangun helper statis MIPS afalg-ctr-test untuk uji pada router; jalankan AFALG_CTR_DRIVER='ctr(aes-eip93)' ./afalg-ctr-test.

**Batas validasi:** QEMU MT7621 hanya memvalidasi fallback atau jalur yang benar-benar disediakan emulator. Keberhasilan SDK dan QEMU tidak membuktikan EIP93 bekerja di router fisik. Kriteria bukti hardware adalah helper MIPS berhasil dengan AFALG_CTR_DRIVER=ctr(aes-eip93), log core menunjukkan AES-128-CTR, dan interval PERF mencatat libssh2_eip93_ctr_hw_bytes non-zero. Jika driver spesifik gagal di-bind atau dijalankan, core harus tetap menggunakan AES-GCM fallback.

Pengujian benchmark tetap dibatasi ke satu endpoint Datapacket, masing-masing satu download direct dan satu SOCKS5 berukuran 100 MB, timeout 50 detik per transfer, tanpa retry, satu autentikasi dan satu SSH session. Hasil kecepatan dan kelulusan build belum tersedia pada tahap pencatatan ini.


### r45 SDK attempt #543 — failure diagnosis and patcher correction

SDK run #543 (45170164738) passed native regressions and downloaded the OpenWrt 24.10.7 SDK, but failed while compiling patched libssh2 1.11.0. The r45 transport patcher had replaced the closing tail of the r44 AES-GCM fast path when inserting the CTR branch. This left decrypt() structurally unclosed; GCC then reported invalid storage class for following file-scope functions and an end-of-input error. This was a patcher-generated C syntax defect, not an EIP93 driver or MIPS toolchain failure.

The patcher now preserves the full r44 AES-GCM fast path verbatim, then inserts the r45 AES-CTR batch branch after its closing brace and before the legacy block loop. The transmit-side CTR replacement remains scoped to the original encryption loop. The corrected patcher has not yet been rebuilt; SDK validation is pending. No r45 IPK or QEMU benchmark was produced by run #543.
