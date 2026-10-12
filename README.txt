FORENSIK RUNNER - cara pakai
Pembuat aplikasi: APH4NC-Dit.P2-DJP-KEMENKEU
1. Klik kanan JALANKAN.bat > Run as administrator (di komputer yang diperiksa).
2. Isi identitas pemeriksaan (NPWP, SP2, Surat Tugas, pemeriksa, tenaga ahli), pilih folder hasil (disarankan media eksternal).
3. Klik "JALANKAN SEMUA & BUAT LAPORAN PDF". Hasil: <folder hasil>\<NPWP>_<waktu>\Laporan_PDF, Data_Mentah, manifest.csv, log_proses.txt.
CLI: python forensik_app.py --cli --case case_contoh.json --out E:\Hasil   |   python forensik_app.py --info
Perlu Python 3.8+ dan "pip install reportlab" (JALANKAN.bat memasangnya otomatis bila ada internet). Spesifikasi: PRD.md

KAPE (opsional): bila folder KAPE ada di folder alat (mis. tools\kape\KAPE), kelengkapannya otomatis diperiksa dan dimuat di laporan.
Eksekusi KAPE hanya jika dicentang di aplikasi (ada konfirmasi) atau CLI: --kape live|triage|sans|kapetriage|custom --kape-yes
  python forensik_app.py --kape-check            (periksa kelengkapan saja, tidak menjalankan apa pun)
  python forensik_app.py --cli --case case.json --kape live --kape-dry   (susun perintah KAPE tanpa menjalankannya)

BAB INTEGRASI HASIL LINTAS ALAT (Laporan Final, setelah Ringkasan)
- Menggabungkan keluaran seluruh alat: matriks cakupan tema x alat, linimasa terpadu (maks. 300 peristiwa terbaru;
  lengkap di Data_Mentah\Integrasi_Linimasa.csv), korelasi nomor seri USB (USBDeview/USBDriveLog/USBLogView),
  jejak akses berkas pada drive removable, dan indikator kata kunci.
- Daftar kata kunci ada di indikator_kata_kunci.json (dibuat otomatis saat pertama jalan; boleh diedit petugas,
  mis. menambah nama bank, marketplace, atau aplikasi tertentu).
- Semua isi bab ini adalah INDIKATOR untuk ditelaah pemeriksa, bukan bukti atau simpulan. Bila format tanggal tidak
  dapat dipastikan (dd/mm atau mm/dd) dipakai asumsi dd/mm dan ditandai pada laporan.

ALAT TAMBAHAN (ChromeHistoryView, MozillaHistoryView, IEHV, IPNetInfo)
- ChromeHistoryView, MozillaHistoryView (ada versi x64), dan IEHV dijalankan otomatis seperti alat lain.
  IEHV tidak punya /scomma sehingga diekspor dengan /stab (berkas .txt bertab di Data_Mentah).
- IPNetInfo TIDAK dijalankan otomatis (GUI saja dan mengirim kueri whois lewat internet). Aplikasi mengumpulkan
  alamat IPv4 publik dari riwayat peramban dan LastActivityView ke Data_Mentah\Daftar_IP_Publik.txt. Telusuri manual
  di komputer lain yang terhubung internet:  ipnetinfo.exe /ipfile Daftar_IP_Publik.txt

LAPORAN INTEGRASI
- Setiap pelaksanaan menghasilkan 00_LAPORAN_FINAL_*.pdf (gabungan semua alat + bab integrasi) dan
  01_LAPORAN_INTEGRASI_*.pdf (laporan mandiri: identitas, status semua alat, bab integrasi).
- Membangun ulang tanpa menjalankan alat lagi: tombol "Buat laporan integrasi dari folder hasil..." di aplikasi,
  atau  python forensik_app.py --rebuild "<folder hasil>"  (laporan lama tidak ditimpa; bab KAPE tidak ikut).

ANALISIS TINGKAT-KASUS (bab integrasi dan Laporan Integrasi)
- Pengaitan huruf drive -> perangkat USB -> serial -> jejak akses (awal-akhir), disertai anomali: waktu 'created' identik,
  akses sebelum 'created', huruf dipakai ganda, huruf tanpa perangkat USB (mungkin drive jaringan), perangkat USB tanpa
  huruf drive, serial tidak unik. Semua berstatus indikator.
- Host dan share jaringan (UNC), serta penelusuran kata kunci kasus yang diisi petugas pada kolom "Kata kunci kasus".
- Validasi ke artefak sumber: bila KAPE dijalankan dengan modul parser (profil triage/sans/kapetriage), petunjuk NirSoft dicari
  di seluruh CSV keluaran KAPE_Modul; hasil "terkonfirmasi: ya/belum" per petunjuk. Setelah KAPE selesai, bangun ulang laporan
  bila perlu (tombol "Buat laporan integrasi dari folder hasil...").
- Laporan Integrasi memuat lampiran: Matriks Uji Bukti (terisi sebagian), Acquisition Log, Chain of Custody, dan daftar
  periksa peer review. Isian opsional baru: ID perkara, nomor berita acara, perwakilan WP/saksi, kata kunci kasus.
- Setiap bab alat memuat versi alat (FileVersion) dan catatan kehati-hatian. Alat NirSoft membaca profil akun Windows yang
  menjalankan aplikasi: jalankan pada sesi akun yang diperiksa atau kumpulkan NTUSER.DAT/UsrClass.dat lewat KAPE.

ALAT TAMBAHAN 2 (CurrPorts, OpenedFilesView, SysExporter)
- CurrPorts (koneksi/port aktif) dan OpenedFilesView (berkas yang sedang dibuka) dijalankan otomatis; keduanya snapshot saat
  pelaksanaan. CurrPorts dijalankan tanpa pemetaan DNS. Koneksi SMB (port 445/139) ditampilkan pada bab integrasi.
- SysExporter TIDAK dijalankan otomatis (perlu menentukan jendela target). Contoh manual:
  sysexp.exe /Process <aplikasi.exe> /Class SysListView32 /Visible Yes /scomma Data_Mentah\ekspor.csv


PEMBARUAN APLIKASI (dari GitHub)
--------------------------------
Tombol "Pembaruan..." di bilah bawah aplikasi:
 1. Isi repositori GitHub (format pemilik/nama). Token hanya perlu untuk repositori privat.
 2. Klik "Periksa & pasang pembaruan". Aplikasi menampilkan versi dan catatan rilis, lalu meminta konfirmasi.
 3. Paket diunduh, diverifikasi SHA-256, berkas lama dicadangkan ke folder _backup_versi, lalu diganti. Mulai ulang aplikasi.
 4. "Kembalikan versi sebelumnya" memulihkan cadangan terakhir.
Yang TIDAK disentuh: config.json, folder alat (tools), folder hasil/data kasus. Berkas .json pengaturan (mis. indikator_kata_kunci.json)
tidak ditimpa; versi baru disimpan sebagai *.json.baru. Pembaruan tanpa checksum ditolak. Aplikasi hanya mengunduh, tidak mengirim data kasus.
Pemeriksaan otomatis saat dibuka bersifat opsional (default mati).
CLI: python forensik_app.py --update-check | --update | --rollback

Menerbitkan versi baru (untuk pembuat aplikasi):
 1. Naikkan APP_VERSION di forensik_core.py (mis. "1.2").
 2. Jalankan: python buat_rilis.py  -> dist\ForensikRunner-v1.2.zip dan .sha256
 3. Di GitHub: Releases > Draft new release > tag v1.2 > lampirkan kedua berkas > Publish release.
Gunakan repositori privat/terkendali dengan autentikasi dua langkah; checksum melindungi dari unduhan rusak, bukan dari repositori yang disusupi.


MENGUNGGAH APLIKASI KE GITHUB (repositori andri-puspo/forensik_runner_P2_DJP)
-----------------------------------------------------------------------------
Dari folder ForensikRunner (Command Prompt / PowerShell), sekali saja:
  git init -b main
  git add .
  git commit -m "Forensik Runner v1.1"
  git remote add origin https://github.com/andri-puspo/forensik_runner_P2_DJP.git
  git push -u origin main
(.gitignore sudah mengecualikan config.json, dist, _backup_versi. Folder alat NirSoft/KAPE berada di luar folder ini dan tidak ikut terunggah.)
Menerbitkan rilis agar tombol Check Update bekerja:
  python buat_rilis.py
  gh release create v1.1 dist\ForensikRunner-v1.1.zip dist\ForensikRunner-v1.1.zip.sha256 --title "v1.1" --notes "Catatan rilis"
  (atau lewat web: Releases > Draft a new release > tag v1.1 > lampirkan kedua berkas > Publish release)
Repositori privat: buat token "fine-grained" hanya untuk repositori ini dengan izin Contents: Read-only, lalu tempel di dialog Pembaruan.
