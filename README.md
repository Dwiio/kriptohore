# KRIPTOHORE — Localhost Edition

Aplikasi berjalan sepenuhnya di Mac/PC lokal: frontend HTML/CSS/JS, backend Node.js, MySQL/MariaDB XAMPP, dan pemantauan Memory Camera Dongle.

---

## 📸 Tampilan Antarmuka (UI)

### 1. Halaman Login
Halaman autentikasi awal yang mendukung verifikasi akun berbasis password dengan Argon2id serta dukungan login biometrik (Touch ID / WebAuthn). Indikator status dongle dan sistem keamanan lokal ditampilkan di bagian atas.

![Halaman Login](login%20kriptohore.jpg)

### 2. Dashboard Utama & Menu Navigasi
Pusat kendali (*Security Dashboard*) yang menampilkan status koneksi perangkat keras (*Memory Camera Dongle*), database MySQL/MariaDB, serta mesin enkripsi yang aktif. Menu navigasi di sebelah kiri memberikan akses cepat ke berbagai modul kriptografi lanjutan.

![Dashboard Utama](menu%20kriptohore.jpg)

---

## 📋 Persyaratan Sistem
- **Node.js**: Versi 20 atau lebih baru.
- **XAMPP**: Dilengkapi dengan MySQL/MariaDB.
- **Browser**: Browser modern yang mendukung WebAuthn (Chrome/Safari/Edge).
- **macOS**: MicroSD kamera terbaca sebagai volume di `/Volumes`.
- **Windows**: MicroSD diberi *drive letter* (scanner memeriksa `D:` sampai `G:` secara default).

---

## ⚙️ Panduan Instalasi
1. Ekstrak file ZIP proyek ke direktori lokal Anda.
2. Nyalakan layanan MySQL dari control panel XAMPP.
3. Buka `http://localhost/phpmyadmin`, buat database baru, lalu lakukan *import* file `database/schema.sql`.
4. Salin file `.env.example` menjadi `.env`, lalu sesuaikan konfigurasi database bila diperlukan.
5. Buka Terminal pada folder proyek, kemudian jalankan perintah berikut:
   ```bash
   npm install
   npm start
   ```
6. Buka browser dan akses `http://localhost:4177`.
7. Salin file `provisioning/MEMORY_CAMERA_DONGLE.key` ke direktori *root* microSD kamera Anda (jangan mengubah nama file).
8. Pastikan status dongle pada aplikasi berubah menjadi **CONNECTED**.
9. Pada startup pertama, backend akan membuat hash Argon2id untuk akun `demo` dan menyimpannya ke kolom `users.password_hash`.
10. Login menggunakan username `demo` dan password awal `kriptohore`.

---

## 🛠️ Penjelasan Modul & Menu Kriptografi

Berikut adalah rincian modul dan program yang tersedia pada bilah navigasi kiri aplikasi:

### 1. Super Enkripsi Teks
* **Fungsi:** Mengamankan pesan teks rahasia menggunakan kombinasi enkripsi berlapis.
* **Mekanisme:** Menggabungkan enkripsi klasik *Vigenère cipher* sebagai lapisan awal, yang kemudian diproses lebih lanjut menggunakan standar enkripsi modern **AES-256-GCM** untuk menjamin kerahasiaan dan integritas data teks secara optimal.

### 2. Secure File Vault
* **Fungsi:** Menyimpan dan mengenkripsi berkas/file penting secara lokal agar aman dari akses yang tidak sah.
* **Mekanisme:** Menggunakan kombinasi **AES-256-CTR** dan **HMAC-SHA-256** (*encrypt-then-MAC*) guna memastikan file yang didekripsi tidak mengalami manipulasi data di tingkat byte.

### 3. Secret Notes
* **Fungsi:** Ruang catatan rahasia berbasis web yang terenkripsi langsung di sisi klien (*client-side*).
* **Mekanisme:** Mengenkripsi teks catatan menggunakan **AES-256-GCM** di dalam browser pengguna; database hanya menerima dan menyimpan data dalam format *ciphertext* JSON yang aman.

### 4. Image Steganography
* **Fungsi:** Menyembunyikan pesan rahasia di dalam file gambar tanpa mengubah tampilan visualnya secara mencolok.
* **Mekanisme:** Pesan terlebih dahulu dienkripsi menggunakan **AES-256-GCM**, lalu disisipkan ke dalam data piksel gambar menggunakan teknik *Least Significant Bit* (LSB) pada komponen warna RGB, kemudian disimpan ke format PNG.

### 5. Blockchain Ledger
* **Fungsi:** Simulasi buku besar digital terdesentralisasi yang mencatat transaksi atau histori data secara transparan dan aman.
* **Mekanisme:** Menerapkan teknik *SHA-256 chaining* (penautan hash antar blok) yang dikombinasikan dengan *proof-of-work* ringan (prefix `000`) untuk menjaga integritas urutan data.

### 6. Device Security (Pengaturan Perangkat)
* **Fungsi:** Memantau status dan konfigurasi keamanan perangkat keras eksternal (*Memory Camera Dongle*).
* **Mekanisme:** Berjalan mendeteksi keberadaan file kunci fisik pada media *removable* secara berkala untuk memastikan sesi pengguna tetap sah.

---

## 👆 Fingerprint / Touch ID
Pilih **Masuk dengan Touch ID**. Browser harus mendukung WebAuthn dan *platform authenticator*. Penggunaan pertama mendaftarkan *passkey* pada perangkat; penggunaan berikutnya meminta verifikasi biometrik ulang. Untuk produksi/keamanan tingkat tinggi, *assertion* harus diverifikasi secara *server-side* dengan *challenge* dan *public key* tersimpan di database.

---

## 🔑 Sistem Dongle & Keamanan
- Node backend memeriksa volume *removable* setiap 500 ms:
  - **macOS:** `/Volumes/<VOLUME>/MEMORY_CAMERA_DONGLE.key`
  - **Linux:** `/media/<user>` dan `/run/media/<user>`
  - **Windows:** Drive `D:` sampai `G:` (dapat diubah via `DRIVE_SCAN_ROOTS` pada `backend/server.js`).
- Dongle divalidasi dengan SHA-256 file. Jika dongle yang valid dicabut saat sesi aktif, UI otomatis mengirim perintah *logout* dan kembali ke layar login.

---

## 🔐 Login Password dengan Argon2id
- Frontend mengirim kredensial ke endpoint lokal; tidak ada lagi hash password tetap atau verifikasi PBKDF2 di browser.
- Backend mengambil `password_hash` dari tabel `users` dan memverifikasinya secara aman menggunakan Argon2id (memory 64 MiB, time cost 3, parallelism 1).

---

## ⚠️ Catatan Keamanan & Demo
- Gunakan hanya untuk data simulasi/demo akademik, bukan data rahasia produksi.
- Server hanya melakukan *bind* ke `127.0.0.1` (tidak diekspos ke jaringan publik).
- Sesi disimpan di MySQL pada tabel `user_sessions` dengan masa berlaku 30 menit.
