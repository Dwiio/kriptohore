# KRIPTOHORE — Localhost Edition

Aplikasi berjalan sepenuhnya di Mac/PC lokal: frontend HTML/CSS/JS, backend Node.js, MySQL/MariaDB XAMPP, dan pemantauan Memory Camera Dongle.

## Persyaratan
- Node.js 20 atau lebih baru
- XAMPP dengan MySQL/MariaDB
- Browser modern
- macOS: microSD kamera terbaca sebagai volume di `/Volumes`
- Windows: microSD diberi drive letter (scanner memeriksa D: sampai G: secara default)

## Instalasi
1. Ekstrak ZIP.
2. Jalankan MySQL dari XAMPP.
3. Buka `http://localhost/phpmyadmin`, buat/import database dengan mengimpor `database/schema.sql`.
4. Salin `.env.example` menjadi `.env`, sesuaikan konfigurasi database bila perlu.
5. Jalankan Terminal di folder project:
   ```bash
   npm install
   npm start
   ```
6. Buka `http://localhost:4177`.
7. Salin `provisioning/MEMORY_CAMERA_DONGLE.key` ke root microSD kamera. Jangan rename file.
8. Pastikan status dongle berubah menjadi CONNECTED.
9. Pada startup pertama, backend membuat hash Argon2id untuk akun `demo` dan menyimpannya ke `users.password_hash` jika kolom tersebut masih NULL.
10. Login dengan username `demo` dan password awal `kriptohore`. Setelah berhasil, password diverifikasi server-side terhadap hash Argon2id di MySQL.

## Fingerprint / Touch ID
Pilih **Masuk dengan Touch ID**. Browser harus mendukung WebAuthn dan platform authenticator. Penggunaan pertama mendaftarkan passkey pada browser/perangkat; penggunaan berikutnya meminta verifikasi ulang. Ini adalah demo autentikasi platform lokal; endpoint helper menerima sinyal sukses dari frontend setelah WebAuthn selesai. Untuk produksi/penilaian keamanan tingkat tinggi, assertion harus diverifikasi server-side dengan challenge dan public key yang tersimpan di database.

## Dongle
Node backend memeriksa volume removable setiap 500 ms:
- macOS: `/Volumes/<VOLUME>/MEMORY_CAMERA_DONGLE.key`
- Linux: `/media/<user>` dan `/run/media/<user>`
- Windows: drive D: sampai G: (ubah `DRIVE_SCAN_ROOTS` pada `backend/server.js` jika perlu).

Dongle divalidasi dengan SHA-256 file. Jika dongle yang valid dicabut saat sesi aktif, UI mengirim logout dan kembali ke layar login. Pemantauan browser berjalan setiap 500 ms; waktu lock aktual bergantung pada scheduler browser/OS. File key dapat disalin, jadi ini bukan secure element anti-cloning.

## Login password dengan Argon2id
- Frontend mengirim username/password ke endpoint lokal; tidak ada lagi hash password tetap atau verifikasi PBKDF2 di browser.
- Backend mengambil `password_hash` dari tabel `users` dan memverifikasinya dengan Argon2id.
- Saat startup, backend menambahkan kolom `password_hash` bila database lama belum memilikinya.
- Untuk akun demo lama yang kolomnya NULL, backend membuat hash dari `DEMO_INITIAL_PASSWORD` (default `kriptohore`) sekali saja. Hash yang sudah terisi tidak ditimpa.
- Jika ingin mengganti password awal sebelum bootstrap pertama, ubah `DEMO_INITIAL_PASSWORD` pada `.env`. Penggantian password setelah hash terbentuk perlu dilakukan melalui mekanisme reset password yang terautentikasi atau update hash Argon2id dari backend.

## Modul kriptografi
- Login password: Argon2id (memory 64 MiB, time cost 3, parallelism 1); hash tersimpan di `users.password_hash`, verifikasi hanya di backend.
- Teks: Vigenère klasik → AES-256-GCM.
- File: AES-256-CTR + HMAC-SHA-256 (encrypt-then-MAC).
- Secret Notes: AES-256-GCM di browser; database hanya menerima ciphertext JSON.
- Steganografi: AES-256-GCM lalu LSB RGB; simpan PNG.
- Blockchain: SHA-256 chaining + proof-of-work ringan (prefix `000`).

## Catatan keamanan dan demo
- Gunakan hanya data demo, bukan rahasia produksi.
- Server hanya bind ke `127.0.0.1`, tidak dibuka ke jaringan.
- Session disimpan di MySQL pada `user_sessions`; cookie hanya memuat token acak, sedangkan database menyimpan SHA-256 token. Session berlaku 30 menit dan dihapus saat logout/expired.
- Touch ID client flow pada paket ini tetap merupakan prototipe lokal, bukan implementasi WebAuthn server-verified; sesuai permintaan, mekanisme verifikasi Touch ID dan pemeriksaan dongle tidak diubah. Keduanya tetap menjadi pengecualian dari audit keamanan penuh.
- Jangan menganggap microSD file dongle tidak dapat dikloning.
