# p

**Ultra-Lightweight Multiplatform Remote Access Tool (SSH-like Server & Client)**

`p` adalah alat akses dan kendali jarak jauh (remote access) lintas platform (Windows, Linux, macOS) yang dibangun dengan **Rust**. Dirancang sebagai alternatif modern yang sangat ringan (< 8 MB RAM), cepat, aman dengan enkripsi *end-to-end* Noise Protocol sekelas WireGuard, dan praktis tanpa konfigurasi rumit (*zero-config single binary*).

Menggunakan filosofi dan terminologi yang sama dengan **SSH**:
* **Server** (seperti `sshd`): Berjalan di komputer/server target. Menunggu koneksi, melayani eksekusi terminal, transfer file, dan mounting drive. **Mendukung banyak klien sekaligus (multi-client)** secara *asynchronous* melalui Tokio.
* **Client** (seperti `ssh`): Berjalan di laptop/komputer admin untuk terhubung ke Server, masuk ke interactive shell, transfer file, atau tunneling port.

---

## ⚡ Quick Install & Update (Satu Baris Perintah)

Jalankan perintah ini di terminal untuk langsung mengunduh/memperbarui `p` versi terbaru dan mendaftarkannya ke PATH sistem:

### 🪟 Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/n0z0/p/main/install.ps1 | iex
```
*(Otomatis mengunduh `p.exe`, memasang di `~/.p/bin`, dan mendaftarkannya ke User PATH)*

### 🐧 Linux & 🍏 macOS (Terminal / Shell)
```bash
curl -fsSL https://raw.githubusercontent.com/n0z0/p/main/install.sh | bash
```
*(Otomatis mendeteksi OS & arsitektur, memasang di `~/.local/bin/p`, dan memperbarui PATH shell)*

---

## 🚀 Quick Start (Cara Penggunaan)

Seluruh fungsi Server dan Client tergabung dalam satu file biner tunggal: **`p`**.

### 1. Menjalankan Server di Komputer Target (seperti `sshd`)
Jalankan `p` tanpa argumen di komputer atau server yang ingin dikendalikan:

```bash
# Jalankan Server di port default 9999:
p

# Atau tentukan port kustom:
p -p 8080
```

> **Catatan Multi-Client & Keamanan:**
> * **Multi-Client:** Server otomatis melayani banyak Client secara bersamaan (*concurrent*). Tiap koneksi Client diisolasi dalam thread async (`tokio::spawn`) dengan kunci sesi enkripsinya masing-masing.
> * **Pairing Token:** Saat pertama kali dijalankan, Server membuat kunci host di `~/.p/agent.key` dan menampilkan **Pairing Token** (password otorisasi) untuk Client pertama kali.

---

### 2. Menghubungkan Client dari Laptop Admin (seperti `ssh`)
Cukup tentukan alamat target Server untuk masuk ke sesi remote shell interaktif:

```bash
p 1.2.3.4:9999
```

**Tampilan Sesi Interaktif:**
```text
🔍 Menghubungi Server di 1.2.3.4:9999 untuk verifikasi kunci publik (TOFU)...
🔒 KUNCI PUBLIK SERVER TERVERIFIKASI: SHA256:4b...
🔒 Server membutuhkan otorisasi untuk Client baru.
🔑 Masukkan Password / Pairing Token: ********
✅ Pairing berhasil! Kunci Client telah diotorisasi di Server (~/.p/authorized_controllers).

══════════════════════════════════════════════════════════
💻 SESI INTERAKTIF REMOTE SHELL (p)
   Target Server : 1.2.3.4:9999
   Bantuan       : Ketik 'help' untuk daftar perintah khusus
   Keluar        : Ketik 'exit' atau tekan Ctrl+C
══════════════════════════════════════════════════════════
p[1.2.3.4:9999]> whoami
root
p[1.2.3.4:9999]> stats
📊 CPU: 1.20% | RAM: 320 MB
p[1.2.3.4:9999]> mount P:
🔌 Menghubungkan drive P: ke File Explorer...
✅ Berhasil! File server kini terbuka di Drive P:.
p[1.2.3.4:9999]> exit
```

> **Zero-Friction:** Pada koneksi berikutnya, Client langsung terhubung tanpa perlu memasukkan token lagi karena kunci Client telah terdaftar di whitelist `~/.p/authorized_controllers` Server.

---

### 3. Menembus NAT / Firewall (`-r` / `--reverse`)
Jika Server berada di balik **NAT ketat, Firewall, atau Modem Seluler/4G** (tidak memiliki IP publik):

1. **Di Laptop Client Admin (Menunggu sambungan Server):**
   ```bash
   p -r
   ```
2. **Di Server Target (Menghubung keluar menembus NAT ke Client):**
   ```bash
   p <IP_LAPTOP_ADMIN>:9999 -r
   ```
   *(Server otomatis mencoba menghubung ulang jika koneksi terputus dengan fitur Auto-Reconnect Exponential Backoff)*

---

### 4. Mount Filesystem Server ke File Explorer Windows
Buka dan kelola file Server secara visual langsung dari File Explorer Windows layaknya flashdisk lokal:

* **Dari dalam sesi interaktif:**
  ```text
  p[1.2.3.4:9999]> mount P:
  ```
* **Atau langsung dari terminal:**
  ```bash
  p 1.2.3.4:9999 mount P:
  ```
  *(Untuk melepas drive: ketik `unmount` di dalam shell)*

---

### 5. Port Forwarding Bergaya SSH (`-L` & `-R`)

#### Local Port Forwarding (`-L`)
Membuka port di komputer Client yang diteruskan ke port internal Server:
```bash
# Akses database MySQL server (port 3306) via localhost:3306:
p 1.2.3.4:9999 -L 3306:3306

# Akses web server internal server (port 80) via localhost:8080:
p 1.2.3.4:9999 -L 8080:80
```

#### Remote Port Forwarding (`-R`)
Membuka port di sisi Server yang diteruskan kembali ke aplikasi di komputer Client:
```bash
# Membuka port 9090 di server target yang mengarah ke localhost:8080 client:
p 1.2.3.4:9999 -R 9090:8080
```

---

### 6. Perintah Sekali Jalan (CLI Scripting Cheat Sheet)

```bash
# Cek penggunaan CPU & RAM Server
p 1.2.3.4:9999 stats

# Eksekusi perintah terminal tanpa masuk ke shell interaktif
p 1.2.3.4:9999 exec "systemctl restart nginx"

# Upload file ke Server
p 1.2.3.4:9999 upload ./project.zip

# Download file dari Server
p 1.2.3.4:9999 download /var/log/nginx/access.log ./access.log

# Rotasi kunci sesi enkripsi Noise
p 1.2.3.4:9999 rekey

# Matikan Server dari jarak jauh
p 1.2.3.4:9999 shutdown

# Buat pasangan kunci kriptografi Noise baru
p keygen
```

---

## 🛠️ Informasi Teknis & Developer

Untuk dokumentasi arsitektur internal, spesifikasi protokol biner, multiplexing channel, dan panduan kompilasi dari source code, silakan baca **[DEV.md](DEV.md)**.
