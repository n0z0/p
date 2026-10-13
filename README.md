# p

**Ultra-Lightweight Multiplatform Remote Control & Access Tool**

`p` adalah alat kendali jarak jauh (remote access) lintas platform (Windows, Linux, macOS) yang dibangun dengan **Rust**. Dirancang sebagai alternatif modern yang sangat ringan (< 8 MB RAM), cepat, aman dengan enkripsi *end-to-end* Noise Protocol sekelas WireGuard, dan praktis tanpa konfigurasi rumit (*zero-config single binary*).

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

Seluruh fungsi tergabung dalam satu file biner: **`p`**.

### 1. Menjalankan di Target / Server (Mode Agent)
Jalankan `p` tanpa argumen di komputer/server yang ingin dikendalikan. Server otomatis mendengarkan koneksi di port default `9999`:

```bash
# Jalankan agent di port default 9999:
p

# Atau tentukan port kustom:
p -p 8080
```

> **Catatan Keamanan:** Saat pertama kali dijalankan, `p` otomatis membuat kunci persisten di `~/.p/agent.key` dan menampilkan **Pairing Token** (password otorisasi satu kali) untuk menghubungkan Controller pertama kali.

---

### 2. Menghubungkan dari Komputer Admin (Interactive Shell)
Cukup tentukan alamat target server untuk masuk ke sesi remote shell interaktif (seperti SSH):

```bash
p 1.2.3.4:9999
```

**Tampilan Sesi Interaktif:**
```text
🔍 Menghubungi Agent di 1.2.3.4:9999 untuk mengambil identitas kunci publik (TOFU)...
🔒 KUNCI PUBLIK AGENT TERVERIFIKASI: SHA256:4b...
🔒 Agent membutuhkan otorisasi untuk Controller baru.
🔑 Masukkan Password / Pairing Token: ********
✅ Pairing berhasil! Kunci Controller telah diotorisasi di Agent (~/.p/authorized_controllers).

══════════════════════════════════════════════════════════
💻 SESI INTERAKTIF REMOTE SHELL (p)
   Target Host : 1.2.3.4:9999
   Bantuan     : Ketik 'help' untuk daftar perintah khusus
   Keluar      : Ketik 'exit' atau tekan Ctrl+C
══════════════════════════════════════════════════════════
p[1.2.3.4:9999]> whoami
root
p[1.2.3.4:9999]> stats
📊 CPU: 1.20% | RAM: 320 MB
p[1.2.3.4:9999]> mount P:
🔌 Menghubungkan drive P: ke File Explorer...
✅ Berhasil! Remote files kini terbuka di Drive P:.
p[1.2.3.4:9999]> exit
```

> **Zero-Friction:** Pada koneksi berikutnya, Controller langsung terhubung tanpa perlu memasukkan password lagi karena kunci Controller telah masuk whitelist `~/.p/authorized_controllers`.

---

### 3. Menembus NAT / Firewall (`-r` / `--reverse`)
Jika Server/Target berada di balik **NAT ketat, Firewall, atau Modem Seluler/4G** (tidak punya IP publik):

1. **Di Laptop/Server Admin (Listener):**
   ```bash
   p -r
   ```
2. **Di Server/Target (Agent):**
   ```bash
   p <IP_LAPTOP_ADMIN>:9999 -r
   ```
   *(Agent otomatis mencoba menghubung ulang jika koneksi internet terputus dengan fitur Auto-Reconnect Exponential Backoff)*

---

### 4. Mount Remote Filesystem ke File Explorer Windows
Buka dan kelola file server remote langsung dari File Explorer Windows layaknya flashdisk lokal:

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
Membuka port di komputer lokal yang diteruskan ke port internal server target:
```bash
# Akses database MySQL server (port 3306) via localhost:3306:
p 1.2.3.4:9999 -L 3306:3306

# Akses web server internal target (port 80) via localhost:8080:
p 1.2.3.4:9999 -L 8080:80
```

#### Remote Port Forwarding (`-R`)
Membuka port di sisi server target yang diteruskan kembali ke aplikasi di komputer Anda:
```bash
# Membuka port 9090 di server target yang mengarah ke localhost:8080 admin:
p 1.2.3.4:9999 -R 9090:8080
```

---

### 6. Perintah Sekali Jalan (CLI Scripting Cheat Sheet)

```bash
# Cek penggunaan CPU & RAM target
p 1.2.3.4:9999 stats

# Eksekusi perintah terminal tanpa masuk ke shell interaktif
p 1.2.3.4:9999 exec "systemctl restart nginx"

# Upload file ke target
p 1.2.3.4:9999 upload ./project.zip

# Download file dari target
p 1.2.3.4:9999 download /var/log/nginx/access.log ./access.log

# Rotasi kunci sesi enkripsi Noise
p 1.2.3.4:9999 rekey

# Matikan server target dari jarak jauh
p 1.2.3.4:9999 shutdown

# Buat pasangan kunci kriptografi Noise baru
p keygen
```

---

## 🛠️ Informasi Teknis & Developer

Untuk dokumentasi arsitektur internal, spesifikasi protokol biner, multiplexing channel, dan panduan kompilasi dari source code, silakan baca **[DEV.md](DEV.md)**.
