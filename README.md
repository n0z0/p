# Custom Lightweight Multiplatform Remote Control Agent

Sistem kendali jarak jauh kustom (Custom Remote Access Agent) lintas platform yang didesain dengan fokus pada performa ekstrem, efisiensi memori tingkat tinggi, dan keamanan kriptografi yang ketat. 

Proyek ini dibangun sepenuhnya menggunakan **Rust** untuk menggantikan protokol berat (seperti HTTP/gRPC) atau agen standar yang boros *resource*.

## 🚀 Arsitektur Teknis (Tech Stack)

Sistem ini memangkas seluruh *overhead* tradisional dengan mengombinasikan komponen-komponen berikut:
* **Transport:** `Tokio` (Raw TCP Socket Async) – Beban jaringan minimal tanpa HTTP Header.
* **Serialization:** `Bincode` (Zero-Fluff Binary) – Mengubah *Struct/Enum* Rust langsung menjadi biner mentah yang jauh lebih ringan dari JSON/Protobuf.
* **Security:** `Snow` (Noise Protocol Framework) – Enkripsi *end-to-end* modern sekelas WireGuard dengan proses *handshake* kilat (1-2 paket data) dan *wire overhead* minimal (~16-32 byte per paket).
* **Target OS:** Multiplatform tunggal (Linux, Windows, macOS) berbasis satu *codebase*.

---

## 🧠 Konsep & Peran: Agent vs. Controller

Dalam sistem kendali jarak jauh ini, komponen aplikasi dibagi menjadi dua modul terpisah dengan peran yang tidak sama rata:

```text
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│           CONTROLLER            │                 │              AGENT              │
│  (Laptop / PC Administrator)    │                 │ (Server / VPS / Perangkat IoT)  │
│                                 │                 │                                 │
│  • Pihak yang MEMERINTAH        │   Noise TCP     │  • Pihak yang DIKENDALIKAN      │
│  • Antarmuka CLI Interaktif     │ ──────────────> │  • Daemon Ringan (Tanpa UI)     │
│  • Port Forwarding Client (-L)  │                 │  • Eksekusi Terminal & OS CMD   │
│  • Membaca Stat & Unduh File    │                 │  • Monitoring RAM & CPU Lokal   │
└─────────────────────────────────┘                 └─────────────────────────────────┘
```

### 1. 🤖 **Agent** (Target Remote / Service Daemon)
* **Tempat Dijalankan:** Komputer target, server VPS, atau mesin IoT yang ingin Anda akses atau kelola dari jarak jauh.
* **Peran:** Sebagai pihak yang **melayani instruksi**. Agent berjalan di latar belakang (daemon), mengeksekusi perintah terminal OS (`cmd` / `bash`), membaca utilisasi RAM & CPU, menyimpan potongan file (*chunk transfer*), dan meneruskan lalu lintas jaringan ke port internal lokal (seperti database MySQL `3306` atau web server `80`).

### 2. 🎮 **Controller** (Admin Client Tool)
* **Tempat Dijalankan:** Laptop atau PC kerja pribadi Anda (sang administrator/operator).
* **Peran:** Sebagai **pusat kendali**. Controller adalah aplikasi CLI interaktif yang Anda gunakan untuk mengirim instruksi jarak jauh (`stats`, `exec`, `upload`, `rekey`, `forward-local`).

### 🔄 Siapa "Client" dan Siapa "Server"?

| Sudut Pandang | **Controller** | **Agent** | Penjelasan |
| :--- | :--- | :--- | :--- |
| **Logika Bisnis (Aplikasi)** | **Client** | **Server** | Controller bertindak sebagai pemohon/pemberi instruksi (*master*), sedangkan Agent adalah penyedia eksekusi (*worker*). |
| **Koneksi Jaringan Direct** | **Client** (`connect`) | **Server** (`listen`) | Digunakan jika target/Agent memiliki IP Publik atau berada di satu jaringan lokal yang bisa diakses langsung oleh Controller. |
| **Koneksi Jaringan Reverse** | **Server Hub** (`listen`) | **Client** (`connect` + *Auto-Reconnect*) | **Skenario Enterprise:** Agent berada di balik firewall/NAT perusahaan. Agent berinisiatif menghubungi Controller dengan strategi *Exponential Backoff*. Begitu terhubung, Controller tetap memegang kendali penuh. |

---

## 🛡️ Fitur Lanjutan & Ketahanan Sistem (Enterprise Features)

Untuk memastikan agen siap digunakan di lingkungan produksi yang dinamis, fitur-fitur ketahanan dan fungsionalitas jaringan tingkat tinggi berikut wajib diimplementasikan:

1. **Auto-Reconnect (Resiliensi Jaringan)**
   * Jika koneksi TCP terputus akibat gangguan jaringan, *Agent* tidak boleh mati (*crash*).
   * Gunakan strategi **Exponential Backoff** (misal: mencoba kembali dalam waktu 1s, 2s, 4s, hingga maksimal 60s) untuk mencegah serangan *Thundering Herd* pada server pengendali (Controller).

2. **File Transfer Terintegrasi Dua Arah (Bi-Directional Chunk-Based)**
   * Pengiriman file dari Controller ke Agent (`upload`) maupun penarikan file dari Agent ke Controller (`download`).
   * Seluruh proses menggunakan pembagian potongan data (*chunking* 32 KB) dengan verifikasi konfirmasi dan indeks, mencegah lonjakan RAM pada perangkat berdaya rendah.

3. **Periodic Key Rotation (Pemutaran Kunci Berkala)**
   * Untuk meminimalkan dampak jika terjadi kebocoran kunci enkripsi sesi, sistem wajib melakukan *re-keying* secara otomatis.
   * Proses pembuatan kunci baru (*Handshake* ulang) dipicu berdasarkan dua kondisi: **Batas Waktu** (misal setiap 1 jam sekali) atau **Volume Data** (misal setiap 1 GB data yang ditransfer).

4. **Multiplexed Port Forwarding (Local & Reverse Tunneling)**
   * Sistem harus mendukung fungsionalitas tunneling seperti SSH `-L` (Local Forwarding) dan `-R` (Reverse Forwarding).
   * Seluruh lalu lintas data port forwarding tidak boleh membuka port internet baru. Data wajib "menumpang" di dalam satu koneksi Raw TCP Noise utama (Multiplexing) menggunakan identifikasi `channel_id`.

5. **Manajemen Kunci Praktis Bergaya SSH (TOFU - Trust On First Use)**
   * **Host Key Persisten:** Agent dan Controller secara otomatis membuat dan menyimpan kunci host permanen di `~/.p/agent.key` dan `~/.p/controller.key` sehingga tidak berganti-ganti setiap restart.
   * **Auto-Discovery Kunci Publik:** Controller tidak mewajibkan copy-paste 64-karakter hex key secara manual. Saat pertama kali terhubung tanpa `--agent-pubkey`, Controller melakukan probe penemuan kunci publik secara instan, memverifikasi *Fingerprint (SHA-256)*, dan menyimpannya ke `~/.p/known_agents` persis seperti cara kerja OpenSSH!

---

## 🏗️ Arsitektur Alur & Multiplexing Port Forwarding

Ketika fitur Port Forwarding aktif, satu koneksi utama akan membagi jalurnya secara *asynchronous* menggunakan `tokio::sync::mpsc` untuk mengalirkan paket data kustom ke target port internal:

```text
  [Aplikasi Lokal / Browser] (misal: Port 8080)
            │
            ▼ (TCP Stream Lokal)
  ┌────────────────────────────────────────────────────────┐
  │ CLIENT / CONTROLLER                                    │
  │  ├── Listen di 8080 ──> Generate `channel_id: 101`      │
  │  └── Bungkus ke Bincode::ForwardData                   │
  └─────────────────────────┬──────────────────────────────┘
                            │
                            ▼ [Enkripsi Noise via `snow`]
                 [Satu Koneksi Raw TCP Utama]
                            │
                            ▼ [Dekripsi Noise via `snow`]
  ┌────────────────────────────────────────────────────────┐
  │ SERVER / TARGET AGENT                                  │
  │  ├── Baca `channel_id: 101` ──> Cari Router Internal   │
  │  └── Teruskan byte mentah ke Target Port Internal      │
  └─────────────────────────┬──────────────────────────────┘
                            │
                            ▼ (TCP Stream Internal)
  [Database / Web Server Internal] (misal: Port 3306 / Port 80)
```

---

## 📦 Skema Data & Payload (`shared/src/lib.rs`)

Seluruh komunikasi antar-servis wajib menggunakan *Shared Crate* berbasis strongly-typed Enum berikut untuk menghindari miskomunikasi struktur data:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RemoteCommand {
    RunTerminal(String),
    GetSystemStats,
    ShutdownDevice,
    
    // Fitur Transfer File (Chunk-Based)
    StartFileTransfer { filename: String, total_chunks: u32 },
    WriteFileChunk { chunk_index: u32, data: Vec<u8> },
    
    // Fitur Pemutaran Kunci (Key Rotation)
    RequestKeyRotation,

    // Fitur Multiplexed Port Forwarding
    OpenForwardChannel { channel_id: u32, target_port: u16 },
    ForwardData { channel_id: u32, data: Vec<u8> },
    CloseForwardChannel { channel_id: u32 },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CommandResponse {
    TerminalOutput { stdout: String, stderr: String },
    SystemStats { cpu_usage: f32, ram_used_mb: u64 },
    FileChunkAck { chunk_index: u32, success: bool },
    KeyRotationReady,
    
    // Respons Port Forwarding
    ForwardChannelAck { channel_id: u32, opened: bool },
    ForwardDataInbound { channel_id: u32, data: Vec<u8> },
    
    ExecutionError(String),
}
```

---

## 🖥️ Target Implementasi Lintas Platform

Untuk mengeksekusi perintah terminal, tim pengembang wajib menggunakan abstraksi penanganan sistem operasi (*Conditional Compilation*) agar agen berjalan mulus di Windows maupun Unix:

```rust
use std::process::Command;

pub fn execute_os_command(cmd_string: &str) -> Result<String, String> {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", cmd_string]).output()
    } else {
        Command::new("sh").args(["-c", cmd_string]).output()
    };
    
    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).to_string())
            }
        }
        Err(e) => Err(format!("Gagal menjalankan perintah: {}", e)),
    }
}
```

---

## 🔒 Aturan Keamanan (Noise Protocol)

1. **Fixed Cryptographic Primitives:** Kita menggunakan pola `Noise_IK_25519_ChaChaPoly_BLAKE2b` untuk efisiensi CPU maksimal.
2. **Key Management:** Agen target (Server) harus memiliki *Static Public Key* yang sudah ditanam (*hardcoded* atau via konfig berkas aman) pada sisi Controller (Client) untuk mencegah serangan *Man-in-the-Middle* (MitM).
3. **No Plaintext:** Dilarang keras mengirimkan biner Bincode langsung ke jaringan sebelum dilewatkan ke fungsi enkripsi `snow::Session::write_message`.

---

## ⚡ Target Performa & Target Metrik

* **Memory Footprint (Standby):** `< 8 MB RAM`.
* **Binary Size (Stripped):** `< 4 MB` (Single Executable tanpa dependensi eksternal / murni statis).
* **Wire Overhead:** Maksimal `32 byte` di atas data biner asli per transaksi.

---

## 💻 Panduan Penggunaan & Kompilasi (Single Binary `p`)

Seluruh fungsi Agent, Controller, dan Keygen tergabung dalam **satu file biner tunggal: `p`** (atau `p.exe`).

### 1. Kompilasi Release (Statis & Stripped)
```bash
cargo build --release
```
Biner tunggal akan dihasilkan di `target/release/p` (atau `target/release/p.exe`). Ukuran biner hanya **~1.3 MB** (jauh di bawah batas toleransi 4 MB).

### 2. Membuat Pasangan Kunci 25519
```bash
./target/release/p keygen
```
Perintah ini mencetak *Public Key* (32-byte hex) dan *Private Key* (32-byte hex).

### 3. Menjalankan Mode Agent (di Server / VPS / IoT)
```bash
# Otomatis: host key dibuat/dimuat persisten di ~/.p/agent.key
./target/release/p agent --mode listen --addr 0.0.0.0:9999

# Mode Connect (Reverse Connection dengan Auto-Reconnect)
./target/release/p agent --mode connect --addr 1.2.3.4:9999

# Atau tentukan private key custom manual jika diinginkan
./target/release/p agent --mode listen --addr 0.0.0.0:9999 --privkey <AGENT_PRIVATE_KEY_HEX>
```

### 4. Menjalankan Perintah dari Controller (di Laptop / PC Admin)
> **Fitur SSH-Style TOFU:** Parameter `--agent-pubkey` bersifat **opsional**. Jika diabaikan, Controller otomatis mengunduh kunci publik Agent, memverifikasi fingerprint SHA-256, dan menyimpannya ke `~/.p/known_agents`!

```bash
# Mengambil Statistik Remote (CPU & RAM)
./target/release/p controller --addr 1.2.3.4:9999 stats

# Eksekusi Perintah Terminal OS Jarak Jauh
./target/release/p controller --addr 1.2.3.4:9999 exec "uname -a"

# Unggah File Lokal ke Agent (Chunk 32 KB)
./target/release/p controller --addr 1.2.3.4:9999 upload ./file.zip

# Unduh File Remote dari Agent ke Mesin Lokal (Chunk 32 KB)
./target/release/p controller --addr 1.2.3.4:9999 download /var/log/syslog ./syslog.log

# Rotasi Kunci Sesi Secara Manual
./target/release/p controller --addr 1.2.3.4:9999 rekey

# Local Port Forwarding Multiplexed (SSH -L 8080:80)
# Membuka layanan remote di Agent (port 80) agar bisa diakses di laptop Controller (port 8080)
./target/release/p controller --addr 1.2.3.4:9999 forward-local -L 8080:80

# Remote Port Forwarding Multiplexed (SSH -R 9090:8080)
# Membuka aplikasi lokal di Controller (port 8080) agar bisa diakses dari sisi Agent (port 9090)
./target/release/p controller --addr 1.2.3.4:9999 forward-remote -R 9090:8080

# Matikan Perangkat Jarak Jauh
./target/release/p controller --addr 1.2.3.4:9999 shutdown
```

---

## 🏗️ Status Implementasi (Completed ✅)

- [x] **Single Binary Architecture (`p`):** Menggabungkan peran Agent, Controller, dan Keygen ke dalam satu biner tunggal hemat memori dan ukuran (~1.3 MB).
- [x] **SSH-Style TOFU Key Discovery:** Otomatis mengambil dan memverifikasi public key Agent pada koneksi pertama serta mencatat di `~/.p/known_agents` tanpa copy-paste manual.
- [x] **Bi-Directional File Transfer:** Transfer file dua arah yang aman (`upload` & `download`) berbasis chunking 32 KB hemat memori.
- [x] **Handshake Awal:** Selesai menggunakan `snow` (`Noise_IK_25519_ChaChaPoly_BLAKE2b`) di atas `tokio::net::TcpStream`.
- [x] **Stream Framed:** Pembungkus `NoiseFramedStream` memanfaatkan `tokio_util::codec::LengthDelimitedCodec` untuk mencegah fragmentasi data.
- [x] **Auto-Reconnect Loop:** Modul resiliensi jaringan dengan strategi *Exponential Backoff* (1s - 60s) pada Agent.
- [x] **Local Port Forwarding (-L):** Aliran multi-channel (`channel_id`) menggunakan `HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>` yang menumpang di satu koneksi Raw TCP.
- [x] **Remote Port Forwarding (-R / Reverse Tunneling):** Membuka layanan/aplikasi internal Controller agar dapat diakses langsung oleh perangkat/klien di sisi Agent melalui tunnel terenkripsi Noise.
- [x] **Kompilasi Silang & Docker:** Dikonfigurasi via `Dockerfile` serta GitHub Actions Multi-OS workflow untuk Windows, Linux, dan macOS.


