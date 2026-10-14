# Developer & Architecture Guide: `p`

Dokumen ini berisi spesifikasi arsitektur teknis, protokol komunikasi, skema data, dan panduan pengembang untuk proyek `p`.

---

## 🚀 Arsitektur Teknis (Tech Stack)

Sistem ini memangkas seluruh *overhead* tradisional dengan mengombinasikan komponen-komponen berikut:
* **Transport:** `Tokio` (Raw TCP Socket Async) – Beban jaringan minimal tanpa HTTP Header.
* **Serialization:** `Bincode` (Zero-Fluff Binary) – Mengubah *Struct/Enum* Rust langsung menjadi biner mentah yang jauh lebih ringan dari JSON/Protobuf.
* **Security:** `Snow` (Noise Protocol Framework) – Enkripsi *end-to-end* modern sekelas WireGuard (`Noise_IK_25519_ChaChaPoly_BLAKE2b`) dengan proses *handshake* kilat (1-2 paket data) dan *wire overhead* minimal (~16-32 byte per paket).
* **Target OS:** Multiplatform tunggal (Linux, Windows, macOS) berbasis satu *codebase*.

---

## 🧠 Konsep & Peran: Server vs. Client (Filosofi SSH)

Dalam sistem `p`, komponen dibagi menjadi dua peran yang mengadopsi standar **SSH**:

```text
┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
│             CLIENT              │                 │             SERVER              │
│  (Laptop / PC Administrator)    │                 │ (Server / VPS / Perangkat IoT)  │
│                                 │                 │                                 │
│  • Pihak yang MEMERINTAH        │    Noise TCP    │  • Pihak yang DIKENDALIKAN      │
│  • Antarmuka CLI Interaktif     │ ──────────────> │  • Daemon Ringan (Multi-Client) │
│  • Port Forwarding Client (-L)  │                 │  • Eksekusi Terminal & OS CMD   │
│  • Membaca Stat & Unduh File    │                 │  • Monitoring RAM & CPU Lokal   │
└─────────────────────────────────┘                 └─────────────────────────────────┘
```

### 1. 🤖 **Server** (Target Remote / Service Daemon — Mirip `sshd`)
* **Peran:** Sebagai pihak yang **melayani instruksi**. Server berjalan di latar belakang (daemon), mengeksekusi perintah terminal OS (`cmd` / `bash`), membaca utilisasi RAM & CPU, menyimpan potongan file (*chunk transfer*), dan meneruskan lalu lintas jaringan ke port internal lokal (seperti database MySQL `3306` atau web server `80`).
* **Multi-Client Concurrency:** Server mendukung banyak Client sekaligus. Setiap koneksi Client yang masuk diterima di `listener.accept()` dan langsung di-spawn ke task `tokio::spawn` asynchronous mandiri dengan sesi enkripsi Noise yang terisolasi.

### 2. 🎮 **Client** (Admin Tool — Mirip `ssh`)
* **Peran:** Sebagai **pusat kendali**. Client adalah aplikasi CLI interaktif yang Anda gunakan untuk mengirim instruksi jarak jauh (`stats`, `exec`, `upload`, `rekey`, `-L`, `-R`, `mount`).

### 🔄 Hubungan Client vs. Server

| Sudut Pandang | **Client** | **Server** | Penjelasan |
| :--- | :--- | :--- | :--- |
| **Logika Bisnis (Aplikasi)** | **Client** | **Server** | Client bertindak sebagai pemohon/pemberi instruksi (*master*), sedangkan Server adalah penyedia eksekusi (*worker*). |
| **Koneksi Jaringan Direct** | **Client** (`connect`) | **Server** (`listen`) | Digunakan jika Server memiliki IP Publik atau berada di satu jaringan lokal yang bisa diakses langsung oleh Client. |
| **Koneksi Jaringan Reverse (`-r`)** | **Client Hub** (`listen`) | **Server** (`connect` + *Auto-Reconnect*) | **Skenario Enterprise:** Server berada di balik firewall/NAT perusahaan. Server berinisiatif menghubungi Client dengan strategi *Exponential Backoff*. Begitu terhubung, Client tetap memegang kendali penuh. |

---

## 🛡️ Fitur Lanjutan & Ketahanan Sistem

1. **Multi-Client Async Concurrency:**
   * Server dapat melayani banyak koneksi Client secara simultan tanpa saling memblokir (non-blocking async via Tokio).

2. **Auto-Reconnect (Resiliensi Jaringan):**
   * Jika koneksi TCP terputus akibat gangguan jaringan, Server/Client tidak mati (*crash*).
   * Menggunakan strategi **Exponential Backoff** (1s, 2s, 4s, hingga maksimal 60s) untuk mencegah *Thundering Herd*.

3. **File Transfer Terintegrasi Dua Arah (Chunk-Based):**
   * Pengiriman file (`upload`) maupun penarikan file (`download`).
   * Seluruh proses menggunakan pembagian potongan data (*chunking* 32 KB) dengan konfirmasi indeks (`FileChunkAck`), mencegah lonjakan RAM pada perangkat berdaya rendah.

4. **Periodic Key Rotation (Pemutaran Kunci Berkala):**
   * Otomatis memutar kunci simetris sesi Noise secara berkala berdasarkan batas waktu (misal 1 jam) atau volume data (1 GB) via `RemoteCommand::RequestKeyRotation`.

5. **Multiplexed Port Forwarding (`-L` & `-R`):**
   * Local Port Forwarding (`-L`) dan Remote Port Forwarding (`-R`).
   * Seluruh lalu lintas data port forwarding menumpang di dalam satu koneksi Raw TCP Noise utama (Multiplexing) menggunakan identifikasi `channel_id`.

6. **Manajemen Kunci Bergaya SSH (TOFU - Trust On First Use):**
   * **Host Key Persisten:** Disimpan di `~/.p/server.key` dan `~/.p/client.key`.
   * **Auto-Discovery Kunci Publik:** Client melakukan probe TOFU, memverifikasi Fingerprint (SHA-256), dan mencatatnya ke `~/.p/known_servers` (seperti `known_hosts`).
   * **Pairing Token & Nickname:** Melindungi akses awal dengan token rahasia di `~/.p/server.token` dan mencatat Client terotorisasi di `~/.p/authorized_clients` (seperti `authorized_keys`).

---

## 🏗️ Alur Multiplexing Port Forwarding

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

## 📦 Skema Protokol Komunikasi Data

Semua pertukaran data menggunakan Enum strongly-typed biner (Bincode):

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

    // Remote Port Forwarding
    StartRemoteForward { bind_port: u16, target_client_port: u16 },

    // WebDAV Virtual Drive Filesystem Operations
    FsReadDir { path: String },
    FsGetMetadata { path: String },
    FsReadFile { path: String },
    FsWriteFile { path: String, data: Vec<u8> },
    FsDelete { path: String },
    FsCreateDir { path: String },
    FsRename { from: String, to: String },
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
    RemoteForwardAck { success: bool, message: String, bind_port: u16 },
    
    // Autentikasi
    AuthChallenge,
    AuthSuccess,
    AuthFailed(String),

    ExecutionError(String),
}
```

---

## 🛡️ Telemetri & Audit Log CTI (SOC-Grade)

Server mengimplementasikan modul telemetri keamanan mandiri (`src/audit.rs`) dengan arsitektur **Zero-Bloat** (tanpa dependensi eksternal berat) yang menghasilkan log streaming berstandar **NDJSON (Newline-Delimited JSON)** ke `~/.p/audit.log`. Format ini kompatibel langsung untuk ingest SIEM (Wazuh, Splunk, Elastic Security, Microsoft Sentinel).

### Contoh Entri Log Mentah:
```json
{"timestamp":"2026-10-14T04:45:00.123Z","event_type":"COMMAND_EXEC","severity":"NOTICE","session_id":"sess-a1b2c3d4e5f67890","client":{"fingerprint":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","nickname":"laptop-joe","remote_ip":"203.0.113.45:51234"},"server":{"local_addr":"0.0.0.0:9999"},"action":{"command":"cat /etc/passwd"}}
```

### Taksonomi Event Audit:
* **`AUTH_ATTEMPT` / `AUTH_SUCCESS` / `AUTH_FAILED`**: Pelacakan autentikasi kunci publik atau token pairing.
* **`COMMAND_EXEC`**: Pencatatan string perintah terminal mentah untuk deteksi ancaman (MITRE ATT&CK).
* **`FILE_UPLOAD` / `FILE_DOWNLOAD`**: Pelacakan pemindahan file (chunk-based) untuk forensik exfiltrasi data atau dropping file berbahaya.
* **`WEBDAV_FS_ACCESS`**: Pelacakan operasi virtual drive filesystem (LIST, STAT, READ, WRITE, DELETE, MKDIR, RENAME).
* **`PORT_FORWARD` / `PORT_FORWARD_REMOTE`**: Pelacakan tunnel port forwarding (`-L` dan `-R`) untuk mendeteksi *lateral movement* / *network pivoting*.
* **`SESSION_REKEY`**: Audit rotasi kunci enkripsi simetris pada sesi aktif.
* **`DEVICE_SHUTDOWN`**: Pemicuan sinyal shutdown mesin server.
* **`SESSION_CLOSE`**: Penutupan sesi koneksi client.

---

## 🔒 Aturan Keamanan (Noise Protocol)

1. **Fixed Cryptographic Primitives:** Pola `Noise_IK_25519_ChaChaPoly_BLAKE2b` untuk efisiensi CPU maksimal.
2. **Key Management:** Agen target (Server) diverifikasi menggunakan kunci publik static via TOFU fingerprint atau flag `-k`.
3. **No Plaintext:** Dilarang mengirim byte mentah sebelum dienkripsi melalui `snow::Session::write_message`.

---

## ⚡ Target Performa & Metrik

* **Memory Footprint (Standby):** `< 8 MB RAM`.
* **Binary Size (Stripped):** `< 4 MB` (Single Executable tanpa runtime eksternal).
* **Wire Overhead:** Maksimal `32 byte` di atas payload biner per paket.

---

## 🛠️ Kompilasi dari Source

```bash
# Build binary release optimal & stripped
cargo build --release

# Menjalankan unit & integration test
cargo test
```
Biner hasil kompilasi berada di `target/release/p` (atau `target/release/p.exe`).
