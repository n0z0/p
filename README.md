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

## 🛡️ Fitur Lanjutan & Ketahanan Sistem (Enterprise Features)

Untuk memastikan agen siap digunakan di lingkungan produksi yang dinamis, fitur-fitur ketahanan dan fungsionalitas jaringan tingkat tinggi berikut wajib diimplementasikan:

1. **Auto-Reconnect (Resiliensi Jaringan)**
   * Jika koneksi TCP terputus akibat gangguan jaringan, *Agent* tidak boleh mati (*crash*).
   * Gunakan strategi **Exponential Backoff** (misal: mencoba kembali dalam waktu 1s, 2s, 4s, hingga maksimal 60s) untuk mencegah serangan *Thundering Herd* pada server pengendali (Controller).

2. **File Transfer Terintegrasi (Chunk-Based)**
   * Pengiriman file dilakukan langsung melalui jalur Bincode murni dengan membagi file menjadi potongan kecil (*chunking*, misal per 64KB). 
   * Hal ini mencegah lonjakan memori RAM (*Out of Memory*) pada perangkat IoT atau server kecil saat mentransfer file berukuran besar.

3. **Periodic Key Rotation (Pemutaran Kunci Berkala)**
   * Untuk meminimalkan dampak jika terjadi kebocoran kunci enkripsi sesi, sistem wajib melakukan *re-keying* secara otomatis.
   * Proses pembuatan kunci baru (*Handshake* ulang) dipicu berdasarkan dua kondisi: **Batas Waktu** (misal setiap 1 jam sekali) atau **Volume Data** (misal setiap 1 GB data yang ditransfer).

4. **Multiplexed Port Forwarding (Local & Reverse Tunneling)**
   * Sistem harus mendukung fungsionalitas tunneling seperti SSH `-L` (Local Forwarding) dan `-R` (Reverse Forwarding).
   * Seluruh lalu lintas data port forwarding tidak boleh membuka port internet baru. Data wajib "menumpang" di dalam satu koneksi Raw TCP Noise utama (Multiplexing) menggunakan identifikasi `channel_id`.

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

## 🏗️ Langkah Pengembangan Selanjutnya (Next Steps)

1. Selesaikan implementasi *handshake* awal menggunakan `snow` di atas `Tokio::net::TcpStream`.
2. Buat pembungkus *stream* kustom (`NoiseFramedStream`) memanfaatkan `tokio_util::codec::LengthDelimitedCodec` agar pembacaan byte stream tidak bocor atau terpotong.
3. Rancang modul **Auto-Reconnect Loop** pada *Agent* menggunakan pustaka `tokio::time::sleep`.
4. Implementasikan pemetaan `HashMap<u32, tokio::sync::mpsc::Sender<Vec<u8>>>` pada sisi pengirim dan penerima untuk memisahkan data Port Forwarding berdasarkan `channel_id`.
5. Siapkan konfigurasi `Cross` (Kompilasi Silang via Docker) untuk menghasilkan biner `.exe` (Windows) langsung dari mesin pengembang Linux.
