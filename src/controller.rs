use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::crypto::{
    compute_key_fingerprint, generate_keypair, get_config_dir, lookup_known_agent,
    save_known_agent,
};
use crate::framed::NoiseFramedStream;
use crate::protocol::{CommandResponse, RemoteCommand};

#[derive(Args, Debug, Clone)]
pub struct ControllerArgs {
    /// Alamat Target Agent (contoh: 127.0.0.1:9999). Bisa posisi langsung: 'p controller 127.0.0.1:9999'
    #[arg(value_name = "TARGET_ADDR")]
    pub addr_pos: Option<String>,

    /// Alamat Target Agent via flag -a / --addr
    #[arg(short, long)]
    pub addr: Option<String>,

    /// Token rahasia / Password untuk otorisasi (pairing pertama kali)
    #[arg(short, long)]
    pub token: Option<String>,

    /// Kunci privat statis Controller (32-byte hex). Jika kosong, kunci persisten ~/.p/controller.key digunakan
    #[arg(long)]
    pub privkey: Option<String>,

    /// Kunci publik statis milik Target Agent (32-byte hex). Jika kosong, otomatis diambil via SSH-Style TOFU
    #[arg(short = 'k', long)]
    pub agent_pubkey: Option<String>,

    #[command(subcommand)]
    pub command: Option<ControllerCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ControllerCommand {
    /// Masuk ke sesi interaktif remote shell (SSH-style REPL)
    Shell,

    /// Menjalankan perintah terminal di Agent
    Exec {
        /// Perintah terminal yang ingin dieksekusi
        command: String,
    },

    /// Mengambil metrik sistem dari Agent (CPU & RAM)
    Stats,

    /// Mengunggah file ke Agent dengan pembagian chunk
    Upload {
        /// Path file lokal yang akan diunggah
        filepath: PathBuf,
    },

    /// Mengunduh file dari Agent ke Controller
    Download {
        /// Path file di mesin Agent yang ingin diunduh
        remote_path: String,
        /// Path file/folder lokal tujuan penyimpanan
        local_path: PathBuf,
    },

    /// Rotasi kunci sesi secara manual
    Rekey,

    /// Port Forwarding Lokal (-L local_port:target_port)
    ForwardLocal {
        /// Format forwarding misal 8080:80 (local_port:remote_port)
        #[arg(short = 'L', long)]
        mapping: String,
    },

    /// Remote Port Forwarding (-R agent_bind_port:controller_target_port)
    ForwardRemote {
        /// Format forwarding misal 9090:8080 (agent_bind_port:controller_target_port)
        #[arg(short = 'R', long)]
        mapping: String,
    },

    /// Kirim perintah shutdown ke Agent
    Shutdown,
}

const CHUNK_SIZE: usize = 32 * 1024; // 32 KB per chunk

async fn perform_upload(stream: &mut NoiseFramedStream, filepath: PathBuf) -> Result<()> {
    let mut file = File::open(&filepath)
        .await
        .with_context(|| format!("Gagal membuka file lokal: {}", filepath.display()))?;

    let metadata = file.metadata().await?;
    let file_size = metadata.len();
    let total_chunks = ((file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32;

    let filename = filepath
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    println!("📤 Mengunggah file '{}' ({} byte, {} chunks)...", filename, file_size, total_chunks);

    stream
        .send_command(&RemoteCommand::StartFileTransfer {
            filename: filename.clone(),
            total_chunks,
        })
        .await?;

    let ack = stream.recv_response().await?;
    match ack {
        CommandResponse::FileChunkAck { success: true, .. } => (),
        _ => bail!("Agent menolak inisialisasi transfer file!"),
    }

    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_idx = 0u32;

    loop {
        let n = file.read(&mut chunk_buf).await?;
        if n == 0 {
            break;
        }
        let data = chunk_buf[..n].to_vec();

        stream
            .send_command(&RemoteCommand::WriteFileChunk {
                chunk_index: chunk_idx,
                data,
            })
            .await?;

        let res = stream.recv_response().await?;
        match res {
            CommandResponse::FileChunkAck { chunk_index, success } => {
                if !success {
                    bail!("Agent gagal menyimpan chunk {}", chunk_index);
                }
            }
            _ => bail!("Respons tak terduga saat chunk ack: {:?}", res),
        }

        chunk_idx += 1;
        let percent = (chunk_idx as f32 / total_chunks as f32) * 100.0;
        print!("\r⏳ Mengirim: chunk {}/{} ({:.1}%)", chunk_idx, total_chunks, percent);
    }

    println!("\n✅ File berhasil diunggah secara utuh!");
    Ok(())
}

async fn perform_download(
    stream: &mut NoiseFramedStream,
    remote_path: String,
    local_path: PathBuf,
) -> Result<()> {
    println!("📥 Meminta unduh file '{}' dari Agent...", remote_path);
    stream
        .send_command(&RemoteCommand::StartDownload {
            filepath: remote_path.clone(),
        })
        .await?;

    let header_resp = stream.recv_response().await?;
    let (filename, total_chunks, file_size) = match header_resp {
        CommandResponse::DownloadHeader {
            filename,
            total_chunks,
            file_size,
        } => (filename, total_chunks, file_size),
        CommandResponse::DownloadError(err) => {
            bail!("Agent menolak permintaan unduh: {}", err);
        }
        other => bail!("Respons tak terduga saat inisiasi unduh: {:?}", other),
    };

    let target_path = if local_path.is_dir() {
        local_path.join(&filename)
    } else {
        local_path
    };

    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
    }

    let mut dest_file = File::create(&target_path)
        .await
        .with_context(|| format!("Gagal membuat file lokal: {}", target_path.display()))?;

    println!(
        "📥 Mengunduh file '{}' ({} byte, {} chunks)...",
        filename, file_size, total_chunks
    );

    for chunk_idx in 0..total_chunks {
        stream
            .send_command(&RemoteCommand::RequestDownloadChunk {
                chunk_index: chunk_idx,
            })
            .await?;

        let chunk_resp = stream.recv_response().await?;
        match chunk_resp {
            CommandResponse::DownloadChunk {
                chunk_index,
                data,
            } => {
                if chunk_index != chunk_idx {
                    bail!(
                        "Indeks chunk tidak cocok: diharapkan {}, diterima {}",
                        chunk_idx,
                        chunk_index
                    );
                }
                dest_file.write_all(&data).await?;
            }
            CommandResponse::DownloadError(err) => {
                bail!("Error saat mengunduh chunk {}: {}", chunk_idx, err);
            }
            other => bail!("Respons tak terduga saat meminta chunk {}: {:?}", chunk_idx, other),
        }

        let percent = ((chunk_idx + 1) as f32 / total_chunks as f32) * 100.0;
        print!(
            "\r⏳ Mengunduh: chunk {}/{} ({:.1}%)",
            chunk_idx + 1,
            total_chunks,
            percent
        );
    }

    dest_file.flush().await?;
    println!("\n✅ File berhasil diunduh ke: {}", target_path.display());
    Ok(())
}

async fn run_interactive_shell(stream: &mut NoiseFramedStream, addr: &str) -> Result<()> {
    use std::io::{self, Write};

    println!("══════════════════════════════════════════════════════════");
    println!("💻 SESI INTERAKTIF REMOTE SHELL (p controller)");
    println!("   Target Host : {}", addr);
    println!("   Bantuan     : Ketik 'help' untuk daftar perintah khusus");
    println!("   Keluar      : Ketik 'exit' atau tekan Ctrl+C");
    println!("══════════════════════════════════════════════════════════");

    let stdin = io::stdin();
    loop {
        print!("p[{}]> ", addr);
        let _ = io::stdout().flush();

        let mut input_line = String::new();
        let bytes_read = match stdin.read_line(&mut input_line) {
            Ok(n) => n,
            Err(_) => break,
        };

        if bytes_read == 0 {
            // EOF
            println!();
            break;
        }

        let trimmed = input_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "exit" || trimmed == "quit" {
            println!("👋 Sesi remote shell ditutup.");
            break;
        }

        if trimmed == "help" {
            println!("📋 Perintah Bawaan:");
            println!("   stats                      - Cek beban CPU & RAM di Agent");
            println!("   upload <local_file>        - Unggah file lokal ke Agent");
            println!("   download <remote> [local]  - Unduh file dari Agent ke lokal");
            println!("   rekey                      - Rotasi kunci sesi enkripsi Noise");
            println!("   clear / cls                - Bersihkan layar");
            println!("   exit / quit                - Keluar dari remote shell");
            println!("💡 Semua perintah lainnya akan langsung dieksekusi di OS Agent.");
            continue;
        }

        if trimmed == "clear" || trimmed == "cls" {
            print!("\x1B[2J\x1B[1;1H");
            let _ = io::stdout().flush();
            continue;
        }

        if trimmed == "stats" {
            stream.send_command(&RemoteCommand::GetSystemStats).await?;
            if let Ok(resp) = stream.recv_response().await {
                match resp {
                    CommandResponse::SystemStats { cpu_usage, ram_used_mb } => {
                        println!("📊 CPU: {:.2}% | RAM: {} MB", cpu_usage, ram_used_mb);
                    }
                    other => println!("{:?}", other),
                }
            }
            continue;
        }

        if trimmed == "rekey" {
            println!("🔄 Memutar kunci sesi simetris...");
            stream.send_command(&RemoteCommand::RequestKeyRotation).await?;
            let _ = stream.rekey();
            if let Ok(resp) = stream.recv_response().await {
                match resp {
                    CommandResponse::KeyRotationReady => {
                        println!("✅ Rotasi kunci sesi berhasil!");
                    }
                    other => println!("{:?}", other),
                }
            }
            continue;
        }

        if trimmed.starts_with("upload ") {
            let path_arg = trimmed[7..].trim();
            if path_arg.is_empty() {
                println!("⚠️ Format: upload <path_file_lokal>");
            } else if let Err(e) = perform_upload(stream, PathBuf::from(path_arg)).await {
                eprintln!("❌ Upload gagal: {}", e);
            }
            continue;
        }

        if trimmed.starts_with("download ") {
            let parts: Vec<&str> = trimmed[9..].split_whitespace().collect();
            if parts.is_empty() {
                println!("⚠️ Format: download <remote_path> [local_path]");
                continue;
            }
            let remote = parts[0].to_string();
            let local = if parts.len() > 1 {
                PathBuf::from(parts[1])
            } else {
                let default_name = std::path::Path::new(&remote).file_name().unwrap_or_default();
                PathBuf::from(default_name)
            };
            if let Err(e) = perform_download(stream, remote, local).await {
                eprintln!("❌ Download gagal: {}", e);
            }
            continue;
        }

        // Jalankan perintah terminal biasa di Agent
        stream.send_command(&RemoteCommand::RunTerminal(trimmed.to_string())).await?;
        match stream.recv_response().await {
            Ok(CommandResponse::TerminalOutput { stdout, stderr }) => {
                if !stdout.is_empty() {
                    print!("{}", stdout);
                    let _ = io::stdout().flush();
                }
                if !stderr.is_empty() {
                    eprint!("{}", stderr);
                    let _ = io::stderr().flush();
                }
            }
            Ok(CommandResponse::ExecutionError(err)) => {
                eprintln!("❌ Error eksekusi: {}", err);
            }
            Ok(other) => println!("Respons: {:?}", other),
            Err(e) => {
                eprintln!("⚠️ Koneksi terputus: {}", e);
                break;
            }
        }
    }

    Ok(())
}

pub async fn run_controller(args: ControllerArgs) -> Result<()> {
    let target_addr = args
        .addr
        .or(args.addr_pos)
        .unwrap_or_else(|| "127.0.0.1:9999".into());

    let agent_pubkey_bytes = if let Some(hex_str) = &args.agent_pubkey {
        let bytes = hex::decode(hex_str.trim()).context("Format hex agent_pubkey tidak valid")?;
        if bytes.len() != 32 {
            bail!("Panjang agent_pubkey harus 32 byte!");
        }
        bytes
    } else if let Some(saved_key) = lookup_known_agent(&target_addr) {
        info!("🔑 Kunci publik Agent ditemukan di ~/.p/known_agents untuk {}", target_addr);
        saved_key
    } else {
        println!("🔍 Menghubungi Agent di {} untuk mengambil identitas kunci publik (TOFU)...", target_addr);
        match NoiseFramedStream::discover_remote_pubkey(&target_addr).await {
            Ok(discovered_pubkey) => {
                let fingerprint = compute_key_fingerprint(&discovered_pubkey);
                let hex_key = hex::encode(&discovered_pubkey);
                println!("🔒 KUNCI PUBLIK AGENT TERVERIFIKASI (Trust On First Use):");
                println!("   Host        : {}", target_addr);
                println!("   Fingerprint : {}", fingerprint);
                println!("   Public Key  : {}", hex_key);
                println!("💡 Kunci otomatis disimpan ke ~/.p/known_agents (seperti SSH).");
                println!();
                if let Err(e) = save_known_agent(&target_addr, &hex_key) {
                    warn!("Gagal menyimpan ke known_agents: {}", e);
                }
                discovered_pubkey
            }
            Err(e) => {
                bail!(
                    "Gagal mengambil kunci publik otomatis dari Agent di {}: {}. Pastikan Agent sedang berjalan, atau tentukan secara manual via --agent-pubkey.",
                    target_addr, e
                );
            }
        }
    };

    let controller_privkey_bytes = match args.privkey {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).context("Format hex privkey tidak valid")?;
            if bytes.len() != 32 {
                bail!("Panjang privkey harus 32 byte!");
            }
            bytes
        }
        None => {
            let config_dir = get_config_dir();
            let c_key_file = config_dir.join("controller.key");
            if c_key_file.exists() {
                if let Ok(c) = std::fs::read_to_string(&c_key_file) {
                    if let Ok(b) = hex::decode(c.trim()) {
                        if b.len() == 32 {
                            b
                        } else {
                            let kp = generate_keypair()?;
                            let _ = std::fs::write(&c_key_file, hex::encode(&kp.private));
                            kp.private
                        }
                    } else {
                        let kp = generate_keypair()?;
                        let _ = std::fs::write(&c_key_file, hex::encode(&kp.private));
                        kp.private
                    }
                } else {
                    let kp = generate_keypair()?;
                    let _ = std::fs::write(&c_key_file, hex::encode(&kp.private));
                    kp.private
                }
            } else {
                let _ = std::fs::create_dir_all(&config_dir);
                let kp = generate_keypair()?;
                let _ = std::fs::write(&c_key_file, hex::encode(&kp.private));
                kp.private
            }
        }
    };

    info!("🌐 Menghubungkan ke Agent di {}...", target_addr);
    let mut stream = NoiseFramedStream::connect_as_initiator(
        &target_addr,
        &controller_privkey_bytes,
        &agent_pubkey_bytes,
    )
    .await
    .context("Gagal melakukan handshake terenkripsi Noise ke Agent")?;

    info!("🔒 Terhubung dengan aman ke Agent! Memverifikasi status otorisasi...");

    // 2. Alur Autentikasi / Pairing Token
    let initial_auth = stream.recv_response().await
        .context("Gagal menerima respons awal status autentikasi dari Agent")?;

    match initial_auth {
        CommandResponse::AuthSuccess => {
            info!("🔑 Controller telah terotorisasi otomatis (terdaftar di ~/.p/authorized_controllers Agent).");
        }
        CommandResponse::AuthChallenge => {
            println!("🔒 Agent membutuhkan otorisasi untuk Controller baru.");
            let token = match args.token {
                Some(t) => t.trim().to_string(),
                None => {
                    use std::io::{self, Write};
                    print!("🔑 Masukkan Password / Pairing Token: ");
                    let _ = io::stdout().flush();
                    let entered = rpassword::read_password()
                        .context("Gagal membaca password dari input")?;
                    entered.trim().to_string()
                }
            };

            stream.send_command(&RemoteCommand::Authenticate { token }).await?;
            let auth_res = stream.recv_response().await
                .context("Gagal menerima hasil verifikasi autentikasi dari Agent")?;

            match auth_res {
                CommandResponse::AuthSuccess => {
                    println!("✅ Pairing berhasil! Kunci Controller telah diotorisasi di Agent.");
                    println!("💡 Pada koneksi berikutnya, Anda tidak perlu memasukkan password lagi!");
                    println!();
                }
                CommandResponse::AuthFailed(reason) => {
                    bail!("❌ Autentikasi ditolak oleh Agent: {}", reason);
                }
                other => bail!("Respons tak terduga saat autentikasi: {:?}", other),
            }
        }
        other => bail!("Respons status awal tidak dikenal dari Agent: {:?}", other),
    }

    let cmd = args.command.unwrap_or(ControllerCommand::Shell);
    match cmd {
        ControllerCommand::Shell => {
            run_interactive_shell(&mut stream, &target_addr).await?;
        }

        ControllerCommand::Exec { command } => {
            stream.send_command(&RemoteCommand::RunTerminal(command)).await?;
            let resp = stream.recv_response().await?;
            match resp {
                CommandResponse::TerminalOutput { stdout, stderr } => {
                    if !stdout.is_empty() {
                        print!("{}", stdout);
                    }
                    if !stderr.is_empty() {
                        eprint!("{}", stderr);
                    }
                }
                CommandResponse::ExecutionError(err) => {
                    eprintln!("❌ Error eksekusi di Agent: {}", err);
                }
                other => {
                    println!("Respons tak terduga: {:?}", other);
                }
            }
        }

        ControllerCommand::Stats => {
            stream.send_command(&RemoteCommand::GetSystemStats).await?;
            let resp = stream.recv_response().await?;
            match resp {
                CommandResponse::SystemStats { cpu_usage, ram_used_mb } => {
                    println!("📊 STATISTIK AGENT REMOTE:");
                    println!("   Utilisasi CPU : {:.2}%", cpu_usage);
                    println!("   Penggunaan RAM: {} MB", ram_used_mb);
                }
                other => println!("Respons: {:?}", other),
            }
        }

        ControllerCommand::Upload { filepath } => {
            perform_upload(&mut stream, filepath).await?;
        }

        ControllerCommand::Download { remote_path, local_path } => {
            perform_download(&mut stream, remote_path, local_path).await?;
        }

        ControllerCommand::Rekey => {
            println!("🔄 Meminta rotasi kunci sesi...");
            stream.send_command(&RemoteCommand::RequestKeyRotation).await?;
            stream.rekey()?;
            let resp = stream.recv_response().await?;
            match resp {
                CommandResponse::KeyRotationReady => {
                    println!("✅ Rotasi kunci sesi berhasil! Kunci simetris telah diperbarui.");
                }
                other => println!("Respons rotasi: {:?}", other),
            }
        }

        ControllerCommand::ForwardLocal { mapping } => {
            let parts: Vec<&str> = mapping.split(':').collect();
            if parts.len() != 2 {
                bail!("Format mapping harus berupa 'local_port:target_port', contoh: '8080:80'");
            }
            let local_port: u16 = parts[0].parse().context("Local port tidak valid")?;
            let target_port: u16 = parts[1].parse().context("Target port tidak valid")?;

            let local_listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))
                .await
                .with_context(|| format!("Gagal listen di 127.0.0.1:{}", local_port))?;

            println!("🔀 Local Port Forwarding aktif!");
            println!("   Aplikasi Lokal: 127.0.0.1:{}", local_port);
            println!("   Target Remote : 127.0.0.1:{}", target_port);
            println!("   Multiplexing  : Menumpang di dalam satu koneksi Raw TCP Noise.");

            let channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<RemoteCommand>(100);
            let mut channel_counter = 100u32;

            loop {
                tokio::select! {
                    Some(cmd) = outbound_rx.recv() => {
                        stream.send_command(&cmd).await?;
                    }

                    resp_res = stream.recv_response() => {
                        let resp = match resp_res {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("Koneksi tunnel terputus: {}", e);
                                break;
                            }
                        };

                        match resp {
                            CommandResponse::ForwardDataInbound { channel_id, data } => {
                                let sender = {
                                    channels.lock().await.get(&channel_id).cloned()
                                };
                                if let Some(s) = sender {
                                    let _ = s.send(data).await;
                                }
                            }
                            CommandResponse::ForwardChannelAck { channel_id, opened } => {
                                info!("Forward channel {} status: opened={}", channel_id, opened);
                            }
                            _ => ()
                        }
                    }

                    Ok((local_stream, client_addr)) = local_listener.accept() => {
                        channel_counter += 1;
                        let channel_id = channel_counter;
                        info!("Baru terhubung di port lokal {}: channel_id={}", client_addr, channel_id);

                        let (mut local_reader, mut local_writer) = local_stream.into_split();
                        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
                        channels.lock().await.insert(channel_id, data_tx);

                        let _ = outbound_tx.send(RemoteCommand::OpenForwardChannel {
                            channel_id,
                            target_port,
                        }).await;

                        let outbound_tx_clone = outbound_tx.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            loop {
                                match local_reader.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        let data = buf[..n].to_vec();
                                        if outbound_tx_clone.send(RemoteCommand::ForwardData { channel_id, data }).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let _ = outbound_tx_clone.send(RemoteCommand::CloseForwardChannel { channel_id }).await;
                        });

                        tokio::spawn(async move {
                            while let Some(chunk) = data_rx.recv().await {
                                if local_writer.write_all(&chunk).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                }
            }
        }

        ControllerCommand::ForwardRemote { mapping } => {
            let parts: Vec<&str> = mapping.split(':').collect();
            if parts.len() != 2 {
                bail!("Format mapping harus berupa 'agent_port:controller_port', contoh: '9090:8080'");
            }
            let agent_port: u16 = parts[0].parse().context("Agent port tidak valid")?;
            let controller_port: u16 = parts[1].parse().context("Controller target port tidak valid")?;

            println!("🔄 Meminta Agent membuka listener port {} untuk diteruskan ke Controller port {}...", agent_port, controller_port);

            stream.send_command(&RemoteCommand::StartRemoteForward {
                bind_port: agent_port,
                target_controller_port: controller_port,
            }).await?;

            let ack = stream.recv_response().await?;
            match ack {
                CommandResponse::RemoteForwardAck { success, message, .. } => {
                    if !success {
                        bail!("Agent menolak remote port forward: {}", message);
                    }
                    println!("✅ Remote Port Forwarding (-R) aktif!");
                    println!("   Port di Agent        : 127.0.0.1:{}", agent_port);
                    println!("   Aplikasi Controller  : 127.0.0.1:{}", controller_port);
                    println!("   Info Listener        : {}", message);
                    println!("   Klien di Agent dapat membuka http://127.0.0.1:{} untuk mengakses aplikasi lokal Controller.", agent_port);
                }
                other => bail!("Respons tidak terduga saat inisiasi remote forward: {:?}", other),
            }

            let channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<RemoteCommand>(100);

            loop {
                tokio::select! {
                    Some(cmd) = outbound_rx.recv() => {
                        stream.send_command(&cmd).await?;
                    }

                    resp_res = stream.recv_response() => {
                        let resp = match resp_res {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("Koneksi tunnel terputus: {}", e);
                                break;
                            }
                        };

                        match resp {
                            CommandResponse::RemoteChannelOpened { channel_id, target_port } => {
                                info!("Koneksi masuk di Agent! Membuka koneksi lokal ke 127.0.0.1:{} (channel_id={})", target_port, channel_id);
                                let outbound_tx_clone = outbound_tx.clone();
                                let channels_clone = channels.clone();

                                match TcpStream::connect(format!("127.0.0.1:{}", target_port)).await {
                                    Ok(local_stream) => {
                                        let (mut local_reader, mut local_writer) = local_stream.into_split();
                                        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
                                        channels_clone.lock().await.insert(channel_id, data_tx);

                                        tokio::spawn(async move {
                                            let mut buf = vec![0u8; 16384];
                                            loop {
                                                match local_reader.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        let data = buf[..n].to_vec();
                                                        if outbound_tx_clone.send(RemoteCommand::ForwardData { channel_id, data }).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                            let _ = outbound_tx_clone.send(RemoteCommand::CloseForwardChannel { channel_id }).await;
                                        });

                                        tokio::spawn(async move {
                                            while let Some(chunk) = data_rx.recv().await {
                                                if local_writer.write_all(&chunk).await.is_err() {
                                                    break;
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        warn!("Gagal membuka koneksi ke aplikasi Controller di port {}: {}", target_port, e);
                                        let _ = outbound_tx.send(RemoteCommand::CloseForwardChannel { channel_id }).await;
                                    }
                                }
                            }

                            CommandResponse::ForwardDataInbound { channel_id, data } => {
                                let sender = {
                                    channels.lock().await.get(&channel_id).cloned()
                                };
                                if let Some(s) = sender {
                                    let _ = s.send(data).await;
                                }
                            }

                            CommandResponse::RemoteChannelClosed { channel_id } => {
                                info!("Remote channel {} ditutup oleh Agent", channel_id);
                                channels.lock().await.remove(&channel_id);
                            }

                            _ => ()
                        }
                    }
                }
            }
        }

        ControllerCommand::Shutdown => {
            println!("🛑 Mengirim sinyal Shutdown ke Agent...");
            stream.send_command(&RemoteCommand::ShutdownDevice).await?;
            let resp = stream.recv_response().await?;
            match resp {
                CommandResponse::TerminalOutput { stdout, .. } => println!("{}", stdout),
                other => println!("Respons: {:?}", other),
            }
        }
    }

    Ok(())
}
