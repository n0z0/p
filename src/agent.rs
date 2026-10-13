use anyhow::{bail, Context, Result};
use clap::Args;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use crate::crypto::{compute_key_fingerprint, load_or_create_agent_key};
use crate::framed::NoiseFramedStream;
use crate::os::{execute_os_command, get_system_stats, shutdown_system};
use crate::protocol::{CommandResponse, RemoteCommand};

#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
    /// Mode operasi: 'listen' untuk menunggu Controller atau 'connect' untuk reverse-connection ke Controller
    #[arg(short, long, default_value = "listen")]
    pub mode: String,

    /// Alamat target (0.0.0.0:9999 untuk listen, atau 127.0.0.1:9999 untuk connect)
    #[arg(short, long, default_value = "0.0.0.0:9999")]
    pub addr: String,

    /// Kunci privat statis dalam format heksadesimal (32-byte). Jika kosong, kunci persisten ~/.p/agent.key akan digunakan
    #[arg(short, long)]
    pub privkey: Option<String>,

    /// Folder penyimpanan file yang diterima
    #[arg(short, long, default_value = "./storage")]
    pub storage_dir: PathBuf,

    /// Interval rotasi kunci otomatis dalam detik (default: 3600s / 1 jam)
    #[arg(long, default_value_t = 3600)]
    pub key_rotation_secs: u64,

    /// Batas volume data rotasi kunci otomatis dalam byte (default: 1 GB)
    #[arg(long, default_value_t = 1_073_741_824)]
    pub key_rotation_bytes: u64,
}

struct FileTransferState {
    filename: String,
    total_chunks: u32,
    received_chunks: u32,
    file: File,
}

pub async fn run_agent(args: AgentArgs) -> Result<()> {
    tokio::fs::create_dir_all(&args.storage_dir)
        .await
        .context("Gagal membuat direktori storage")?;

    let (privkey_bytes, pubkey_bytes) = match &args.privkey {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).context("Format hex privkey tidak valid")?;
            if bytes.len() != 32 {
                bail!("Panjang privkey harus tepat 32 byte!");
            }
            (bytes, Vec::new())
        }
        None => {
            let keypair = load_or_create_agent_key().context("Gagal memuat atau membuat kunci host persisten")?;
            let fingerprint = compute_key_fingerprint(&keypair.public);
            println!("🔑 Kunci Host Agent Persisten (~/.p/agent.key):");
            println!("   Public Key  : {}", hex::encode(&keypair.public));
            println!("   Fingerprint : {}", fingerprint);
            println!("   SSH-Style   : Controller dapat otomatis mendeteksi & menyimpan kunci ini (TOFU)!");
            println!();
            (keypair.private, keypair.public)
        }
    };

    match args.mode.to_lowercase().as_str() {
        "listen" => {
            run_listen_loop(&args, &privkey_bytes, &pubkey_bytes).await?;
        }
        "connect" => {
            run_reconnect_loop(&args, &privkey_bytes, &pubkey_bytes).await?;
        }
        other => {
            bail!("Mode tidak dikenal '{}'. Gunakan 'listen' atau 'connect'.", other);
        }
    }

    Ok(())
}

async fn run_listen_loop(args: &AgentArgs, privkey: &[u8], pubkey: &[u8]) -> Result<()> {
    let listener = TcpListener::bind(&args.addr)
        .await
        .with_context(|| format!("Gagal bind ke {}", args.addr))?;

    info!("🚀 Remote Agent aktif dalam mode LISTEN di {}", args.addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("🌐 Koneksi masuk dari {}", peer_addr);
                let privkey_clone = privkey.to_vec();
                let pubkey_clone = pubkey.to_vec();
                let storage_dir = args.storage_dir.clone();
                let rot_secs = args.key_rotation_secs;
                let rot_bytes = args.key_rotation_bytes;

                tokio::spawn(async move {
                    match NoiseFramedStream::accept_as_responder(stream, &privkey_clone, &pubkey_clone).await {
                        Ok(framed) => {
                            info!("🔒 Handshake Noise IK sukses dengan {}", peer_addr);
                            if let Err(e) = handle_session(framed, storage_dir, rot_secs, rot_bytes).await {
                                warn!("⚠️ Sesi terputus dengan {}: {}", peer_addr, e);
                            }
                        }
                        Err(e) => {
                            // Jika sekadar probe discovery TOFU atau disconnect biasa, jangan anggap error fatal
                            info!("Koneksi selesai dari {}: {}", peer_addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Gagal menerima koneksi: {}", e);
            }
        }
    }
}

async fn run_reconnect_loop(args: &AgentArgs, privkey: &[u8], pubkey: &[u8]) -> Result<()> {
    let mut backoff = 1u64;
    let max_backoff = 60u64;

    loop {
        info!("🔄 Menghubungi Controller di {} ...", args.addr);
        match TcpStream::connect(&args.addr).await {
            Ok(stream) => {
                info!("🌐 Koneksi TCP terbuka ke {}. Memulai Noise handshake...", args.addr);
                match NoiseFramedStream::accept_as_responder(stream, privkey, pubkey).await {
                    Ok(framed) => {
                        info!("🔒 Handshake terenkripsi sukses!");
                        backoff = 1;
                        if let Err(e) = handle_session(
                            framed,
                            args.storage_dir.clone(),
                            args.key_rotation_secs,
                            args.key_rotation_bytes,
                        )
                        .await
                        {
                            warn!("⚠️ Sesi terputus: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("❌ Handshake gagal: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Gagal koneksi ke {}: {}", args.addr, e);
            }
        }

        info!("⏳ Mencoba kembali dalam {} detik (Exponential Backoff)...", backoff);
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

async fn handle_session(
    mut stream: NoiseFramedStream,
    storage_dir: PathBuf,
    key_rotation_secs: u64,
    key_rotation_bytes: u64,
) -> Result<()> {
    let channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let remote_listeners: Arc<Mutex<HashMap<u16, tokio::sync::oneshot::Sender<()>>>> = Arc::new(Mutex::new(HashMap::new()));
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<CommandResponse>(128);

    let mut current_file: Option<FileTransferState> = None;
    let mut current_download: Option<File> = None;

    loop {
        if stream.needs_rekey(key_rotation_secs, key_rotation_bytes) {
            info!("🔄 Batas waktu/volume data rotasi kunci tercapai. Memutar kunci simetris...");
            if let Err(e) = stream.rekey() {
                warn!("Gagal melakukan rotasi kunci otomatis: {}", e);
            }
        }

        tokio::select! {
            Some(resp) = outbound_rx.recv() => {
                stream.send_response(&resp).await?;
            }

            cmd_res = stream.recv_command() => {
                let cmd = match cmd_res {
                    Ok(c) => c,
                    Err(e) => {
                        info!("Koneksi sesi ditutup: {}", e);
                        break;
                    }
                };

                match cmd {
                    RemoteCommand::RunTerminal(command_str) => {
                        info!("💻 Menjalankan perintah terminal: {}", command_str);
                        let (stdout, stderr) = match execute_os_command(&command_str) {
                            Ok(out) => (out, String::new()),
                            Err(err) => (String::new(), err),
                        };
                        stream.send_response(&CommandResponse::TerminalOutput { stdout, stderr }).await?;
                    }

                    RemoteCommand::GetSystemStats => {
                        info!("📊 Membaca metrik performa sistem (CPU & RAM)...");
                        let (cpu_usage, ram_used_mb) = get_system_stats();
                        stream.send_response(&CommandResponse::SystemStats {
                            cpu_usage,
                            ram_used_mb,
                        }).await?;
                    }

                    RemoteCommand::ShutdownDevice => {
                        info!("🛑 Menerima perintah shutdown perangkat!");
                        match shutdown_system() {
                            Ok(msg) => {
                                stream.send_response(&CommandResponse::TerminalOutput {
                                    stdout: format!("Shutdown berhasil dipicu: {}", msg),
                                    stderr: String::new(),
                                }).await?;
                            }
                            Err(err) => {
                                stream.send_response(&CommandResponse::ExecutionError(err)).await?;
                            }
                        }
                    }

                    RemoteCommand::StartFileTransfer { filename, total_chunks } => {
                        info!("📥 Memulai penerimaan file: {} (total {} chunk)", filename, total_chunks);
                        let file_path = storage_dir.join(Path::new(&filename).file_name().unwrap_or(filename.as_ref()));
                        match OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(&file_path)
                            .await
                        {
                            Ok(f) => {
                                current_file = Some(FileTransferState {
                                    filename: filename.clone(),
                                    total_chunks,
                                    received_chunks: 0,
                                    file: f,
                                });
                                stream.send_response(&CommandResponse::FileChunkAck {
                                    chunk_index: 0,
                                    success: true,
                                }).await?;
                            }
                            Err(e) => {
                                error!("Gagal membuat file {}: {}", file_path.display(), e);
                                stream.send_response(&CommandResponse::FileChunkAck {
                                    chunk_index: 0,
                                    success: false,
                                }).await?;
                            }
                        }
                    }

                    RemoteCommand::WriteFileChunk { chunk_index, data } => {
                        let mut success = false;
                        if let Some(state) = &mut current_file {
                            if let Err(e) = state.file.write_all(&data).await {
                                error!("Gagal menulis chunk {}: {}", chunk_index, e);
                            } else {
                                state.received_chunks += 1;
                                success = true;
                                if state.received_chunks >= state.total_chunks {
                                    let _ = state.file.flush().await;
                                    info!("✅ File {} selesai diterima ({} chunks)!", state.filename, state.total_chunks);
                                }
                            }
                        }
                        stream.send_response(&CommandResponse::FileChunkAck { chunk_index, success }).await?;
                    }

                    RemoteCommand::StartDownload { filepath } => {
                        info!("📤 Permintaan unduh file diterima: {}", filepath);
                        let path = PathBuf::from(&filepath);
                        match File::open(&path).await {
                            Ok(file) => {
                                match file.metadata().await {
                                    Ok(meta) => {
                                        let file_size = meta.len();
                                        let total_chunks = ((file_size + 32768 - 1) / 32768) as u32;
                                        let filename = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                        current_download = Some(file);
                                        stream.send_response(&CommandResponse::DownloadHeader {
                                            filename,
                                            total_chunks,
                                            file_size,
                                        }).await?;
                                    }
                                    Err(e) => {
                                        stream.send_response(&CommandResponse::DownloadError(format!("Gagal membaca metadata: {}", e))).await?;
                                    }
                                }
                            }
                            Err(e) => {
                                stream.send_response(&CommandResponse::DownloadError(format!("File tidak ditemukan atau gagal dibuka: {}", e))).await?;
                            }
                        }
                    }

                    RemoteCommand::RequestDownloadChunk { chunk_index } => {
                        let mut chunk_data = Vec::new();
                        if let Some(file) = &mut current_download {
                            use tokio::io::AsyncSeekExt;
                            let offset = chunk_index as u64 * 32768;
                            if file.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                                let mut buf = vec![0u8; 32768];
                                if let Ok(n) = file.read(&mut buf).await {
                                    buf.truncate(n);
                                    chunk_data = buf;
                                }
                            }
                        }
                        stream.send_response(&CommandResponse::DownloadChunk { chunk_index, data: chunk_data }).await?;
                    }

                    RemoteCommand::RequestKeyRotation => {
                        info!("🔑 Permintaan pemutaran kunci diterima. Memutar kunci...");
                        if let Err(e) = stream.rekey() {
                            stream.send_response(&CommandResponse::ExecutionError(format!("Rekey failed: {}", e))).await?;
                        } else {
                            stream.send_response(&CommandResponse::KeyRotationReady).await?;
                        }
                    }

                    RemoteCommand::OpenForwardChannel { channel_id, target_port } => {
                        info!("🔀 Membuka port forward channel {}: target port {}", channel_id, target_port);
                        let target_addr = format!("127.0.0.1:{}", target_port);

                        match TcpStream::connect(&target_addr).await {
                            Ok(target_stream) => {
                                let (mut reader, mut writer) = target_stream.into_split();
                                let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);

                                channels.lock().await.insert(channel_id, data_tx);

                                tokio::spawn(async move {
                                    while let Some(chunk) = data_rx.recv().await {
                                        if let Err(e) = writer.write_all(&chunk).await {
                                            warn!("Gagal menulis ke target port {}: {}", target_port, e);
                                            break;
                                        }
                                    }
                                });

                                let outbound_tx_clone = outbound_tx.clone();
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 16384];
                                    loop {
                                        match reader.read(&mut buf).await {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                let payload = buf[..n].to_vec();
                                                if outbound_tx_clone
                                                    .send(CommandResponse::ForwardDataInbound {
                                                        channel_id,
                                                        data: payload,
                                                    })
                                                    .await
                                                    .is_err()
                                                {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                });

                                stream.send_response(&CommandResponse::ForwardChannelAck {
                                    channel_id,
                                    opened: true,
                                }).await?;
                            }
                            Err(e) => {
                                warn!("Gagal membuka koneksi ke port target {}: {}", target_port, e);
                                stream.send_response(&CommandResponse::ForwardChannelAck {
                                    channel_id,
                                    opened: false,
                                }).await?;
                            }
                        }
                    }

                    RemoteCommand::ForwardData { channel_id, data } => {
                        let sender_opt = {
                            let lock = channels.lock().await;
                            lock.get(&channel_id).cloned()
                        };

                        if let Some(sender) = sender_opt {
                            let _ = sender.send(data).await;
                        }
                    }

                    RemoteCommand::CloseForwardChannel { channel_id } => {
                        info!("Menutup forward channel {}", channel_id);
                        channels.lock().await.remove(&channel_id);
                    }

                    RemoteCommand::StartRemoteForward { bind_port, target_controller_port } => {
                        info!("🔀 Membuka remote forward listener di port {} (target controller port {})", bind_port, target_controller_port);
                        
                        let bind_res = match TcpListener::bind(format!("0.0.0.0:{}", bind_port)).await {
                            Ok(l) => Ok(l),
                            Err(_) => TcpListener::bind(format!("127.0.0.1:{}", bind_port)).await,
                        };

                        match bind_res {
                            Ok(listener) => {
                                info!("✅ Remote forward listening di port {}", bind_port);
                                stream.send_response(&CommandResponse::RemoteForwardAck {
                                    bind_port,
                                    success: true,
                                    message: format!("Listening on port {}", bind_port),
                                }).await?;

                                let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
                                remote_listeners.lock().await.insert(bind_port, stop_tx);

                                let outbound_tx_listener = outbound_tx.clone();
                                let channels_listener = channels.clone();

                                tokio::spawn(async move {
                                    static REMOTE_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x8000_0000);
                                    loop {
                                        tokio::select! {
                                            _ = &mut stop_rx => {
                                                info!("Remote listener port {} dimatikan", bind_port);
                                                break;
                                            }
                                            accept_res = listener.accept() => {
                                                let (client_stream, client_addr) = match accept_res {
                                                    Ok(res) => res,
                                                    Err(e) => {
                                                        warn!("Gagal menerima koneksi di port {}: {}", bind_port, e);
                                                        break;
                                                    }
                                                };

                                                let channel_id = REMOTE_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                                info!("Koneksi remote baru di Agent port {} dari {}: channel_id={}", bind_port, client_addr, channel_id);

                                                let (mut client_reader, mut client_writer) = client_stream.into_split();
                                                let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
                                                channels_listener.lock().await.insert(channel_id, data_tx);

                                                if outbound_tx_listener.send(CommandResponse::RemoteChannelOpened {
                                                    channel_id,
                                                    target_port: target_controller_port,
                                                }).await.is_err() {
                                                    break;
                                                }

                                                tokio::spawn(async move {
                                                    while let Some(chunk) = data_rx.recv().await {
                                                        if client_writer.write_all(&chunk).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                });

                                                let outbound_tx_stream = outbound_tx_listener.clone();
                                                let channels_cleanup = channels_listener.clone();
                                                tokio::spawn(async move {
                                                    let mut buf = vec![0u8; 16384];
                                                    loop {
                                                        match client_reader.read(&mut buf).await {
                                                            Ok(0) => break,
                                                            Ok(n) => {
                                                                let data = buf[..n].to_vec();
                                                                if outbound_tx_stream.send(CommandResponse::ForwardDataInbound {
                                                                    channel_id,
                                                                    data,
                                                                }).await.is_err() {
                                                                    break;
                                                                }
                                                            }
                                                            Err(_) => break,
                                                        }
                                                    }
                                                    channels_cleanup.lock().await.remove(&channel_id);
                                                    let _ = outbound_tx_stream.send(CommandResponse::RemoteChannelClosed { channel_id }).await;
                                                });
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("Gagal bind remote forward port {}: {}", bind_port, e);
                                stream.send_response(&CommandResponse::RemoteForwardAck {
                                    bind_port,
                                    success: false,
                                    message: format!("Gagal bind port {}: {}", bind_port, e),
                                }).await?;
                            }
                        }
                    }

                    RemoteCommand::StopRemoteForward { bind_port } => {
                        info!("🛑 Menghentikan remote forward listener di port {}", bind_port);
                        if let Some(stop_tx) = remote_listeners.lock().await.remove(&bind_port) {
                            let _ = stop_tx.send(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
