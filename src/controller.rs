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

use crate::crypto::generate_keypair;
use crate::framed::NoiseFramedStream;
use crate::protocol::{CommandResponse, RemoteCommand};

#[derive(Args, Debug, Clone)]
pub struct ControllerArgs {
    /// Alamat Target Agent (default: 127.0.0.1:9999)
    #[arg(short, long, default_value = "127.0.0.1:9999")]
    pub addr: String,

    /// Kunci privat statis Controller (32-byte hex). Jika kosong, kunci sementara dibuat
    #[arg(long)]
    pub privkey: Option<String>,

    /// Kunci publik statis milik Target Agent (32-byte hex)
    #[arg(short, long)]
    pub agent_pubkey: Option<String>,

    #[command(subcommand)]
    pub command: ControllerCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ControllerCommand {
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

pub async fn run_controller(args: ControllerArgs) -> Result<()> {
    let agent_pubkey_bytes = match args.agent_pubkey {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).context("Format hex agent_pubkey tidak valid")?;
            if bytes.len() != 32 {
                bail!("Panjang agent_pubkey harus 32 byte!");
            }
            bytes
        }
        None => {
            bail!("Parameter --agent-pubkey (32-byte hex) wajib disertakan untuk handshake Noise IK!");
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
            let kp = generate_keypair()?;
            info!("Menggunakan kunci Controller sementara: {}", hex::encode(&kp.public));
            kp.private
        }
    };

    info!("🌐 Menghubungkan ke Agent di {}...", args.addr);
    let mut stream = NoiseFramedStream::connect_as_initiator(
        &args.addr,
        &controller_privkey_bytes,
        &agent_pubkey_bytes,
    )
    .await
    .context("Gagal melakukan handshake terenkripsi Noise ke Agent")?;

    info!("🔒 Terhubung dengan aman ke Agent! Mengirim perintah...");

    match args.command {
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
