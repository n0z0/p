use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use shared::crypto::generate_keypair;
use shared::framed::NoiseFramedStream;
use shared::protocol::{CommandResponse, RemoteCommand};

#[derive(Parser, Debug)]
#[command(name = "controller", author, version, about = "Custom Lightweight Remote Control Client/Controller")]
struct Cli {
    /// Alamat Target Agent (default: 127.0.0.1:9999)
    #[arg(short, long, default_value = "127.0.0.1:9999")]
    addr: String,

    /// Kunci privat statis Controller (32-byte hex). Jika kosong, kunci sementara dibuat
    #[arg(long)]
    privkey: Option<String>,

    /// Kunci publik statis Target Agent (32-byte hex) yang wajib diketahui (Noise IK)
    #[arg(long)]
    agent_pubkey: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Buat pasangan kunci 25519 baru untuk Agent atau Controller
    Keygen,

    /// Jalankan perintah terminal jarak jauh
    Exec {
        /// Perintah yang akan dijalankan
        command: String,
    },

    /// Dapatkan metrik statistik sistem dari Agent (CPU, RAM)
    Stats,

    /// Unggah file ke Agent menggunakan pengiriman berbasis chunk (64KB)
    Upload {
        /// Jalur file lokal yang ingin diunggah
        local_path: PathBuf,
        /// Nama file tujuan di Agent (opsional)
        remote_name: Option<String>,
    },

    /// Minta Agent melakukan rotasi kunci sesi (Re-Keying)
    Rekey,

    /// Port Forwarding Lokal (-L local_port:target_port)
    ForwardLocal {
        /// Format forwarding misal 8080:80 (local_port:remote_port)
        #[arg(short = 'L', long)]
        mapping: String,
    },

    /// Kirim perintah shutdown ke Agent
    Shutdown,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if let Commands::Keygen = cli.command {
        let keypair = generate_keypair().context("Gagal membuat kunci 25519")?;
        println!("🔑 PASANGAN KUNCI BARU (25519):");
        println!("   Public Key:  {}", hex::encode(&keypair.public));
        println!("   Private Key: {}", hex::encode(&keypair.private));
        println!("\n💡 Salin Public Key ke Controller (--agent-pubkey) dan Private Key ke Agent (--privkey).");
        return Ok(());
    }

    let agent_pubkey_bytes = match cli.agent_pubkey {
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

    let controller_privkey_bytes = match cli.privkey {
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

    info!("🔌 Menghubungkan ke Target Agent di {}...", cli.addr);
    let mut stream = NoiseFramedStream::connect_as_initiator(
        &cli.addr,
        &controller_privkey_bytes,
        &agent_pubkey_bytes,
    )
    .await
    .with_context(|| format!("Gagal melakukan handshake dengan {}", cli.addr))?;
    info!("🔒 Terhubung & Terenkripsi dengan Noise IK!");

    match cli.command {
        Commands::Keygen => unreachable!(),

        Commands::Exec { command } => {
            info!("📤 Mengirim perintah terminal: {}", command);
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
                CommandResponse::ExecutionError(e) => {
                    eprintln!("❌ Error eksekusi: {}", e);
                }
                other => {
                    println!("Respons tak terduga: {:?}", other);
                }
            }
        }

        Commands::Stats => {
            info!("📊 Mengambil metrik sistem...");
            stream.send_command(&RemoteCommand::GetSystemStats).await?;
            let resp = stream.recv_response().await?;
            match resp {
                CommandResponse::SystemStats { cpu_usage, ram_used_mb } => {
                    println!("╔════════════════════════════════════╗");
                    println!("║       METRIK SISTEM REMOTE         ║");
                    println!("╠════════════════════════════════════╣");
                    println!("║  CPU Usage : {:>6.2}%               ║", cpu_usage);
                    println!("║  RAM Used  : {:>6} MB             ║", ram_used_mb);
                    println!("╚════════════════════════════════════╝");
                }
                other => println!("Respons: {:?}", other),
            }
        }

        Commands::Upload { local_path, remote_name } => {
            let mut file = File::open(&local_path)
                .await
                .with_context(|| format!("Gagal membuka file lokal: {}", local_path.display()))?;
            let metadata = file.metadata().await?;
            let file_size = metadata.len();

            let filename = remote_name.unwrap_or_else(|| {
                local_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("uploaded_file.bin")
                    .to_string()
            });

            const CHUNK_SIZE: usize = 32 * 1024; // 32 KB per chunk (fit securely inside Noise MAX_MESSAGE_LEN)
            let total_chunks = ((file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as u32;

            println!("📦 Memulai upload: {} ({} bytes, {} chunks)", filename, file_size, total_chunks);
            stream
                .send_command(&RemoteCommand::StartFileTransfer {
                    filename,
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

        Commands::Rekey => {
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

        Commands::ForwardLocal { mapping } => {
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
                    // Meneruskan perintah outbound ke Agent
                    Some(cmd) = outbound_rx.recv() => {
                        stream.send_command(&cmd).await?;
                    }

                    // Menerima data inbound dari Agent
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

                    // Menerima koneksi lokal baru
                    Ok((local_stream, client_addr)) = local_listener.accept() => {
                        channel_counter += 1;
                        let channel_id = channel_counter;
                        info!("Baru terhubung di port lokal {}: channel_id={}", client_addr, channel_id);

                        let (mut local_reader, mut local_writer) = local_stream.into_split();
                        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
                        channels.lock().await.insert(channel_id, data_tx);

                        // Kirim OpenForwardChannel
                        let _ = outbound_tx.send(RemoteCommand::OpenForwardChannel {
                            channel_id,
                            target_port,
                        }).await;

                        // Task membaca dari socket lokal dan mengirim ForwardData ke Agent
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

                        // Task menerima data dari Agent dan menulis ke socket lokal
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

        Commands::Shutdown => {
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
