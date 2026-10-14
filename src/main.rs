use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use p::client::{run_client, ClientArgs, ClientCommand};
use p::crypto::generate_keypair;
use p::server::{run_server, ServerArgs};

#[derive(Parser, Debug)]
#[command(
    name = "p",
    author,
    version,
    about = "Lightweight Multiplatform Remote Access Tool (SSH-like Server & Client)"
)]
struct Cli {
    /// Alamat target remote (contoh: 1.2.3.4:9999).
    /// Jika diisi, otomatis menjadi Client (klien pengontrol, mirip ssh).
    /// Jika kosong, otomatis menjadi Server (daemon pelayan, mirip sshd).
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Port listen (untuk Server), contoh: -p 9999
    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    /// Alamat bind/target via flag
    #[arg(short = 'a', long)]
    pub addr: Option<String>,

    /// Token rahasia / Password untuk otorisasi (pairing)
    #[arg(short = 't', long)]
    pub token: Option<String>,

    /// Kunci privat statis (32-byte hex)
    #[arg(long)]
    pub privkey: Option<String>,

    /// Kunci publik milik target Server (32-byte hex)
    #[arg(short = 'k', long = "server-pubkey", alias = "agent-pubkey")]
    pub server_pubkey: Option<String>,

    /// Folder penyimpanan file yang diterima (Server)
    #[arg(long, default_value = "./storage")]
    pub storage_dir: PathBuf,

    /// Mode Reverse Connection (NAT/Firewall Traversal):
    /// - Pada server (di balik NAT): `p <IP_CLIENT>:9999 -r` (server menghubung keluar ke client)
    /// - Pada client: `p -r` atau `p -r -p 9999` (client mendengarkan koneksi masuk dari server)
    #[arg(short = 'r', long = "reverse")]
    pub reverse: bool,

    /// Local Port Forwarding (seperti ssh -L local_port:remote_port), contoh: -L 8080:80
    #[arg(short = 'L', long = "forward-local", value_name = "LOCAL:REMOTE")]
    pub forward_local: Option<String>,

    /// Remote Port Forwarding (seperti ssh -R remote_port:local_port), contoh: -R 9090:8080
    #[arg(short = 'R', long = "forward-remote", value_name = "REMOTE:LOCAL")]
    pub forward_remote: Option<String>,

    #[command(subcommand)]
    pub command: Option<ClientCommand>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // 1. Cek apakah pengguna memanggil keygen: `p keygen`
    if cli.target.as_deref() == Some("keygen") || matches!(cli.command, Some(ClientCommand::Keygen)) {
        let keypair = generate_keypair()?;
        println!("🔑 PASANGAN KUNCI BARU (25519):");
        println!("   Public Key : {}", hex::encode(&keypair.public));
        println!("   Private Key: {}", hex::encode(&keypair.private));
        println!("\n💡 Gunakan Public Key pada Client (-k) dan Private Key pada Server (--privkey).");
        return Ok(());
    }

    // Resolusi command port forwarding dari flag -L / -R
    let command = if let Some(mapping) = cli.forward_local {
        Some(ClientCommand::ForwardLocal { mapping })
    } else if let Some(mapping) = cli.forward_remote {
        Some(ClientCommand::ForwardRemote { mapping })
    } else {
        cli.command
    };

    // 2. Tentukan peran: Client vs Server
    // - Jika flag -r aktif dan ada target -> Server connecting reverse to Client
    // - Jika flag -r aktif tanpa target -> Client listening for reverse Server
    // - Jika normal dan ada target / command -> Client connecting to Server
    // - Jika normal tanpa target -> Server listening
    let is_client = if cli.reverse {
        cli.target.is_none() // Jika tanpa target, Client yang listen
    } else {
        cli.target.is_some() || command.is_some()
    };

    if is_client {
        let addr = cli.addr.or_else(|| cli.port.map(|p| format!("0.0.0.0:{}", p)));
        let args = ClientArgs {
            addr_pos: cli.target,
            addr,
            token: cli.token,
            privkey: cli.privkey,
            server_pubkey: cli.server_pubkey,
            reverse: cli.reverse,
            command,
        };
        run_client(args).await
    } else {
        // Mode Server (Daemon Pelayan)
        let mode = if cli.reverse && cli.target.is_some() {
            "connect".to_string() // Reverse connection outbound
        } else {
            "listen".to_string()
        };

        let addr = if mode == "connect" {
            cli.target.or(cli.addr).unwrap_or_else(|| "127.0.0.1:9999".into())
        } else if let Some(a) = cli.addr {
            a
        } else if let Some(p) = cli.port {
            format!("0.0.0.0:{}", p)
        } else {
            "0.0.0.0:9999".into()
        };

        let args = ServerArgs {
            mode,
            addr,
            privkey: cli.privkey,
            token: cli.token,
            storage_dir: cli.storage_dir,
            key_rotation_secs: 3600,
            key_rotation_bytes: 1_073_741_824,
        };
        run_server(args).await
    }
}
