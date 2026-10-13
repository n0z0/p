use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use p::agent::{run_agent, AgentArgs};
use p::controller::{run_controller, ControllerArgs, ControllerCommand};
use p::crypto::generate_keypair;

#[derive(Parser, Debug)]
#[command(
    name = "p",
    author,
    version,
    about = "Custom Lightweight Multiplatform Remote Control Agent & Controller"
)]
struct Cli {
    /// Alamat target remote (contoh: 1.2.3.4:9999).
    /// Jika diisi, otomatis menjadi Controller (klien pengontrol).
    /// Jika kosong, otomatis menjadi Agent (server/daemon).
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Port listen (untuk Agent), contoh: -p 9999
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

    /// Kunci publik milik target Agent (32-byte hex)
    #[arg(short = 'k', long)]
    pub agent_pubkey: Option<String>,

    /// Folder penyimpanan file yang diterima (Agent)
    #[arg(long, default_value = "./storage")]
    pub storage_dir: PathBuf,

    /// Mode Reverse Connection:
    /// - Pada target/agent: `p 1.2.3.4:9999 -R` (agent menghubung balik ke controller)
    /// - Pada controller: `p -R` atau `p -R -p 9999` (controller mendengarkan koneksi masuk dari agent)
    #[arg(short = 'R', long = "reverse")]
    pub reverse: bool,

    #[command(subcommand)]
    pub command: Option<ControllerCommand>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // 1. Cek apakah pengguna memanggil keygen: `p keygen`
    if cli.target.as_deref() == Some("keygen") || matches!(cli.command, Some(ControllerCommand::Keygen)) {
        let keypair = generate_keypair()?;
        println!("🔑 PASANGAN KUNCI BARU (25519):");
        println!("   Public Key : {}", hex::encode(&keypair.public));
        println!("   Private Key: {}", hex::encode(&keypair.private));
        println!("\n💡 Gunakan Public Key pada Controller (-k) dan Private Key pada Agent (--privkey).");
        return Ok(());
    }

    // 2. Tentukan peran: Controller vs Agent
    // - Jika flag -R aktif dan ada target -> Agent connecting reverse to Controller
    // - Jika flag -R aktif tanpa target -> Controller listening for reverse Agent
    // - Jika normal dan ada target / command -> Controller connecting to Agent
    // - Jika normal tanpa target -> Agent listening
    let is_controller = if cli.reverse {
        cli.target.is_none() // Jika tanpa target, Controller yang listen
    } else {
        cli.target.is_some() || cli.command.is_some()
    };

    if is_controller {
        let addr = cli.addr.or_else(|| cli.port.map(|p| format!("0.0.0.0:{}", p)));
        let args = ControllerArgs {
            addr_pos: cli.target,
            addr,
            token: cli.token,
            privkey: cli.privkey,
            agent_pubkey: cli.agent_pubkey,
            reverse: cli.reverse,
            command: cli.command,
        };
        run_controller(args).await
    } else {
        // Mode Agent (Server Daemon)
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

        let args = AgentArgs {
            mode,
            addr,
            privkey: cli.privkey,
            token: cli.token,
            storage_dir: cli.storage_dir,
            key_rotation_secs: 3600,
            key_rotation_bytes: 1_073_741_824,
        };
        run_agent(args).await
    }
}
