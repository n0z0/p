use anyhow::Result;
use clap::{Parser, Subcommand};

use p::agent::{run_agent, AgentArgs};
use p::controller::{run_controller, ControllerArgs};
use p::crypto::generate_keypair;

#[derive(Parser, Debug)]
#[command(
    name = "p",
    author,
    version,
    about = "Custom Lightweight Multiplatform Remote Control Agent & Controller"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Jalankan sebagai Remote Agent (Server Daemon / Target)
    #[command(alias = "a")]
    Agent(AgentArgs),

    /// Jalankan sebagai Remote Controller (Admin Client)
    #[command(alias = "c")]
    Controller(ControllerArgs),

    /// Buat pasangan kunci kriptografi Noise 25519 baru
    Keygen,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Agent(args) => run_agent(args).await,
        Commands::Controller(args) => run_controller(args).await,
        Commands::Keygen => {
            let keypair = generate_keypair()?;
            println!("🔑 PASANGAN KUNCI BARU (25519):");
            println!("   Public Key : {}", hex::encode(&keypair.public));
            println!("   Private Key: {}", hex::encode(&keypair.private));
            println!("\n💡 Gunakan Public Key pada Controller (--agent-pubkey) dan Private Key pada Agent (--privkey).");
            Ok(())
        }
    }
}
