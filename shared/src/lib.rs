pub mod crypto;
pub mod framed;
pub mod os;
pub mod protocol;

pub use crypto::{generate_keypair, NoiseSession, NOISE_PATTERN};
pub use framed::{FrameError, NoiseFramedStream};
pub use os::{execute_os_command, get_system_stats, shutdown_system};
pub use protocol::{CommandResponse, RemoteCommand};
