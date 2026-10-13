use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum RemoteCommand {
    RunTerminal(String),
    GetSystemStats,
    ShutdownDevice,

    // Fitur Transfer File (Chunk-Based)
    StartFileTransfer { filename: String, total_chunks: u32 },
    WriteFileChunk { chunk_index: u32, data: Vec<u8> },
    StartDownload { filepath: String },
    RequestDownloadChunk { chunk_index: u32 },

    // Fitur Pemutaran Kunci (Key Rotation)
    RequestKeyRotation,

    // Fitur Multiplexed Port Forwarding (Local & Remote)
    OpenForwardChannel { channel_id: u32, target_port: u16 },
    ForwardData { channel_id: u32, data: Vec<u8> },
    CloseForwardChannel { channel_id: u32 },

    // Autentikasi / Pairing
    Authenticate { token: String },

    // Remote Port Forwarding (-R: Agent Listener -> Controller Target)
    StartRemoteForward { bind_port: u16, target_controller_port: u16 },
    StopRemoteForward { bind_port: u16 },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum CommandResponse {
    // Autentikasi / Pairing
    AuthChallenge,
    AuthSuccess,
    AuthFailed(String),

    TerminalOutput { stdout: String, stderr: String },
    SystemStats { cpu_usage: f32, ram_used_mb: u64 },
    FileChunkAck { chunk_index: u32, success: bool },
    KeyRotationReady,

    // Respons Unduh File (Download)
    DownloadHeader { filename: String, total_chunks: u32, file_size: u64 },
    DownloadChunk { chunk_index: u32, data: Vec<u8> },
    DownloadError(String),

    // Respons Port Forwarding
    ForwardChannelAck { channel_id: u32, opened: bool },
    ForwardDataInbound { channel_id: u32, data: Vec<u8> },

    // Respons Remote Port Forwarding (-R)
    RemoteForwardAck { bind_port: u16, success: bool, message: String },
    RemoteChannelOpened { channel_id: u32, target_port: u16 },
    RemoteChannelClosed { channel_id: u32 },

    ExecutionError(String),
}
