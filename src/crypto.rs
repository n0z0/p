use std::time::Instant;
use snow::{Builder, Keypair, TransportState};
use thiserror::Error;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
pub const MAX_MESSAGE_LEN: usize = 65535;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Snow noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("Invalid key length (expected 32 bytes)")]
    InvalidKeyLength,
    #[error("Handshake not completed")]
    HandshakeIncomplete,
    #[error("Rekey error: {0}")]
    RekeyFailed(String),
}

/// Menghasilkan pasangan kunci statis 25519 baru
pub fn generate_keypair() -> Result<Keypair, CryptoError> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    Ok(builder.generate_keypair()?)
}

/// Helper untuk membuat initiator handshake (Controller)
pub fn create_initiator(
    local_privkey: &[u8],
    remote_pubkey: &[u8],
) -> Result<snow::HandshakeState, CryptoError> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let initiator = builder
        .local_private_key(local_privkey)
        .remote_public_key(remote_pubkey)
        .build_initiator()?;
    Ok(initiator)
}

/// Helper untuk membuat responder handshake (Target Agent)
pub fn create_responder(local_privkey: &[u8]) -> Result<snow::HandshakeState, CryptoError> {
    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let responder = builder.local_private_key(local_privkey).build_responder()?;
    Ok(responder)
}

/// Pembungkus Transport State dengan pelacakan volume data dan waktu untuk rotasi kunci
pub struct NoiseSession {
    transport: TransportState,
    bytes_sent: u64,
    bytes_received: u64,
    created_at: Instant,
    last_rekey: Instant,
}

impl NoiseSession {
    pub fn new(transport: TransportState) -> Self {
        let now = Instant::now();
        Self {
            transport,
            bytes_sent: 0,
            bytes_received: 0,
            created_at: now,
            last_rekey: now,
        }
    }

    /// Enkripsi data plaintext menjadi ciphertext
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; plaintext.len() + 16];
        let len = self.transport.write_message(plaintext, &mut out)?;
        out.truncate(len);
        self.bytes_sent += len as u64;
        Ok(out)
    }

    /// Dekripsi data ciphertext menjadi plaintext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut out)?;
        out.truncate(len);
        self.bytes_received += ciphertext.len() as u64;
        Ok(out)
    }

    /// Melakukan rekeying (pemutaran kunci sesi simetris)
    pub fn rekey(&mut self) -> Result<(), CryptoError> {
        self.transport.rekey_outgoing();
        self.transport.rekey_incoming();
        self.last_rekey = Instant::now();
        Ok(())
    }

    /// Cek apakah batas rotasi kunci terlewati (berdasarkan waktu atau volume data)
    pub fn needs_rekey(&self, max_duration_secs: u64, max_bytes: u64) -> bool {
        let elapsed = self.last_rekey.elapsed().as_secs();
        let total_bytes = self.bytes_sent + self.bytes_received;
        elapsed >= max_duration_secs || total_bytes >= max_bytes
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn session_duration_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    pub fn get_remote_static(&self) -> Option<&[u8]> {
        self.transport.get_remote_static()
    }
}

pub const DISCOVERY_MAGIC_REQ: &[u8] = b"P_DISCOVERY_REQ_V1\0";
pub const DISCOVERY_MAGIC_RESP: &[u8] = b"P_DISCOVERY_RESP_V1\0";

/// Menghitung sidik jari (fingerprint) SHA256 dari kunci publik
pub fn compute_key_fingerprint(pubkey: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let result = hasher.finalize();
    format!("SHA256:{}", hex::encode(result))
}

/// Mendapatkan folder konfigurasi p (~/.p)
pub fn get_config_dir() -> std::path::PathBuf {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        std::path::PathBuf::from(userprofile).join(".p")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".p")
    } else {
        std::env::temp_dir().join(".p")
    }
}

/// Memuat atau membuat kunci host persisten milik Server (~/.p/server.key, fallback ~/.p/agent.key)
pub fn load_or_create_server_key() -> Result<Keypair, CryptoError> {
    let dir = get_config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let key_file = dir.join("server.key");
    let pub_file = dir.join("server.pub");
    let legacy_key = dir.join("agent.key");
    let legacy_pub = dir.join("agent.pub");

    let actual_key = if key_file.exists() {
        key_file.clone()
    } else if legacy_key.exists() {
        legacy_key
    } else {
        key_file.clone()
    };

    if actual_key.exists() {
        if let Ok(content) = std::fs::read_to_string(&actual_key) {
            if let Ok(privkey) = hex::decode(content.trim()) {
                if privkey.len() == 32 {
                    let actual_pub = if pub_file.exists() {
                        pub_file
                    } else {
                        legacy_pub
                    };
                    let pubkey = if actual_pub.exists() {
                        hex::decode(std::fs::read_to_string(&actual_pub).unwrap_or_default().trim()).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    return Ok(Keypair {
                        private: privkey,
                        public: pubkey,
                    });
                }
            }
        }
    }

    // Buat kunci baru dan simpan
    let keypair = generate_keypair()?;
    let _ = std::fs::write(&key_file, hex::encode(&keypair.private));
    let _ = std::fs::write(&pub_file, hex::encode(&keypair.public));
    Ok(keypair)
}

/// Alias backward compatibility untuk load_or_create_server_key
pub fn load_or_create_agent_key() -> Result<Keypair, CryptoError> {
    load_or_create_server_key()
}

/// Memuat atau membuat kunci host persisten milik Client (~/.p/client.key, fallback ~/.p/controller.key)
pub fn load_or_create_client_key() -> Result<Keypair, CryptoError> {
    let dir = get_config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let key_file = dir.join("client.key");
    let pub_file = dir.join("client.pub");
    let legacy_key = dir.join("controller.key");
    let legacy_pub = dir.join("controller.pub");

    let actual_key = if key_file.exists() {
        key_file.clone()
    } else if legacy_key.exists() {
        legacy_key
    } else {
        key_file.clone()
    };

    if actual_key.exists() {
        if let Ok(content) = std::fs::read_to_string(&actual_key) {
            if let Ok(privkey) = hex::decode(content.trim()) {
                if privkey.len() == 32 {
                    let actual_pub = if pub_file.exists() {
                        pub_file
                    } else {
                        legacy_pub
                    };
                    let pubkey = if actual_pub.exists() {
                        hex::decode(std::fs::read_to_string(&actual_pub).unwrap_or_default().trim()).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    return Ok(Keypair {
                        private: privkey,
                        public: pubkey,
                    });
                }
            }
        }
    }

    // Buat kunci baru dan simpan
    let keypair = generate_keypair()?;
    let _ = std::fs::write(&key_file, hex::encode(&keypair.private));
    let _ = std::fs::write(&pub_file, hex::encode(&keypair.public));
    Ok(keypair)
}

/// Mencari kunci publik yang sudah dikenal untuk suatu alamat di ~/.p/known_servers (fallback ~/.p/known_agents)
pub fn lookup_known_server(addr: &str) -> Option<Vec<u8>> {
    let files = [
        get_config_dir().join("known_servers"),
        get_config_dir().join("known_agents"),
    ];

    for known_file in &files {
        if !known_file.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(known_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((saved_addr, key_hex)) = line.split_once('=') {
                    if saved_addr.trim() == addr.trim() {
                        if let Ok(bytes) = hex::decode(key_hex.trim()) {
                            if bytes.len() == 32 {
                                return Some(bytes);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Alias backward compatibility untuk lookup_known_server
pub fn lookup_known_agent(addr: &str) -> Option<Vec<u8>> {
    lookup_known_server(addr)
}

/// Menyimpan kunci publik Server ke ~/.p/known_servers (TOFU)
pub fn save_known_server(addr: &str, pubkey_hex: &str) -> std::io::Result<()> {
    use std::io::Write;
    let dir = get_config_dir();
    std::fs::create_dir_all(&dir)?;
    let known_file = dir.join("known_servers");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_file)?;
    writeln!(file, "{}={}", addr.trim(), pubkey_hex.trim())?;
    Ok(())
}

/// Alias backward compatibility untuk save_known_server
pub fn save_known_agent(addr: &str, pubkey_hex: &str) -> std::io::Result<()> {
    save_known_server(addr, pubkey_hex)
}

/// Memeriksa apakah kunci publik Client ada di daftar ~/.p/authorized_clients (fallback ~/.p/authorized_controllers)
pub fn is_client_authorized(pubkey: &[u8]) -> bool {
    let files = [
        get_config_dir().join("authorized_clients"),
        get_config_dir().join("authorized_controllers"),
    ];
    let target_hex = hex::encode(pubkey).to_lowercase();

    for auth_file in &files {
        if !auth_file.exists() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(auth_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let key_part = line.split_whitespace().next().unwrap_or("").to_lowercase();
                if key_part == target_hex {
                    return true;
                }
            }
        }
    }
    false
}

/// Alias backward compatibility untuk is_client_authorized
pub fn is_controller_authorized(pubkey: &[u8]) -> bool {
    is_client_authorized(pubkey)
}

/// Menambahkan kunci publik Client ke ~/.p/authorized_clients
pub fn add_authorized_client(pubkey: &[u8], comment: Option<&str>) -> std::io::Result<()> {
    use std::io::Write;
    let dir = get_config_dir();
    std::fs::create_dir_all(&dir)?;
    let auth_file = dir.join("authorized_clients");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(auth_file)?;
    let key_hex = hex::encode(pubkey);
    let desc = comment.unwrap_or("client");
    writeln!(file, "{} # {}", key_hex, desc)?;
    Ok(())
}

/// Alias backward compatibility untuk add_authorized_client
pub fn add_authorized_controller(pubkey: &[u8], comment: Option<&str>) -> std::io::Result<()> {
    add_authorized_client(pubkey, comment)
}

/// Menghasilkan token pairing acak (format xxxx-xxxx)
pub fn generate_pairing_token() -> String {
    format!("{:04x}-{:04x}", rand::random::<u16>(), rand::random::<u16>())
}

/// Memuat atau membuat token pairing rahasia milik Server (~/.p/server.token, fallback ~/.p/agent.token)
pub fn load_or_create_server_token() -> String {
    let dir = get_config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let token_file = dir.join("server.token");
    let legacy_file = dir.join("agent.token");

    let actual_file = if token_file.exists() {
        token_file.clone()
    } else if legacy_file.exists() {
        legacy_file
    } else {
        token_file.clone()
    };

    if actual_file.exists() {
        if let Ok(content) = std::fs::read_to_string(&actual_file) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    let token = generate_pairing_token();
    let _ = std::fs::write(&token_file, &token);
    token
}

/// Alias backward compatibility untuk load_or_create_server_token
pub fn load_or_create_agent_token() -> String {
    load_or_create_server_token()
}


