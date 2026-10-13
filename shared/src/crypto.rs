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
}
