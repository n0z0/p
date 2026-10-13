use std::io;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use thiserror::Error;

use crate::crypto::{create_initiator, create_responder, CryptoError, NoiseSession, MAX_MESSAGE_LEN};
use crate::protocol::{CommandResponse, RemoteCommand};

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Bincode serialization/deserialization error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("Connection closed by peer")]
    ConnectionClosed,
    #[error("Invalid handshake message")]
    InvalidHandshake,
}

pub struct NoiseFramedStream {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    session: NoiseSession,
}

impl NoiseFramedStream {
    /// Inisialisasi koneksi dari sisi Initiator (Client/Controller) dengan Handshake Noise IK
    pub async fn connect_as_initiator(
        addr: &str,
        local_privkey: &[u8],
        remote_pubkey: &[u8],
    ) -> Result<Self, FrameError> {
        let stream = TcpStream::connect(addr).await?;
        let mut framed = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .max_frame_length(MAX_MESSAGE_LEN)
            .new_framed(stream);

        let mut initiator = create_initiator(local_privkey, remote_pubkey)?;

        // Pesan 1 Handshake: Initiator -> Responder
        let mut msg1 = vec![0u8; MAX_MESSAGE_LEN];
        let len1 = initiator.write_message(&[], &mut msg1).map_err(CryptoError::Noise)?;
        msg1.truncate(len1);
        framed.send(Bytes::from(msg1)).await?;

        // Pesan 2 Handshake: Responder -> Initiator
        let msg2_frame = framed
            .next()
            .await
            .ok_or(FrameError::ConnectionClosed)??;
        let mut payload_buf = vec![0u8; MAX_MESSAGE_LEN];
        initiator
            .read_message(&msg2_frame, &mut payload_buf)
            .map_err(CryptoError::Noise)?;

        let transport = initiator.into_transport_mode().map_err(CryptoError::Noise)?;
        let session = NoiseSession::new(transport);

        Ok(Self { framed, session })
    }

    /// Menerima koneksi masuk dari sisi Responder (Agent) dan menyelesaikan Handshake Noise IK
    pub async fn accept_as_responder(
        stream: TcpStream,
        local_privkey: &[u8],
    ) -> Result<Self, FrameError> {
        let mut framed = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .max_frame_length(MAX_MESSAGE_LEN)
            .new_framed(stream);

        let mut responder = create_responder(local_privkey)?;

        // Pesan 1 Handshake: Initiator -> Responder
        let msg1_frame = framed
            .next()
            .await
            .ok_or(FrameError::ConnectionClosed)??;
        let mut payload_buf = vec![0u8; MAX_MESSAGE_LEN];
        responder
            .read_message(&msg1_frame, &mut payload_buf)
            .map_err(CryptoError::Noise)?;

        // Pesan 2 Handshake: Responder -> Initiator
        let mut msg2 = vec![0u8; MAX_MESSAGE_LEN];
        let len2 = responder.write_message(&[], &mut msg2).map_err(CryptoError::Noise)?;
        msg2.truncate(len2);
        framed.send(Bytes::from(msg2)).await?;

        let transport = responder.into_transport_mode().map_err(CryptoError::Noise)?;
        let session = NoiseSession::new(transport);

        Ok(Self { framed, session })
    }

    /// Kirim RemoteCommand terenkripsi via Bincode & Noise
    pub async fn send_command(&mut self, cmd: &RemoteCommand) -> Result<(), FrameError> {
        let serialized = bincode::serialize(cmd)?;
        let ciphertext = self.session.encrypt(&serialized)?;
        self.framed.send(Bytes::from(ciphertext)).await?;
        Ok(())
    }

    /// Terima RemoteCommand terenkripsi lalu didekripsi
    pub async fn recv_command(&mut self) -> Result<RemoteCommand, FrameError> {
        let frame = self
            .framed
            .next()
            .await
            .ok_or(FrameError::ConnectionClosed)??;
        let plaintext = self.session.decrypt(&frame)?;
        let cmd = bincode::deserialize(&plaintext)?;
        Ok(cmd)
    }

    /// Kirim CommandResponse terenkripsi via Bincode & Noise
    pub async fn send_response(&mut self, res: &CommandResponse) -> Result<(), FrameError> {
        let serialized = bincode::serialize(res)?;
        let ciphertext = self.session.encrypt(&serialized)?;
        self.framed.send(Bytes::from(ciphertext)).await?;
        Ok(())
    }

    /// Terima CommandResponse terenkripsi lalu didekripsi
    pub async fn recv_response(&mut self) -> Result<CommandResponse, FrameError> {
        let frame = self
            .framed
            .next()
            .await
            .ok_or(FrameError::ConnectionClosed)??;
        let plaintext = self.session.decrypt(&frame)?;
        let res = bincode::deserialize(&plaintext)?;
        Ok(res)
    }

    /// Pemicu rotasi kunci secara manual
    pub fn rekey(&mut self) -> Result<(), CryptoError> {
        self.session.rekey()
    }

    /// Cek apakah rotasi kunci diperlukan
    pub fn needs_rekey(&self, max_duration_secs: u64, max_bytes: u64) -> bool {
        self.session.needs_rekey(max_duration_secs, max_bytes)
    }

    pub fn total_bytes(&self) -> u64 {
        self.session.total_bytes()
    }
}
