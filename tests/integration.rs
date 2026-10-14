use p::crypto::generate_keypair;
use p::framed::NoiseFramedStream;
use p::protocol::{CommandResponse, RemoteCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_noise_handshake_and_command_exchange() {
    let agent_keypair = generate_keypair().expect("Failed to gen agent keys");
    let controller_keypair = generate_keypair().expect("Failed to gen controller keys");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let agent_pub_for_acceptor = agent_pub.clone();
    // Spawn Agent acceptor
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor)
            .await
            .expect("Agent handshake failed");

        // Receive command
        let cmd = framed.recv_command().await.expect("Agent failed to recv cmd");
        assert_eq!(cmd, RemoteCommand::GetSystemStats);

        // Send response
        let res = CommandResponse::SystemStats {
            cpu_usage: 12.5,
            ram_used_mb: 2048,
        };
        framed.send_response(&res).await.expect("Agent failed to send response");

        // Rekey test
        let rekey_cmd = framed.recv_command().await.expect("Recv rekey cmd");
        assert_eq!(rekey_cmd, RemoteCommand::RequestKeyRotation);
        framed.rekey().expect("Agent rekey failed");
        framed
            .send_response(&CommandResponse::KeyRotationReady)
            .await
            .expect("Send rekey ack");

        // Subsequent message after rekey
        let final_cmd = framed.recv_command().await.expect("Recv final cmd");
        assert_eq!(final_cmd, RemoteCommand::RunTerminal("whoami".into()));
        framed
            .send_response(&CommandResponse::TerminalOutput {
                stdout: "agent_user\n".into(),
                stderr: String::new(),
            })
            .await
            .unwrap();
    });

    // Controller connects
    let mut controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    )
    .await
    .expect("Controller handshake failed");

    // Send GetSystemStats
    controller
        .send_command(&RemoteCommand::GetSystemStats)
        .await
        .unwrap();

    let res = controller.recv_response().await.unwrap();
    match res {
        CommandResponse::SystemStats {
            cpu_usage,
            ram_used_mb,
        } => {
            assert_eq!(cpu_usage, 12.5);
            assert_eq!(ram_used_mb, 2048);
        }
        _ => panic!("Unexpected response: {:?}", res),
    }

    // Trigger Key Rotation
    controller
        .send_command(&RemoteCommand::RequestKeyRotation)
        .await
        .unwrap();
    controller.rekey().expect("Controller rekey failed");
    let rekey_res = controller.recv_response().await.unwrap();
    assert_eq!(rekey_res, CommandResponse::KeyRotationReady);

    // Verify channel still works seamlessly after rekey
    controller
        .send_command(&RemoteCommand::RunTerminal("whoami".into()))
        .await
        .unwrap();
    let final_res = controller.recv_response().await.unwrap();
    match final_res {
        CommandResponse::TerminalOutput { stdout, stderr } => {
            assert_eq!(stdout, "agent_user\n");
            assert!(stderr.is_empty());
        }
        _ => panic!("Unexpected final response: {:?}", final_res),
    }

    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_chunked_file_transfer() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let test_data = vec![0xABu8; 150_000]; // 150 KB test payload
    let test_data_clone = test_data.clone();
    let agent_pub_for_acceptor = agent_pub.clone();

    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor).await.unwrap();

        // Expect StartFileTransfer
        let start_cmd = framed.recv_command().await.unwrap();
        let mut assembled_bytes = Vec::new();
        let total_chunks_expected;

        match start_cmd {
            RemoteCommand::StartFileTransfer { filename, total_chunks } => {
                assert_eq!(filename, "test_file.bin");
                total_chunks_expected = total_chunks;
                framed.send_response(&CommandResponse::FileChunkAck { chunk_index: 0, success: true }).await.unwrap();
            }
            _ => panic!("Expected StartFileTransfer"),
        }

        for idx in 0..total_chunks_expected {
            let chunk_cmd = framed.recv_command().await.unwrap();
            match chunk_cmd {
                RemoteCommand::WriteFileChunk { chunk_index, data } => {
                    assert_eq!(chunk_index, idx);
                    assembled_bytes.extend_from_slice(&data);
                    framed.send_response(&CommandResponse::FileChunkAck { chunk_index, success: true }).await.unwrap();
                }
                _ => panic!("Expected WriteFileChunk"),
            }
        }

        assert_eq!(assembled_bytes, test_data_clone);
    });

    let mut controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    )
    .await
    .unwrap();

    const CHUNK_SIZE: usize = 32 * 1024; // 32 KB per chunk to ensure Noise frame headroom
    let total_chunks = ((test_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;

    controller.send_command(&RemoteCommand::StartFileTransfer {
        filename: "test_file.bin".into(),
        total_chunks,
    }).await.unwrap();

    let ack = controller.recv_response().await.unwrap();
    assert_eq!(ack, CommandResponse::FileChunkAck { chunk_index: 0, success: true });

    let mut chunk_idx = 0;
    for chunk in test_data.chunks(CHUNK_SIZE) {
        controller.send_command(&RemoteCommand::WriteFileChunk {
            chunk_index: chunk_idx,
            data: chunk.to_vec(),
        }).await.unwrap();

        let chunk_ack = controller.recv_response().await.unwrap();
        assert_eq!(chunk_ack, CommandResponse::FileChunkAck { chunk_index: chunk_idx, success: true });
        chunk_idx += 1;
    }

    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_multiplexed_port_forwarding() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    // Internal service (e.g. echo server) simulating remote target port
    let internal_service = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_port = internal_service.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = internal_service.accept().await {
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 { break; }
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    let main_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let main_addr = main_listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    // Agent handler
    let agent_pub_for_acceptor = agent_pub.clone();
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = main_listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor).await.unwrap();
        let channel_id_expected = 101u32;
        // Expect OpenForwardChannel
        let open_cmd = framed.recv_command().await.unwrap();
        let target_stream = match open_cmd {
            RemoteCommand::OpenForwardChannel { channel_id, target_port } => {
                assert_eq!(channel_id, channel_id_expected);
                assert_eq!(target_port, internal_port);
                let target_stream = TcpStream::connect(format!("127.0.0.1:{}", target_port)).await.unwrap();
                framed.send_response(&CommandResponse::ForwardChannelAck { channel_id, opened: true }).await.unwrap();
                target_stream
            }
            _ => panic!("Expected OpenForwardChannel"),
        };

        let mut target = target_stream;
        let (mut target_reader, mut target_writer) = target.split();

        // Receive ForwardData
        let data_cmd = framed.recv_command().await.unwrap();
        match data_cmd {
            RemoteCommand::ForwardData { channel_id, data } => {
                assert_eq!(channel_id, channel_id_expected);
                target_writer.write_all(&data).await.unwrap();
            }
            _ => panic!("Expected ForwardData"),
        }

        // Read echo response from internal service
        let mut echo_buf = [0u8; 1024];
        let n = target_reader.read(&mut echo_buf).await.unwrap();
        framed.send_response(&CommandResponse::ForwardDataInbound {
            channel_id: channel_id_expected,
            data: echo_buf[..n].to_vec(),
        }).await.unwrap();

        // Close channel
        let close_cmd = framed.recv_command().await.unwrap();
        assert_eq!(close_cmd, RemoteCommand::CloseForwardChannel { channel_id: channel_id_expected });
    });

    // Controller connects
    let mut controller = NoiseFramedStream::connect_as_initiator(
        &main_addr.to_string(),
        &controller_priv,
        &agent_pub,
    ).await.unwrap();

    // Open channel 101 to internal port
    controller.send_command(&RemoteCommand::OpenForwardChannel {
        channel_id: 101,
        target_port: internal_port,
    }).await.unwrap();

    let ack = controller.recv_response().await.unwrap();
    assert_eq!(ack, CommandResponse::ForwardChannelAck { channel_id: 101, opened: true });

    // Send payload
    let test_payload = b"PING MULTIPLEXED TUNNEL";
    controller.send_command(&RemoteCommand::ForwardData {
        channel_id: 101,
        data: test_payload.to_vec(),
    }).await.unwrap();

    // Receive echo
    let resp = controller.recv_response().await.unwrap();
    match resp {
        CommandResponse::ForwardDataInbound { channel_id, data } => {
            assert_eq!(channel_id, 101);
            assert_eq!(data, test_payload);
        }
        _ => panic!("Unexpected response: {:?}", resp),
    }

    // Close channel
    controller.send_command(&RemoteCommand::CloseForwardChannel { channel_id: 101 }).await.unwrap();

    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_remote_port_forwarding() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    // 1. Controller local app (e.g. echo service on Controller)
    let controller_app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let controller_app_port = controller_app.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = controller_app.accept().await {
            let mut buf = [0u8; 1024];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 { break; }
                let _ = stream.write_all(&buf[..n]).await;
            }
        }
    });

    // 2. Main noise connection
    let main_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let main_addr = main_listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    // 3. Agent handler simulating Remote Forwarding
    let agent_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_bound_port = agent_listener.local_addr().unwrap().port();

    let agent_pub_for_acceptor = agent_pub.clone();
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = main_listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor).await.unwrap();

        // Expect StartRemoteForward
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::StartRemoteForward { bind_port, target_controller_port } => {
                assert_eq!(target_controller_port, controller_app_port);
                framed.send_response(&CommandResponse::RemoteForwardAck {
                    bind_port,
                    success: true,
                    message: "Listening OK".to_string(),
                }).await.unwrap();
            }
            _ => panic!("Expected StartRemoteForward"),
        }

        // Simulating client connecting to Agent's listener
        let (mut client_stream, _) = agent_listener.accept().await.unwrap();
        let channel_id = 999u32;

        framed.send_response(&CommandResponse::RemoteChannelOpened {
            channel_id,
            target_port: controller_app_port,
        }).await.unwrap();

        // Read from client and forward to Controller
        let mut client_buf = [0u8; 1024];
        let n = client_stream.read(&mut client_buf).await.unwrap();
        framed.send_response(&CommandResponse::ForwardDataInbound {
            channel_id,
            data: client_buf[..n].to_vec(),
        }).await.unwrap();

        // Receive response from Controller
        let fwd_cmd = framed.recv_command().await.unwrap();
        match fwd_cmd {
            RemoteCommand::ForwardData { channel_id: cid, data } => {
                assert_eq!(cid, channel_id);
                client_stream.write_all(&data).await.unwrap();
            }
            _ => panic!("Expected ForwardData"),
        }
    });

    // 4. Controller connection
    let mut controller = NoiseFramedStream::connect_as_initiator(
        &main_addr.to_string(),
        &controller_priv,
        &agent_pub,
    ).await.unwrap();

    // Request Agent to bind agent_bound_port
    controller.send_command(&RemoteCommand::StartRemoteForward {
        bind_port: agent_bound_port,
        target_controller_port: controller_app_port,
    }).await.unwrap();

    let ack = controller.recv_response().await.unwrap();
    match ack {
        CommandResponse::RemoteForwardAck { success, .. } => assert!(success),
        _ => panic!("Expected RemoteForwardAck"),
    }

    // 5. Simulate client at Agent sending data to agent_bound_port
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", agent_bound_port)).await.unwrap();
        client.write_all(b"PING REVERSE TUNNEL").await.unwrap();
        let mut resp_buf = [0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        assert_eq!(&resp_buf[..n], b"PING REVERSE TUNNEL");
    });

    // 6. Controller handles RemoteChannelOpened and bridges to controller_app
    let chan_msg = controller.recv_response().await.unwrap();
    let (channel_id, target_port) = match chan_msg {
        CommandResponse::RemoteChannelOpened { channel_id, target_port } => (channel_id, target_port),
        _ => panic!("Expected RemoteChannelOpened"),
    };
    assert_eq!(target_port, controller_app_port);

    // Controller connects to local app
    let mut local_app_stream = TcpStream::connect(format!("127.0.0.1:{}", target_port)).await.unwrap();

    // Receive data from Agent client
    let data_msg = controller.recv_response().await.unwrap();
    match data_msg {
        CommandResponse::ForwardDataInbound { channel_id: cid, data } => {
            assert_eq!(cid, channel_id);
            local_app_stream.write_all(&data).await.unwrap();
        }
        _ => panic!("Expected ForwardDataInbound"),
    }

    // Read echo from controller local app and send back to Agent
    let mut echo_buf = [0u8; 1024];
    let n = local_app_stream.read(&mut echo_buf).await.unwrap();
    controller.send_command(&RemoteCommand::ForwardData {
        channel_id,
        data: echo_buf[..n].to_vec(),
    }).await.unwrap();

    client_task.await.unwrap();
    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_ssh_style_tofu_discovery() {
    let agent_keypair = generate_keypair().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub).await;
    });

    let discovered = NoiseFramedStream::discover_remote_pubkey(&addr.to_string())
        .await
        .expect("Discovery failed");
    assert_eq!(discovered, agent_keypair.public);
}

#[tokio::test]
async fn test_download_file_transfer() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let fake_agent_file_content = vec![0x33u8; 100_000]; // 100 KB payload
    let fake_agent_file_content_clone = fake_agent_file_content.clone();
    let agent_pub_for_acceptor = agent_pub.clone();

    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor)
            .await
            .unwrap();

        // 1. Recv StartDownload
        let cmd = framed.recv_command().await.unwrap();
        let total_chunks = match cmd {
            RemoteCommand::StartDownload { filepath } => {
                assert_eq!(filepath, "dummy.txt");
                const CHUNK_SIZE: usize = 32 * 1024;
                let chunks = ((fake_agent_file_content_clone.len() + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
                framed.send_response(&CommandResponse::DownloadHeader {
                    filename: "dummy.txt".into(),
                    total_chunks: chunks,
                    file_size: fake_agent_file_content_clone.len() as u64,
                }).await.unwrap();
                chunks
            }
            _ => panic!("Expected StartDownload"),
        };

        // 2. Respond to chunks
        for _ in 0..total_chunks {
            match framed.recv_command().await {
                Ok(RemoteCommand::RequestDownloadChunk { chunk_index }) => {
                    const CHUNK_SIZE: usize = 32 * 1024;
                    let start = (chunk_index as usize) * CHUNK_SIZE;
                    let end = std::cmp::min(start + CHUNK_SIZE, fake_agent_file_content_clone.len());
                    let slice = fake_agent_file_content_clone[start..end].to_vec();
                    framed.send_response(&CommandResponse::DownloadChunk {
                        chunk_index,
                        data: slice,
                    }).await.unwrap();
                }
                other => panic!("Expected RequestDownloadChunk, got {:?}", other),
            }
        }
    });

    let mut controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    )
    .await
    .unwrap();

    controller.send_command(&RemoteCommand::StartDownload {
        filepath: "dummy.txt".into(),
    }).await.unwrap();

    let header = controller.recv_response().await.unwrap();
    let total_chunks = match header {
        CommandResponse::DownloadHeader { total_chunks, file_size, .. } => {
            assert_eq!(file_size, 100_000);
            total_chunks
        }
        _ => panic!("Expected DownloadHeader"),
    };

    let mut downloaded_bytes = Vec::new();
    for idx in 0..total_chunks {
        controller.send_command(&RemoteCommand::RequestDownloadChunk { chunk_index: idx }).await.unwrap();
        match controller.recv_response().await.unwrap() {
            CommandResponse::DownloadChunk { chunk_index, data } => {
                assert_eq!(chunk_index, idx);
                downloaded_bytes.extend_from_slice(&data);
            }
            _ => panic!("Expected DownloadChunk"),
        }
    }

    assert_eq!(downloaded_bytes, fake_agent_file_content);
    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_pairing_token_authentication() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let expected_token = "secret-token-123";

    let agent_pub_for_agent = agent_pub.clone();
    // Agent side simulating auth challenge
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_agent).await.unwrap();

        // 1. Send challenge
        framed.send_response(&CommandResponse::AuthChallenge).await.unwrap();

        // 2. Expect Authenticate command
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::Authenticate { token, nickname } => {
                assert_eq!(nickname.as_deref(), Some("test-admin@laptop"));
                if token == expected_token {
                    framed.send_response(&CommandResponse::AuthSuccess).await.unwrap();
                } else {
                    framed.send_response(&CommandResponse::AuthFailed("Invalid token".into())).await.unwrap();
                }
            }
            _ => panic!("Expected Authenticate command"),
        }

        // 3. Normal command after auth
        let next_cmd = framed.recv_command().await.unwrap();
        assert_eq!(next_cmd, RemoteCommand::GetSystemStats);
        framed.send_response(&CommandResponse::SystemStats { cpu_usage: 5.0, ram_used_mb: 1000 }).await.unwrap();
    });

    // Controller side
    let mut controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    ).await.unwrap();

    let challenge = controller.recv_response().await.unwrap();
    assert_eq!(challenge, CommandResponse::AuthChallenge);

    // Send correct token with nickname
    controller.send_command(&RemoteCommand::Authenticate {
        token: expected_token.into(),
        nickname: Some("test-admin@laptop".into()),
    }).await.unwrap();
    let auth_ack = controller.recv_response().await.unwrap();
    assert_eq!(auth_ack, CommandResponse::AuthSuccess);

    // Subsequent command works
    controller.send_command(&RemoteCommand::GetSystemStats).await.unwrap();
    let stats = controller.recv_response().await.unwrap();
    match stats {
        CommandResponse::SystemStats { cpu_usage, ram_used_mb } => {
            assert_eq!(cpu_usage, 5.0);
            assert_eq!(ram_used_mb, 1000);
        }
        _ => panic!("Expected SystemStats"),
    }

    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_filesystem_remote_commands() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let temp_dir = std::env::temp_dir().join(format!("p_fs_test_{}", rand::random::<u32>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let temp_dir_clone = temp_dir.clone();

    let agent_pub_for_acceptor = agent_pub.clone();
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor).await.unwrap();

        // 1. Write file
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsWriteFile { path, data, truncate: _ } => {
                let file_path = temp_dir_clone.join(path);
                std::fs::write(&file_path, data).unwrap();
                framed.send_response(&CommandResponse::FsOpResult { success: true, error: None }).await.unwrap();
            }
            _ => panic!("Expected FsWriteFile"),
        }

        // 2. Read file
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsReadFile { path, offset, length } => {
                let file_path = temp_dir_clone.join(path);
                let content = std::fs::read(&file_path).unwrap();
                let slice = content[offset as usize..(offset as usize + length as usize).min(content.len())].to_vec();
                framed.send_response(&CommandResponse::FsReadResult { data: slice, error: None }).await.unwrap();
            }
            _ => panic!("Expected FsReadFile"),
        }

        // 3. Stat file
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsStat { path } => {
                let file_path = temp_dir_clone.join(&path);
                let meta = std::fs::metadata(&file_path).unwrap();
                let entry = p::protocol::FsEntry {
                    name: path,
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                    modified_timestamp: 12345678,
                };
                framed.send_response(&CommandResponse::FsStatResult { entry: Some(entry), error: None }).await.unwrap();
            }
            _ => panic!("Expected FsStat"),
        }

        // 4. Delete file
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsDelete { path } => {
                let file_path = temp_dir_clone.join(path);
                let _ = std::fs::remove_file(file_path);
                framed.send_response(&CommandResponse::FsOpResult { success: true, error: None }).await.unwrap();
            }
            _ => panic!("Expected FsDelete"),
        }
    });

    let mut controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    ).await.unwrap();

    // 1. Write file
    let test_data = b"Hello from remote filesystem integration test!".to_vec();
    controller.send_command(&RemoteCommand::FsWriteFile {
        path: "test.txt".into(),
        data: test_data.clone(),
        truncate: true,
    }).await.unwrap();

    let res = controller.recv_response().await.unwrap();
    assert_eq!(res, CommandResponse::FsOpResult { success: true, error: None });

    // 2. Read file back
    controller.send_command(&RemoteCommand::FsReadFile {
        path: "test.txt".into(),
        offset: 0,
        length: 1024,
    }).await.unwrap();

    let read_res = controller.recv_response().await.unwrap();
    match read_res {
        CommandResponse::FsReadResult { data, error: None } => {
            assert_eq!(data, test_data);
        }
        other => panic!("Expected FsReadResult, got {:?}", other),
    }

    // 3. Stat file
    controller.send_command(&RemoteCommand::FsStat {
        path: "test.txt".into(),
    }).await.unwrap();

    let stat_res = controller.recv_response().await.unwrap();
    match stat_res {
        CommandResponse::FsStatResult { entry: Some(e), .. } => {
            assert_eq!(e.name, "test.txt");
            assert_eq!(e.size, test_data.len() as u64);
            assert!(!e.is_dir);
        }
        other => panic!("Expected FsStatResult, got {:?}", other),
    }

    // 4. Delete file
    controller.send_command(&RemoteCommand::FsDelete {
        path: "test.txt".into(),
    }).await.unwrap();

    let del_res = controller.recv_response().await.unwrap();
    assert_eq!(del_res, CommandResponse::FsOpResult { success: true, error: None });

    let _ = std::fs::remove_dir_all(&temp_dir);
    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_webdav_server_http_methods() {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    let agent_pub_for_acceptor = agent_pub.clone();
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv, &agent_pub_for_acceptor).await.unwrap();

        // 1. Responds to PROPFIND's FsStat
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsStat { path: _ } => {
                let entry = p::protocol::FsEntry {
                    name: "hello.txt".into(),
                    is_dir: false,
                    size: 13,
                    modified_timestamp: 1773000000,
                };
                framed.send_response(&CommandResponse::FsStatResult { entry: Some(entry), error: None }).await.unwrap();
            }
            _ => panic!("Expected FsStat"),
        }

        // 2. Responds to GET's FsStat and FsReadFile
        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsStat { path: _ } => {
                let entry = p::protocol::FsEntry {
                    name: "hello.txt".into(),
                    is_dir: false,
                    size: 13,
                    modified_timestamp: 1773000000,
                };
                framed.send_response(&CommandResponse::FsStatResult { entry: Some(entry), error: None }).await.unwrap();
            }
            _ => panic!("Expected FsStat"),
        }

        let cmd = framed.recv_command().await.unwrap();
        match cmd {
            RemoteCommand::FsReadFile { path: _, offset: _, length: _ } => {
                framed.send_response(&CommandResponse::FsReadResult {
                    data: b"Hello, WebDAV".to_vec(),
                    error: None,
                }).await.unwrap();
            }
            _ => panic!("Expected FsReadFile"),
        }
    });

    let controller = NoiseFramedStream::connect_as_initiator(
        &addr.to_string(),
        &controller_priv,
        &agent_pub,
    ).await.unwrap();

    let controller_arc = Arc::new(Mutex::new(controller));
    let (_webdav, webdav_port) = p::webdav::WebDavServer::start(controller_arc.clone(), 0).await.unwrap();

    // 1. Test OPTIONS HTTP
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", webdav_port)).await.unwrap();
    client.write_all(b"OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await.unwrap();
    let mut resp = vec![0u8; 1024];
    let n = client.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("200 OK"));
    assert!(resp_str.contains("DAV: 1, 2"));

    // 2. Test PROPFIND HTTP
    let mut client2 = TcpStream::connect(format!("127.0.0.1:{}", webdav_port)).await.unwrap();
    client2.write_all(b"PROPFIND /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nDepth: 0\r\n\r\n").await.unwrap();
    let mut resp2 = vec![0u8; 2048];
    let n2 = client2.read(&mut resp2).await.unwrap();
    let resp_str2 = String::from_utf8_lossy(&resp2[..n2]);
    assert!(resp_str2.contains("207 Multi-Status"));
    assert!(resp_str2.contains("hello.txt"));

    // 3. Test GET HTTP
    let mut client3 = TcpStream::connect(format!("127.0.0.1:{}", webdav_port)).await.unwrap();
    client3.write_all(b"GET /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await.unwrap();
    let mut resp3 = Vec::new();
    client3.read_to_end(&mut resp3).await.unwrap();
    let resp_str3 = String::from_utf8_lossy(&resp3);
    assert!(resp_str3.contains("200 OK"));
    assert!(resp_str3.contains("Hello, WebDAV"));

    agent_handle.await.unwrap();
}

#[tokio::test]
async fn test_reverse_connection_handshake() {
    let agent_keypair = generate_keypair().unwrap();
    let controller_keypair = generate_keypair().unwrap();

    // 1. Controller is in listen mode (Reverse Controller)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let controller_addr = listener.local_addr().unwrap();

    let agent_priv = agent_keypair.private.clone();
    let agent_pub = agent_keypair.public.clone();
    let controller_priv = controller_keypair.private.clone();

    // 2. Spawn Controller acceptor
    let controller_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut controller_framed = NoiseFramedStream::handshake_as_initiator(
            stream,
            &controller_priv,
            &agent_pub,
        )
        .await
        .expect("Reverse Controller handshake failed");

        // Controller sends command
        controller_framed
            .send_command(&RemoteCommand::GetSystemStats)
            .await
            .unwrap();

        let resp = controller_framed.recv_response().await.unwrap();
        match resp {
            CommandResponse::SystemStats { cpu_usage, ram_used_mb } => {
                assert_eq!(cpu_usage, 42.0);
                assert_eq!(ram_used_mb, 1024);
            }
            _ => panic!("Unexpected response"),
        }
    });

    // 3. Agent initiates outbound connection to Controller
    let agent_tcp = TcpStream::connect(controller_addr).await.unwrap();
    let mut agent_framed = NoiseFramedStream::accept_as_responder(
        agent_tcp,
        &agent_priv,
        &agent_keypair.public,
    )
    .await
    .expect("Reverse Agent handshake failed");

    let cmd = agent_framed.recv_command().await.unwrap();
    assert_eq!(cmd, RemoteCommand::GetSystemStats);

    agent_framed
        .send_response(&CommandResponse::SystemStats {
            cpu_usage: 42.0,
            ram_used_mb: 1024,
        })
        .await
        .unwrap();

    controller_handle.await.unwrap();
}


