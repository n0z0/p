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

    // Spawn Agent acceptor
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv)
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

    let agent_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv).await.unwrap();

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
    let agent_handle = tokio::spawn(async move {
        let (stream, _) = main_listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv).await.unwrap();
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

    let agent_handle = tokio::spawn(async move {
        let (stream, _) = main_listener.accept().await.unwrap();
        let mut framed = NoiseFramedStream::accept_as_responder(stream, &agent_priv).await.unwrap();

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
