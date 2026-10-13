use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::framed::NoiseFramedStream;
use crate::protocol::{CommandResponse, RemoteCommand};

pub struct WebDavServer {
    #[allow(dead_code)]
    stream: Arc<Mutex<NoiseFramedStream>>,
    port: u16,
}

impl WebDavServer {
    pub async fn start(stream: Arc<Mutex<NoiseFramedStream>>, preferred_port: u16) -> Result<(Self, u16)> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", preferred_port))
            .await
            .with_context(|| format!("Gagal bind WebDAV ke 127.0.0.1:{}", preferred_port))?;
        let actual_port = listener.local_addr()?.port();

        info!("📂 WebDAV Virtual Drive Server aktif di http://127.0.0.1:{}/", actual_port);

        let stream_clone = stream.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _peer)) => {
                        let stream_ref = stream_clone.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_http_client(socket, stream_ref).await {
                                warn!("WebDAV client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("WebDAV listener error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok((
            Self {
                stream,
                port: actual_port,
            },
            actual_port,
        ))
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

async fn handle_http_client(
    mut socket: TcpStream,
    noise_stream: Arc<Mutex<NoiseFramedStream>>,
) -> Result<()> {
    let mut header_buf = vec![0u8; 8192];
    let mut total_read = 0;

    // Baca HTTP Request Header
    let header_end_pos;
    loop {
        let n = socket.read(&mut header_buf[total_read..]).await?;
        if n == 0 {
            return Ok(());
        }
        total_read += n;

        if let Some(pos) = find_header_end(&header_buf[..total_read]) {
            header_end_pos = pos;
            break;
        }

        if total_read == header_buf.len() {
            bail!("HTTP header terlalu besar");
        }
    }

    let header_text = String::from_utf8_lossy(&header_buf[..header_end_pos]);
    let mut lines = header_text.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return Ok(()),
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_uppercase();
    let raw_path = parts[1];

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    let path = normalize_webdav_path(raw_path);
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // Baca sisa request body jika ada (misal untuk PUT)
    let body_already_read = total_read - (header_end_pos + 4);
    let mut body = Vec::with_capacity(content_length);
    if body_already_read > 0 {
        body.extend_from_slice(&header_buf[header_end_pos + 4..total_read]);
    }
    while body.len() < content_length {
        let mut chunk = vec![0u8; (content_length - body.len()).min(16384)];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    match method.as_str() {
        "OPTIONS" => {
            let response = "HTTP/1.1 200 OK\r\n\
                DAV: 1, 2\r\n\
                MS-Author-Via: DAV\r\n\
                Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }

        "PROPFIND" => {
            let depth = headers.get("depth").map(|s| s.as_str()).unwrap_or("1");
            let mut xml_entries = Vec::new();

            // 1. Stat path itu sendiri
            let self_stat = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsStat {
                        path: path.clone(),
                    })
                    .await?;
                guard.recv_response().await?
            };

            let self_is_dir = match self_stat {
                CommandResponse::FsStatResult {
                    entry: Some(entry), ..
                } => {
                    let display_name = if path.is_empty() { "/" } else { &entry.name };
                    let href = format_href(raw_path);
                    xml_entries.push(build_propfind_response(
                        &href,
                        display_name,
                        entry.is_dir,
                        entry.size,
                        entry.modified_timestamp,
                    ));
                    entry.is_dir
                }
                _ => {
                    if path.is_empty() {
                        // Root virtual fallback
                        let href = format_href(raw_path);
                        xml_entries.push(build_propfind_response(&href, "/", true, 0, 1773000000));
                        true
                    } else {
                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        socket.write_all(response.as_bytes()).await?;
                        return Ok(());
                    }
                }
            };

            // 2. Jika depth == 1 dan merupakan direktori, ambil daftar anak (children)
            if depth != "0" && self_is_dir {
                let list_res = {
                    let mut guard = noise_stream.lock().await;
                    guard
                        .send_command(&RemoteCommand::FsListDir {
                            path: path.clone(),
                        })
                        .await?;
                    guard.recv_response().await?
                };

                if let CommandResponse::FsListResult { entries, .. } = list_res {
                    let base_href = format_href(raw_path);
                    let base_trimmed = base_href.trim_end_matches('/');
                    for entry in entries {
                        let child_href = format!("{}/{}", base_trimmed, url_encode(&entry.name));
                        xml_entries.push(build_propfind_response(
                            &child_href,
                            &entry.name,
                            entry.is_dir,
                            entry.size,
                            entry.modified_timestamp,
                        ));
                    }
                }
            }

            let xml_body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                <D:multistatus xmlns:D=\"DAV:\">\n\
                {}\n\
                </D:multistatus>",
                xml_entries.join("\n")
            );

            let header = format!(
                "HTTP/1.1 207 Multi-Status\r\n\
                Content-Type: text/xml; charset=\"utf-8\"\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\r\n",
                xml_body.len()
            );

            socket.write_all(header.as_bytes()).await?;
            socket.write_all(xml_body.as_bytes()).await?;
        }

        "GET" => {
            let stat_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsStat {
                        path: path.clone(),
                    })
                    .await?;
                guard.recv_response().await?
            };

            let file_size = match stat_res {
                CommandResponse::FsStatResult {
                    entry: Some(entry), ..
                } => {
                    if entry.is_dir {
                        let response = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        socket.write_all(response.as_bytes()).await?;
                        return Ok(());
                    }
                    entry.size
                }
                _ => {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            };

            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                Content-Type: application/octet-stream\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\r\n",
                file_size
            );
            socket.write_all(header.as_bytes()).await?;

            // Stream isi file per chunk
            let mut offset = 0u64;
            while offset < file_size {
                let to_read = (file_size - offset).min(32768) as u32;
                let chunk_data = {
                    let mut guard = noise_stream.lock().await;
                    guard
                        .send_command(&RemoteCommand::FsReadFile {
                            path: path.clone(),
                            offset,
                            length: to_read,
                        })
                        .await?;
                    match guard.recv_response().await? {
                        CommandResponse::FsReadResult { data, error: None } => data,
                        _ => break,
                    }
                };

                if chunk_data.is_empty() {
                    break;
                }
                offset += chunk_data.len() as u64;
                socket.write_all(&chunk_data).await?;
            }
        }

        "HEAD" => {
            let stat_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsStat {
                        path: path.clone(),
                    })
                    .await?;
                guard.recv_response().await?
            };

            match stat_res {
                CommandResponse::FsStatResult {
                    entry: Some(entry), ..
                } => {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\n\
                        Content-Type: application/octet-stream\r\n\
                        Content-Length: {}\r\n\
                        Connection: close\r\n\r\n",
                        entry.size
                    );
                    socket.write_all(header.as_bytes()).await?;
                }
                _ => {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
            }
        }

        "PUT" => {
            let write_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsWriteFile {
                        path: path.clone(),
                        data: body,
                        truncate: true,
                    })
                    .await?;
                guard.recv_response().await?
            };

            match write_res {
                CommandResponse::FsOpResult {
                    success: true, ..
                } => {
                    let response = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
                _ => {
                    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
            }
        }

        "DELETE" => {
            let del_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsDelete {
                        path: path.clone(),
                    })
                    .await?;
                guard.recv_response().await?
            };

            match del_res {
                CommandResponse::FsOpResult {
                    success: true, ..
                } => {
                    let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
                _ => {
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
            }
        }

        "MKCOL" => {
            let mkdir_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsMkdir {
                        path: path.clone(),
                    })
                    .await?;
                guard.recv_response().await?
            };

            match mkdir_res {
                CommandResponse::FsOpResult {
                    success: true, ..
                } => {
                    let response = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
                _ => {
                    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
            }
        }

        "MOVE" => {
            let dest_header = headers.get("destination").cloned().unwrap_or_default();
            let dest_path = extract_path_from_uri(&dest_header);
            let normalized_dest = normalize_webdav_path(&dest_path);

            let move_res = {
                let mut guard = noise_stream.lock().await;
                guard
                    .send_command(&RemoteCommand::FsRename {
                        from: path.clone(),
                        to: normalized_dest,
                    })
                    .await?;
                guard.recv_response().await?
            };

            match move_res {
                CommandResponse::FsOpResult {
                    success: true, ..
                } => {
                    let response = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
                _ => {
                    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                }
            }
        }

        "LOCK" => {
            // Berikan token kunci dummy agar Windows Explorer mengizinkan manipulasi file
            let token_id = format!("opaquelocktoken:{:08x}-1111-2222-3333-444455556666", rand::random::<u32>());
            let xml_body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                <D:prop xmlns:D=\"DAV:\">\n\
                  <D:lockdiscovery>\n\
                    <D:activelock>\n\
                      <D:locktype><D:write/></D:locktype>\n\
                      <D:lockscope><D:exclusive/></D:lockscope>\n\
                      <D:depth>Infinity</D:depth>\n\
                      <D:timeout>Second-3600</D:timeout>\n\
                      <D:locktoken><D:href>{}</D:href></D:locktoken>\n\
                    </D:activelock>\n\
                  </D:lockdiscovery>\n\
                </D:prop>",
                token_id
            );

            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                Content-Type: text/xml; charset=\"utf-8\"\r\n\
                Lock-Token: <{}>\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\r\n",
                token_id,
                xml_body.len()
            );

            socket.write_all(header.as_bytes()).await?;
            socket.write_all(xml_body.as_bytes()).await?;
        }

        "UNLOCK" => {
            let response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }

        "PROPPATCH" => {
            let href = format_href(raw_path);
            let xml_body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                <D:multistatus xmlns:D=\"DAV:\">\n\
                  <D:response>\n\
                    <D:href>{}</D:href>\n\
                    <D:propstat>\n\
                      <D:status>HTTP/1.1 200 OK</D:status>\n\
                    </D:propstat>\n\
                  </D:response>\n\
                </D:multistatus>",
                href
            );

            let header = format!(
                "HTTP/1.1 207 Multi-Status\r\n\
                Content-Type: text/xml; charset=\"utf-8\"\r\n\
                Content-Length: {}\r\n\
                Connection: close\r\n\r\n",
                xml_body.len()
            );

            socket.write_all(header.as_bytes()).await?;
            socket.write_all(xml_body.as_bytes()).await?;
        }

        _ => {
            let response = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }
    }

    let _ = socket.flush().await;
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i);
        }
    }
    None
}

fn normalize_webdav_path(raw_path: &str) -> String {
    let decoded = url_decode(raw_path);
    let mut path = decoded.as_str();
    if let Some(pos) = path.find('?') {
        path = &path[..pos];
    }
    if path.starts_with("/DavWWWRoot") {
        path = &path[11..];
    } else if path.starts_with("DavWWWRoot") {
        path = &path[10..];
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn format_href(raw_path: &str) -> String {
    let mut path = raw_path;
    if let Some(pos) = path.find('?') {
        path = &path[..pos];
    }
    if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.to_string()
    }
}

fn extract_path_from_uri(uri: &str) -> String {
    if let Some(pos) = uri.find("://") {
        let after_scheme = &uri[pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            return after_scheme[slash_pos..].to_string();
        }
    }
    uri.to_string()
}

fn build_propfind_response(href: &str, display_name: &str, is_dir: bool, size: u64, ts: u64) -> String {
    let date_str = format_rfc1123(ts);
    let href_clean = if is_dir && !href.ends_with('/') {
        format!("{}/", href)
    } else {
        href.to_string()
    };

    if is_dir {
        format!(
            "  <D:response>\n\
               <D:href>{}</D:href>\n\
               <D:propstat>\n\
                 <D:prop>\n\
                   <D:displayname>{}</D:displayname>\n\
                   <D:resourcetype><D:collection/></D:resourcetype>\n\
                   <D:getlastmodified>{}</D:getlastmodified>\n\
                 </D:prop>\n\
                 <D:status>HTTP/1.1 200 OK</D:status>\n\
               </D:propstat>\n\
             </D:response>",
            xml_escape(&href_clean),
            xml_escape(display_name),
            date_str
        )
    } else {
        format!(
            "  <D:response>\n\
               <D:href>{}</D:href>\n\
               <D:propstat>\n\
                 <D:prop>\n\
                   <D:displayname>{}</D:displayname>\n\
                   <D:resourcetype/>\n\
                   <D:getcontentlength>{}</D:getcontentlength>\n\
                   <D:getlastmodified>{}</D:getlastmodified>\n\
                 </D:prop>\n\
                 <D:status>HTTP/1.1 200 OK</D:status>\n\
               </D:propstat>\n\
             </D:response>",
            xml_escape(&href_clean),
            xml_escape(display_name),
            size,
            date_str
        )
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn url_decode(s: &str) -> String {
    let mut res = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(h1), Some(h2)) = (h1, h2) {
                let hex_str = format!("{}{}", h1, h2);
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    res.push(byte as char);
                    continue;
                }
            }
        } else if c == '+' {
            res.push(' ');
        } else {
            res.push(c);
        }
    }
    res
}

fn url_encode(s: &str) -> String {
    let mut res = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            res.push(b as char);
        } else {
            res.push_str(&format!("%{:02X}", b));
        }
    }
    res
}

fn format_rfc1123(ts: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day_of_week = DAYS[((ts / 86400) % 7) as usize];
    let mut days = (ts / 86400) as i64;
    let sec = ts % 60;
    let min = (ts / 60) % 60;
    let hour = (ts / 3600) % 24;

    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        day_of_week,
        day,
        MONTHS[month.min(11)],
        year,
        hour,
        min,
        sec
    )
}

/// Helper untuk me-mount drive di Windows menggunakan net use
pub fn mount_windows_drive(drive_letter: &str, port: u16) -> Result<()> {
    let drive = drive_letter.trim().trim_end_matches(':');
    let drive_full = format!("{}:", drive);
    let url = format!("http://127.0.0.1:{}/", port);

    // Hapus dulu jika sebelumnya sudah ada drive yang tertinggal
    let _ = std::process::Command::new("net")
        .args(["use", &drive_full, "/delete", "/yes"])
        .output();

    let output = std::process::Command::new("net")
        .args(["use", &drive_full, &url, "/persistent:no"])
        .output()
        .with_context(|| format!("Gagal menjalankan perintah 'net use' untuk {}", drive_full))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let out = String::from_utf8_lossy(&output.stdout);
        bail!("Gagal mount drive {}: {} {}", drive_full, out.trim(), err.trim());
    }

    Ok(())
}

/// Helper untuk melepas mount drive di Windows
pub fn unmount_windows_drive(drive_letter: &str) -> Result<()> {
    let drive = drive_letter.trim().trim_end_matches(':');
    let drive_full = format!("{}:", drive);
    let output = std::process::Command::new("net")
        .args(["use", &drive_full, "/delete", "/yes"])
        .output()?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        warn!("Unmount warning: {}", err);
    }
    Ok(())
}
