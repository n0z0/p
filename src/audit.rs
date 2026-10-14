use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::info;

/// Format ISO 8601 UTC timestamp murni tanpa dependensi eksternal
pub fn current_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now();
    let dur = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let mut days = total_secs / 86400;
    let day_secs = total_secs % 86400;

    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;

    let mut year = 1970i64;
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

    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

/// Helper untuk escape karakter string agar valid dalam JSON NDJSON
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Konteks Client dan Sesi yang aktif untuk telemetri
#[derive(Clone, Debug)]
pub struct AuditSessionContext {
    pub session_id: String,
    pub remote_addr: String,
    pub local_addr: String,
    pub client_fingerprint: String,
    pub client_nickname: Option<String>,
}

impl AuditSessionContext {
    pub fn new(remote_addr: String, local_addr: String, client_fingerprint: String) -> Self {
        let rand_bytes: [u8; 8] = rand::random();
        let session_id = format!("sess-{}", hex::encode(rand_bytes));
        Self {
            session_id,
            remote_addr,
            local_addr,
            client_fingerprint,
            client_nickname: None,
        }
    }

    pub fn set_nickname(&mut self, nickname: Option<String>) {
        self.client_nickname = nickname;
    }
}

/// Audit Logger terpusat untuk SOC-grade CTI Telemetri
#[derive(Clone)]
pub struct AuditLogger {
    log_path: Option<PathBuf>,
    file_lock: Arc<Mutex<()>>,
}

impl AuditLogger {
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self {
            log_path,
            file_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Lokasi default file audit log: ~/.p/audit.log
    pub fn default_log_path() -> PathBuf {
        let dir = crate::crypto::get_config_dir();
        let _ = std::fs::create_dir_all(&dir);
        dir.join("audit.log")
    }

    /// Tulis satu event NDJSON ke file log mentah
    pub async fn log_event(
        &self,
        event_type: &str,
        severity: &str,
        ctx: &AuditSessionContext,
        action_json_fields: &str,
    ) {
        let timestamp = current_iso8601();
        let nickname_escaped = ctx
            .client_nickname
            .as_deref()
            .map(|n| format!("\"{}\"", escape_json(n)))
            .unwrap_or_else(|| "null".to_string());

        let line = format!(
            "{{\"timestamp\":\"{}\",\"event_type\":\"{}\",\"severity\":\"{}\",\"session_id\":\"{}\",\"client\":{{\"fingerprint\":\"{}\",\"nickname\":{},\"remote_ip\":\"{}\"}},\"server\":{{\"local_addr\":\"{}\"}},\"action\":{{{}}}}}\n",
            timestamp,
            escape_json(event_type),
            escape_json(severity),
            escape_json(&ctx.session_id),
            escape_json(&ctx.client_fingerprint),
            nickname_escaped,
            escape_json(&ctx.remote_addr),
            escape_json(&ctx.local_addr),
            action_json_fields
        );

        info!(target: "audit", "[AUDIT] {} - {} from {}", event_type, ctx.client_fingerprint, ctx.remote_addr);

        if let Some(ref path) = self.log_path {
            let _guard = self.file_lock.lock().await;
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                let _ = file.write_all(line.as_bytes()).await;
            }
        }
    }

    // Helper method untuk event-event spesifik CTI:

    pub async fn log_auth_attempt(
        &self,
        ctx: &AuditSessionContext,
        method: &str,
    ) {
        let fields = format!("\"status\":\"ATTEMPT\",\"auth_method\":\"{}\"", escape_json(method));
        self.log_event("AUTH_ATTEMPT", "INFO", ctx, &fields).await;
    }

    pub async fn log_auth_success(
        &self,
        ctx: &AuditSessionContext,
        method: &str,
        nickname: Option<&str>,
    ) {
        let nick_str = nickname.map(|n| format!("\"{}\"", escape_json(n))).unwrap_or_else(|| "null".to_string());
        let fields = format!(
            "\"status\":\"SUCCESS\",\"auth_method\":\"{}\",\"authorized_as\":{}",
            escape_json(method),
            nick_str
        );
        self.log_event("AUTH_SUCCESS", "NOTICE", ctx, &fields).await;
    }

    pub async fn log_auth_failed(
        &self,
        ctx: &AuditSessionContext,
        reason: &str,
    ) {
        let fields = format!(
            "\"status\":\"FAILED\",\"reason\":\"{}\"",
            escape_json(reason)
        );
        self.log_event("AUTH_FAILED", "WARNING", ctx, &fields).await;
    }

    pub async fn log_command_exec(
        &self,
        ctx: &AuditSessionContext,
        command: &str,
    ) {
        let fields = format!(
            "\"command\":\"{}\"",
            escape_json(command)
        );
        self.log_event("COMMAND_EXEC", "NOTICE", ctx, &fields).await;
    }

    pub async fn log_file_upload(
        &self,
        ctx: &AuditSessionContext,
        filename: &str,
        total_chunks: u32,
        status: &str,
    ) {
        let fields = format!(
            "\"file\":\"{}\",\"total_chunks\":{},\"status\":\"{}\"",
            escape_json(filename),
            total_chunks,
            escape_json(status)
        );
        self.log_event("FILE_UPLOAD", "NOTICE", ctx, &fields).await;
    }

    pub async fn log_file_download(
        &self,
        ctx: &AuditSessionContext,
        filepath: &str,
        size_bytes: u64,
        status: &str,
    ) {
        let fields = format!(
            "\"file\":\"{}\",\"size_bytes\":{},\"status\":\"{}\"",
            escape_json(filepath),
            size_bytes,
            escape_json(status)
        );
        self.log_event("FILE_DOWNLOAD", "NOTICE", ctx, &fields).await;
    }

    pub async fn log_port_forward_local(
        &self,
        ctx: &AuditSessionContext,
        channel_id: u32,
        target_port: u16,
    ) {
        let fields = format!(
            "\"type\":\"LOCAL_FORWARD\",\"channel_id\":{},\"target_port\":{}",
            channel_id, target_port
        );
        self.log_event("PORT_FORWARD", "NOTICE", ctx, &fields).await;
    }

    pub async fn log_port_forward_remote(
        &self,
        ctx: &AuditSessionContext,
        bind_port: u16,
        target_client_port: u16,
        status: &str,
    ) {
        let fields = format!(
            "\"type\":\"REMOTE_FORWARD\",\"bind_port\":{},\"target_client_port\":{},\"status\":\"{}\"",
            bind_port, target_client_port, escape_json(status)
        );
        self.log_event("PORT_FORWARD_REMOTE", "WARNING", ctx, &fields).await;
    }

    pub async fn log_rekey(
        &self,
        ctx: &AuditSessionContext,
    ) {
        self.log_event("SESSION_REKEY", "INFO", ctx, "\"action\":\"ROTATION_READY\"").await;
    }

    pub async fn log_shutdown(
        &self,
        ctx: &AuditSessionContext,
    ) {
        self.log_event("DEVICE_SHUTDOWN", "ALERT", ctx, "\"action\":\"SIGNAL_RECEIVED\"").await;
    }

    pub async fn log_fs_operation(
        &self,
        ctx: &AuditSessionContext,
        op_name: &str,
        path: &str,
        status: &str,
    ) {
        let fields = format!(
            "\"operation\":\"{}\",\"path\":\"{}\",\"status\":\"{}\"",
            escape_json(op_name),
            escape_json(path),
            escape_json(status)
        );
        self.log_event("WEBDAV_FS_ACCESS", "INFO", ctx, &fields).await;
    }

    pub async fn log_session_close(
        &self,
        ctx: &AuditSessionContext,
    ) {
        self.log_event("SESSION_CLOSE", "INFO", ctx, "\"status\":\"DISCONNECTED\"").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_iso8601_format() {
        let ts = current_iso8601();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.chars().nth(10), Some('T'));
        assert_eq!(ts.len(), 24); // e.g. 2026-10-14T11:45:00.123Z
    }

    #[test]
    fn test_escape_json() {
        let raw = "hello \"world\"\npath\\test\r\t";
        let escaped = escape_json(raw);
        assert_eq!(escaped, "hello \\\"world\\\"\\npath\\\\test\\r\\t");
    }

    #[tokio::test]
    async fn test_audit_logger_write() {
        let temp_dir = std::env::temp_dir().join(format!("p_audit_test_{}", rand::random::<u32>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("test_audit.log");

        let logger = AuditLogger::new(Some(log_file.clone()));
        let ctx = AuditSessionContext::new(
            "127.0.0.1:5544".to_string(),
            "0.0.0.0:9999".to_string(),
            "sha256:abc123def456".to_string(),
        );

        logger.log_command_exec(&ctx, "whoami").await;
        logger.log_file_download(&ctx, "/etc/passwd", 1234, "START").await;

        let content = std::fs::read_to_string(&log_file).unwrap();
        assert!(content.contains("\"event_type\":\"COMMAND_EXEC\""));
        assert!(content.contains("\"command\":\"whoami\""));
        assert!(content.contains("\"event_type\":\"FILE_DOWNLOAD\""));
        assert!(content.contains("\"file\":\"/etc/passwd\""));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
