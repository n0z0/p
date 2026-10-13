use std::process::Command;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// Menjalankan perintah terminal sesuai target OS (Windows vs Unix)
pub fn execute_os_command(cmd_string: &str) -> Result<String, String> {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", cmd_string]).output()
    } else {
        Command::new("sh").args(["-c", cmd_string]).output()
    };

    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).to_string())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if stderr.is_empty() {
                    Ok(String::from_utf8_lossy(&out.stdout).to_string())
                } else {
                    Err(stderr)
                }
            }
        }
        Err(e) => Err(format!("Gagal menjalankan perintah: {}", e)),
    }
}

/// Mendapatkan statistik sistem (penggunaan CPU dalam persen dan RAM terpakai dalam MB)
pub fn get_system_stats() -> (f32, u64) {
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::new().with_cpu_usage())
            .with_memory(MemoryRefreshKind::new().with_ram()),
    );
    // Tunggu sedikit jika perlu untuk pembacaan delta CPU
    std::thread::sleep(std::time::Duration::from_millis(150));
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpu_usage = sys.global_cpu_info().cpu_usage();
    let ram_used_mb = sys.used_memory() / (1024 * 1024);

    (cpu_usage, ram_used_mb)
}

/// Menjalankan shutdown perangkat sesuai OS
pub fn shutdown_system() -> Result<String, String> {
    if cfg!(target_os = "windows") {
        execute_os_command("shutdown /s /t 10")
    } else {
        execute_os_command("shutdown -h +1")
    }
}
