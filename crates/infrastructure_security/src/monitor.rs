use application::ports::SecurityMonitor;
use domain::security::{
    FileIntegrityStatus,
    FirewallStatus,
    SecuritySnapshot,
    ThreatStatus,
};
use netstat2::{
    get_sockets_info,
    AddressFamilyFlags,
    ProtocolFlags,
    ProtocolSocketInfo,
    TcpState,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const FILE_INTEGRITY_INTERVAL: Duration = Duration::from_secs(120);
const FIREWALL_INTERVAL: Duration = Duration::from_secs(30);
const HASH_BUFFER_SIZE: usize = 64 * 1024;

pub struct LocalSecurityMonitor {
    executable_path: Option<PathBuf>,
    baseline_path: PathBuf,
    baseline_hash: Option<[u8; 32]>,
    cached_integrity: FileIntegrityStatus,
    cached_firewall: FirewallStatus,
    last_integrity_check: Instant,
    last_firewall_check: Instant,
}

impl LocalSecurityMonitor {
    pub fn new() -> Self {
        let now = Instant::now();
        let baseline_path = integrity_baseline_path();
        let baseline_hash = load_integrity_baseline(&baseline_path);

        Self {
            executable_path: std::env::current_exe().ok(),
            baseline_path,
            baseline_hash,
            cached_integrity: FileIntegrityStatus::Unknown,
            cached_firewall: FirewallStatus::Unknown,
            last_integrity_check: now
                .checked_sub(FILE_INTEGRITY_INTERVAL)
                .unwrap_or(now),
            last_firewall_check: now.checked_sub(FIREWALL_INTERVAL).unwrap_or(now),
        }
    }

    fn refresh_integrity(&mut self) {
        if self.last_integrity_check.elapsed() < FILE_INTEGRITY_INTERVAL {
            return;
        }
        self.last_integrity_check = Instant::now();

        let Some(path) = self.executable_path.as_deref() else {
            self.cached_integrity = FileIntegrityStatus::Unknown;
            return;
        };

        if !path.exists() {
            self.cached_integrity = FileIntegrityStatus::Missing;
            return;
        }

        let Some(hash) = sha256_array(path) else {
            self.cached_integrity = FileIntegrityStatus::Unknown;
            return;
        };

        if let Some(persisted_baseline) = load_integrity_baseline(&self.baseline_path) {
            self.baseline_hash = Some(persisted_baseline);
        }

        match self.baseline_hash {
            None => {
                self.baseline_hash = Some(hash);

                if store_integrity_baseline(&self.baseline_path, &hash) {
                    self.cached_integrity = FileIntegrityStatus::BaselineCreated;
                } else {
                    self.cached_integrity = FileIntegrityStatus::Unknown;
                }
            }
            Some(baseline) if baseline == hash => {
                self.cached_integrity = FileIntegrityStatus::Intact;
            }
            Some(_) => {
                self.cached_integrity = FileIntegrityStatus::Changed;
            }
        }
    }

    fn refresh_firewall(&mut self) {
        if self.last_firewall_check.elapsed() < FIREWALL_INTERVAL {
            return;
        }
        self.last_firewall_check = Instant::now();
        self.cached_firewall = firewall_status();
    }
}

impl Default for LocalSecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityMonitor for LocalSecurityMonitor {
    fn snapshot(&mut self) -> SecuritySnapshot {
        self.refresh_integrity();
        self.refresh_firewall();

        let open_port_count = open_port_count();

        let mut warning_count = 0usize;
        if self.cached_firewall == FirewallStatus::Disabled {
            warning_count += 1;
        }
        if matches!(
            self.cached_integrity,
            FileIntegrityStatus::Changed | FileIntegrityStatus::Missing
        ) {
            warning_count += 1;
        }

        let threat_status = if matches!(
            self.cached_integrity,
            FileIntegrityStatus::Changed | FileIntegrityStatus::Missing
        ) {
            ThreatStatus::IntegrityWarning
        } else if self.cached_firewall == FirewallStatus::Disabled {
            ThreatStatus::ProtectionReduced
        } else if self.cached_firewall == FirewallStatus::Enabled {
            ThreatStatus::BasicProtectionActive
        } else {
            ThreatStatus::ProtectionReduced
        };

        SecuritySnapshot {
            open_port_count,
            firewall_status: self.cached_firewall,
            file_integrity_status: self.cached_integrity,
            warning_count,
            threat_status,
        }
    }
}

pub fn reset_integrity_baseline() -> bool {
    let Some(executable_path) = std::env::current_exe().ok() else {
        return false;
    };

    let Some(hash) = sha256_array(&executable_path) else {
        return false;
    };

    let path = integrity_baseline_path();
    store_integrity_baseline(&path, &hash)
}

fn integrity_baseline_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(base)
                .join("AegisGrid")
                .join("integrity_baseline.bin");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".aegisgrid")
                .join("integrity_baseline.bin");
        }
    }

    PathBuf::from("integrity_baseline.bin")
}

fn load_integrity_baseline(path: &Path) -> Option<[u8; 32]> {
    let bytes = fs::read(path).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let mut value = [0u8; 32];
    value.copy_from_slice(&bytes);
    Some(value)
}

fn store_integrity_baseline(path: &Path, hash: &[u8; 32]) -> bool {
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return false;
        }
    }

    let temporary = path.with_extension("tmp");
    if fs::write(&temporary, hash).is_err() {
        return false;
    }

    if fs::rename(&temporary, path).is_ok() {
        return true;
    }

    let _ = fs::remove_file(&temporary);
    false
}

fn sha256_array(path: &Path) -> Option<[u8; 32]> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Some(hasher.finalize().into())
}

fn open_port_count() -> usize {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let Ok(sockets) = get_sockets_info(af, proto) else {
        return 0;
    };

    use std::collections::HashSet;
    let mut unique = HashSet::new();

    for socket in sockets {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => {
                unique.insert((0u8, tcp.local_addr, tcp.local_port));
            }
            ProtocolSocketInfo::Udp(udp) => {
                unique.insert((1u8, udp.local_addr, udp.local_port));
            }
            _ => {}
        }
    }

    unique.len()
}

#[cfg(target_os = "macos")]
fn firewall_status() -> FirewallStatus {
    let Ok(output) = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .output()
    else {
        return FirewallStatus::Unknown;
    };

    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_lowercase();

    if text.contains("enabled") || text.contains("state = 1") {
        FirewallStatus::Enabled
    } else if text.contains("disabled") || text.contains("state = 0") {
        FirewallStatus::Disabled
    } else {
        FirewallStatus::Unknown
    }
}

#[cfg(target_os = "windows")]
fn firewall_status() -> FirewallStatus {
    let script = "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true}).Count";
    let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    else {
        return FirewallStatus::Unknown;
    };

    let count = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<usize>()
        .ok();

    match count {
        Some(value) if value > 0 => FirewallStatus::Enabled,
        Some(_) => FirewallStatus::Disabled,
        None => FirewallStatus::Unknown,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn firewall_status() -> FirewallStatus {
    FirewallStatus::Unknown
}
