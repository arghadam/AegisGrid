use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime},
};

use domain::security::{ProcessRiskAssessment, ProcessRiskLevel, ProcessRiskSignal};
use sha2::{Digest, Sha256};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const PROCESS_ANALYSIS_INTERVAL: Duration = Duration::from_secs(30);

const SIGNATURE_CACHE_DURATION: Duration = Duration::from_secs(300);

const SIGNATURE_METADATA_CACHE_DURATION: Duration = Duration::from_secs(300);

const FILE_HASH_CACHE_DURATION: Duration = Duration::from_secs(300);

const FILE_HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAnomalyReason {
    TemporaryDirectory,
    CacheDirectory,
    DownloadsDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeSignatureMetadata {
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    pub authorities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSignalDetail {
    pub signal: ProcessRiskSignal,
    pub score: u8,
}

impl ProcessSignalDetail {
    pub fn new(signal: ProcessRiskSignal) -> Self {
        Self {
            score: signal.score(),

            signal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSecurityDetail {
    pub pid: u32,
    pub name: String,
    pub executable_path: PathBuf,

    pub primary_reason: ProcessAnomalyReason,

    pub signature_status: CodeSignatureStatus,

    pub signature_metadata: CodeSignatureMetadata,

    pub sha256: Option<String>,

    pub risk_score: u8,
    pub risk_level: ProcessRiskLevel,

    pub signals: Vec<ProcessSignalDetail>,
}

impl ProcessSecurityDetail {
    pub fn signal_count(&self) -> usize {
        self.signals.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub executable_path: PathBuf,

    pub reason: ProcessAnomalyReason,

    pub signature_status: CodeSignatureStatus,

    pub signature_metadata: CodeSignatureMetadata,

    pub sha256: Option<String>,

    pub risk_score: u8,
    pub risk_level: ProcessRiskLevel,

    pub signals: Vec<ProcessRiskSignal>,
}

impl SuspiciousProcess {
    pub fn detail(&self) -> ProcessSecurityDetail {
        let signals = self
            .signals
            .iter()
            .copied()
            .map(ProcessSignalDetail::new)
            .collect();

        ProcessSecurityDetail {
            pid: self.pid,

            name: self.name.clone(),

            executable_path: self.executable_path.clone(),

            primary_reason: self.reason.clone(),

            signature_status: self.signature_status,

            signature_metadata: self.signature_metadata.clone(),

            sha256: self.sha256.clone(),

            risk_score: self.risk_score,

            risk_level: self.risk_level,

            signals,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessSecuritySnapshot {
    pub analyzed_process_count: usize,

    pub observed_processes: Vec<ProcessRiskAssessment>,

    pub suspicious_processes: Vec<SuspiciousProcess>,
}

impl ProcessSecuritySnapshot {
    pub fn suspicious_count(&self) -> usize {
        self.suspicious_processes.len()
    }

    pub fn observed_count(&self) -> usize {
        self.observed_processes.len()
    }

    pub fn review_recommended_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.risk_level == ProcessRiskLevel::ReviewRecommended)
            .count()
    }

    pub fn high_anomaly_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.risk_level == ProcessRiskLevel::HighAnomaly)
            .count()
    }

    pub fn highest_risk_score(&self) -> u8 {
        self.observed_processes
            .iter()
            .map(|assessment| assessment.score)
            .max()
            .unwrap_or(0)
    }

    pub fn highest_risk_level(&self) -> ProcessRiskLevel {
        self.observed_processes
            .iter()
            .map(|assessment| assessment.level)
            .max_by_key(|level| risk_level_priority(*level))
            .unwrap_or(ProcessRiskLevel::Safe)
    }

    pub fn signature_valid_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.signature_status == CodeSignatureStatus::Valid)
            .count()
    }

    pub fn signature_unsigned_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.signature_status == CodeSignatureStatus::Unsigned)
            .count()
    }

    pub fn signature_invalid_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.signature_status == CodeSignatureStatus::Invalid)
            .count()
    }

    pub fn signature_unknown_count(&self) -> usize {
        self.suspicious_processes
            .iter()
            .filter(|process| process.signature_status == CodeSignatureStatus::Unknown)
            .count()
    }

    pub fn process_detail(&self, pid: u32) -> Option<ProcessSecurityDetail> {
        self.suspicious_processes
            .iter()
            .find(|process| process.pid == pid)
            .map(SuspiciousProcess::detail)
    }

    pub fn highest_risk_process_detail(&self) -> Option<ProcessSecurityDetail> {
        self.suspicious_processes
            .first()
            .map(SuspiciousProcess::detail)
    }

    pub fn review_process_details(&self) -> Vec<ProcessSecurityDetail> {
        self.suspicious_processes
            .iter()
            .map(SuspiciousProcess::detail)
            .collect()
    }
}

#[derive(Debug, Clone)]
struct CachedSignature {
    status: CodeSignatureStatus,
    checked_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedSignatureMetadata {
    metadata: CodeSignatureMetadata,
    checked_at: Instant,
}

#[derive(Debug, Clone)]
struct CachedFileHash {
    sha256: String,
    file_size: u64,
    modified: Option<SystemTime>,
    checked_at: Instant,
}

pub struct ProcessSecurityAnalyzer {
    system: System,

    last_analysis: Instant,

    cached_snapshot: ProcessSecuritySnapshot,

    signature_cache: HashMap<PathBuf, CachedSignature>,

    signature_metadata_cache: HashMap<PathBuf, CachedSignatureMetadata>,

    file_hash_cache: HashMap<PathBuf, CachedFileHash>,

    own_pid: u32,
}

impl ProcessSecurityAnalyzer {
    pub fn new() -> Self {
        let now = Instant::now();

        Self {
            system: System::new(),

            last_analysis: now.checked_sub(PROCESS_ANALYSIS_INTERVAL).unwrap_or(now),

            cached_snapshot: ProcessSecuritySnapshot::default(),

            signature_cache: HashMap::new(),

            signature_metadata_cache: HashMap::new(),

            file_hash_cache: HashMap::new(),

            own_pid: std::process::id(),
        }
    }

    pub fn snapshot(&mut self) -> ProcessSecuritySnapshot {
        if self.last_analysis.elapsed() < PROCESS_ANALYSIS_INTERVAL {
            return self.cached_snapshot.clone();
        }

        self.last_analysis = Instant::now();

        self.cleanup_signature_cache();
        self.cleanup_signature_metadata_cache();
        self.cleanup_file_hash_cache();

        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
        );

        let mut candidates = Vec::<(u32, String, PathBuf, Vec<ProcessRiskSignal>)>::new();

        let mut analyzed_process_count = 0_usize;

        for (pid, process) in self.system.processes() {
            let pid_value = pid.as_u32();

            if pid_value == self.own_pid {
                continue;
            }

            analyzed_process_count = analyzed_process_count.saturating_add(1);

            let Some(executable_path) = process.exe().map(Path::to_path_buf) else {
                continue;
            };

            let path_signals = collect_path_signals(&executable_path);

            if path_signals.is_empty() {
                continue;
            }

            let name = process.name().to_string_lossy().into_owned();

            candidates.push((pid_value, name, executable_path, path_signals));
        }

        let mut observed_processes = Vec::new();

        let mut suspicious_processes = Vec::new();

        for (pid, name, executable_path, mut signals) in candidates {
            add_unusual_permissions_signal(&executable_path, &mut signals);

            let signature_status = self.signature_status(&executable_path);

            add_signature_signal(signature_status, &mut signals);

            let assessment = ProcessRiskAssessment::new(pid, name.clone(), signals.clone());

            observed_processes.push(assessment.clone());

            if !assessment.requires_attention() {
                continue;
            }

            let Some(reason) = primary_anomaly_reason(&signals) else {
                continue;
            };

            let signature_metadata = self.signature_metadata(&executable_path);

            let sha256 = self.file_sha256(&executable_path);

            suspicious_processes.push(SuspiciousProcess {
                pid,

                name,

                executable_path,

                reason,

                signature_status,

                signature_metadata,

                sha256,

                risk_score: assessment.score,

                risk_level: assessment.level,

                signals,
            });
        }

        suspicious_processes.sort_by_key(|process| std::cmp::Reverse(process.risk_score));

        observed_processes.sort_by_key(|process| std::cmp::Reverse(process.score));

        self.cached_snapshot = ProcessSecuritySnapshot {
            analyzed_process_count,

            observed_processes,

            suspicious_processes,
        };

        self.cached_snapshot.clone()
    }

    fn signature_status(&mut self, path: &Path) -> CodeSignatureStatus {
        if let Some(cached) = self.signature_cache.get(path)
            && cached.checked_at.elapsed() < SIGNATURE_CACHE_DURATION
        {
            return cached.status;
        }

        let status = check_code_signature(path);

        self.signature_cache.insert(
            path.to_path_buf(),
            CachedSignature {
                status,

                checked_at: Instant::now(),
            },
        );

        status
    }

    fn signature_metadata(&mut self, path: &Path) -> CodeSignatureMetadata {
        if let Some(cached) = self.signature_metadata_cache.get(path)
            && cached.checked_at.elapsed() < SIGNATURE_METADATA_CACHE_DURATION
        {
            return cached.metadata.clone();
        }

        let metadata = read_code_signature_metadata(path);

        self.signature_metadata_cache.insert(
            path.to_path_buf(),
            CachedSignatureMetadata {
                metadata: metadata.clone(),

                checked_at: Instant::now(),
            },
        );

        metadata
    }

    fn file_sha256(&mut self, path: &Path) -> Option<String> {
        let metadata = fs::metadata(path).ok()?;

        if !metadata.is_file() {
            return None;
        }

        let file_size = metadata.len();

        let modified = metadata.modified().ok();

        if let Some(cached) = self.file_hash_cache.get(path) {
            let cache_valid = cached.checked_at.elapsed() < FILE_HASH_CACHE_DURATION
                && cached.file_size == file_size
                && cached.modified == modified;

            if cache_valid {
                return Some(cached.sha256.clone());
            }
        }

        let sha256 = calculate_file_sha256(path)?;

        self.file_hash_cache.insert(
            path.to_path_buf(),
            CachedFileHash {
                sha256: sha256.clone(),

                file_size,

                modified,

                checked_at: Instant::now(),
            },
        );

        Some(sha256)
    }

    fn cleanup_signature_cache(&mut self) {
        self.signature_cache.retain(|path, entry| {
            entry.checked_at.elapsed() < SIGNATURE_CACHE_DURATION && path.exists()
        });
    }

    fn cleanup_signature_metadata_cache(&mut self) {
        self.signature_metadata_cache.retain(|path, entry| {
            entry.checked_at.elapsed() < SIGNATURE_METADATA_CACHE_DURATION && path.exists()
        });
    }

    fn cleanup_file_hash_cache(&mut self) {
        self.file_hash_cache.retain(|path, entry| {
            entry.checked_at.elapsed() < FILE_HASH_CACHE_DURATION && path.exists()
        });
    }
}

impl Default for ProcessSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn calculate_file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;

    let mut hasher = Sha256::new();

    let mut buffer = vec![0_u8; FILE_HASH_BUFFER_SIZE];

    loop {
        let read = file.read(&mut buffer).ok()?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
    }

    Some(format!("{:x}", hasher.finalize(),))
}

fn collect_path_signals(path: &Path) -> Vec<ProcessRiskSignal> {
    let normalized = path.to_string_lossy().to_lowercase();

    let mut signals = Vec::with_capacity(5);

    if normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.contains("\\appdata\\local\\temp\\")
    {
        signals.push(ProcessRiskSignal::TemporaryDirectory);
    }

    if normalized.contains("/library/caches/") || normalized.contains("\\appdata\\local\\cache\\") {
        signals.push(ProcessRiskSignal::CacheDirectory);
    }

    if normalized.contains("/downloads/") || normalized.contains("\\downloads\\") {
        signals.push(ProcessRiskSignal::DownloadsDirectory);
    }

    signals
}

fn add_unusual_permissions_signal(path: &Path, signals: &mut Vec<ProcessRiskSignal>) {
    if has_unusual_permissions(path) {
        signals.push(ProcessRiskSignal::UnusualPermissions);
    }
}

#[cfg(unix)]
fn has_unusual_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    if !metadata.is_file() {
        return false;
    }

    let mode = metadata.permissions().mode();

    let world_writable = mode & 0o002 != 0;

    let set_user_id = mode & 0o4000 != 0;

    let set_group_id = mode & 0o2000 != 0;

    world_writable || set_user_id || set_group_id
}

#[cfg(not(unix))]
fn has_unusual_permissions(_path: &Path) -> bool {
    false
}

fn add_signature_signal(status: CodeSignatureStatus, signals: &mut Vec<ProcessRiskSignal>) {
    match status {
        CodeSignatureStatus::Unsigned => {
            signals.push(ProcessRiskSignal::UnsignedExecutable);
        }

        CodeSignatureStatus::Invalid => {
            signals.push(ProcessRiskSignal::InvalidSignature);
        }

        CodeSignatureStatus::Valid | CodeSignatureStatus::Unknown => {}
    }
}

#[cfg(target_os = "macos")]
fn check_code_signature(path: &Path) -> CodeSignatureStatus {
    let verification = Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg("--strict")
        .arg("--verbose=2")
        .arg(path)
        .output();

    let Ok(output) = verification else {
        return CodeSignatureStatus::Unknown;
    };

    if output.status.success() {
        return CodeSignatureStatus::Valid;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();

    if stderr.contains("code object is not signed") || stderr.contains("not signed at all") {
        return CodeSignatureStatus::Unsigned;
    }

    if stderr.contains("invalid")
        || stderr.contains("modified")
        || stderr.contains("resource envelope")
        || stderr.contains("sealed resource")
    {
        return CodeSignatureStatus::Invalid;
    }

    CodeSignatureStatus::Unknown
}

#[cfg(target_os = "windows")]
fn check_code_signature(path: &Path) -> CodeSignatureStatus {
    let escaped = path.to_string_lossy().replace('\'', "''");

    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{}'; Write-Output $s.Status",
        escaped,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();

    let Ok(output) = output else {
        return CodeSignatureStatus::Unknown;
    };

    match String::from_utf8_lossy(&output.stdout).trim() {
        "Valid" => CodeSignatureStatus::Valid,
        "NotSigned" => CodeSignatureStatus::Unsigned,
        "HashMismatch" | "NotTrusted" | "UnknownError" => CodeSignatureStatus::Invalid,
        _ => CodeSignatureStatus::Unknown,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn check_code_signature(_path: &Path) -> CodeSignatureStatus {
    CodeSignatureStatus::Unknown
}

#[cfg(target_os = "macos")]
fn read_code_signature_metadata(path: &Path) -> CodeSignatureMetadata {
    let output = Command::new("/usr/bin/codesign")
        .arg("-d")
        .arg("--verbose=4")
        .arg(path)
        .output();

    let Ok(output) = output else {
        return CodeSignatureMetadata::default();
    };

    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.stdout.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }

        text.push_str(&String::from_utf8_lossy(&output.stdout));
    }

    parse_code_signature_metadata(&text)
}

#[cfg(target_os = "windows")]
fn read_code_signature_metadata(path: &Path) -> CodeSignatureMetadata {
    let escaped = path.to_string_lossy().replace('\'', "''");

    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{}'; if ($null -ne $s.SignerCertificate) {{ Write-Output ('Authority=' + $s.SignerCertificate.Subject); Write-Output ('Authority=Thumbprint ' + $s.SignerCertificate.Thumbprint) }}",
        escaped,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();

    let Ok(output) = output else {
        return CodeSignatureMetadata::default();
    };

    let mut metadata = parse_code_signature_metadata(&String::from_utf8_lossy(&output.stdout));

    metadata.identifier = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());

    metadata
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn read_code_signature_metadata(_path: &Path) -> CodeSignatureMetadata {
    CodeSignatureMetadata::default()
}

fn parse_code_signature_metadata(output: &str) -> CodeSignatureMetadata {
    let mut metadata = CodeSignatureMetadata::default();

    for raw_line in output.lines() {
        let line = raw_line.trim();

        if let Some(value) = line.strip_prefix("Identifier=") {
            let value = value.trim();

            if !value.is_empty() {
                metadata.identifier = Some(value.to_owned());
            }

            continue;
        }

        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            let value = value.trim();

            if !value.is_empty() && !value.eq_ignore_ascii_case("not set") {
                metadata.team_identifier = Some(value.to_owned());
            }

            continue;
        }

        if let Some(value) = line.strip_prefix("Authority=") {
            let value = value.trim();

            if value.is_empty() {
                continue;
            }

            if !metadata
                .authorities
                .iter()
                .any(|authority| authority == value)
            {
                metadata.authorities.push(value.to_owned());
            }
        }
    }

    metadata
}

fn primary_anomaly_reason(signals: &[ProcessRiskSignal]) -> Option<ProcessAnomalyReason> {
    if signals.contains(&ProcessRiskSignal::TemporaryDirectory) {
        return Some(ProcessAnomalyReason::TemporaryDirectory);
    }

    if signals.contains(&ProcessRiskSignal::DownloadsDirectory) {
        return Some(ProcessAnomalyReason::DownloadsDirectory);
    }

    if signals.contains(&ProcessRiskSignal::CacheDirectory) {
        return Some(ProcessAnomalyReason::CacheDirectory);
    }

    None
}

fn risk_level_priority(level: ProcessRiskLevel) -> u8 {
    match level {
        ProcessRiskLevel::Safe => 0,

        ProcessRiskLevel::Observe => 1,

        ProcessRiskLevel::ReviewRecommended => 2,

        ProcessRiskLevel::HighAnomaly => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CodeSignatureMetadata, CodeSignatureStatus, ProcessAnomalyReason, ProcessSecurityAnalyzer,
        ProcessSecuritySnapshot, SuspiciousProcess, calculate_file_sha256,
        parse_code_signature_metadata,
    };
    use domain::security::{ProcessRiskAssessment, ProcessRiskLevel, ProcessRiskSignal};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use super::add_unusual_permissions_signal;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn test_snapshot() -> ProcessSecuritySnapshot {
        ProcessSecuritySnapshot {
            analyzed_process_count: 500,

            observed_processes: vec![
                ProcessRiskAssessment::new(
                    1,
                    "observe",
                    vec![ProcessRiskSignal::TemporaryDirectory],
                ),
                ProcessRiskAssessment::new(
                    2,
                    "review",
                    vec![
                        ProcessRiskSignal::TemporaryDirectory,
                        ProcessRiskSignal::UnsignedExecutable,
                    ],
                ),
                ProcessRiskAssessment::new(
                    3,
                    "high",
                    vec![
                        ProcessRiskSignal::TemporaryDirectory,
                        ProcessRiskSignal::InvalidSignature,
                    ],
                ),
            ],

            suspicious_processes: vec![
                SuspiciousProcess {
                    pid: 3,

                    name: "high".to_owned(),

                    executable_path: PathBuf::from("/tmp/high"),

                    reason: ProcessAnomalyReason::TemporaryDirectory,

                    signature_status: CodeSignatureStatus::Invalid,

                    signature_metadata: CodeSignatureMetadata {
                        identifier: Some("com.aegisgrid.high".to_owned()),

                        team_identifier: Some("AEGISTEAM01".to_owned()),

                        authorities: vec!["Developer ID Application: AegisGrid Test".to_owned()],
                    },

                    sha256: Some("highhash".to_owned()),

                    risk_score: 80,

                    risk_level: ProcessRiskLevel::HighAnomaly,

                    signals: vec![
                        ProcessRiskSignal::TemporaryDirectory,
                        ProcessRiskSignal::InvalidSignature,
                    ],
                },
                SuspiciousProcess {
                    pid: 2,

                    name: "review".to_owned(),

                    executable_path: PathBuf::from("/tmp/review"),

                    reason: ProcessAnomalyReason::TemporaryDirectory,

                    signature_status: CodeSignatureStatus::Unsigned,

                    signature_metadata: CodeSignatureMetadata::default(),

                    sha256: Some("reviewhash".to_owned()),

                    risk_score: 65,

                    risk_level: ProcessRiskLevel::ReviewRecommended,

                    signals: vec![
                        ProcessRiskSignal::TemporaryDirectory,
                        ProcessRiskSignal::UnsignedExecutable,
                    ],
                },
            ],
        }
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time error")
            .as_nanos();

        std::env::temp_dir().join(format!(
            "aegisgrid_{}_{}_{}",
            name,
            std::process::id(),
            nanos,
        ))
    }

    #[test]
    fn summary_counts_are_correct() {
        let snapshot = test_snapshot();

        assert_eq!(snapshot.analyzed_process_count, 500,);

        assert_eq!(snapshot.observed_count(), 3,);

        assert_eq!(snapshot.suspicious_count(), 2,);

        assert_eq!(snapshot.review_recommended_count(), 1,);

        assert_eq!(snapshot.high_anomaly_count(), 1,);

        assert_eq!(snapshot.highest_risk_score(), 80,);

        assert_eq!(snapshot.highest_risk_level(), ProcessRiskLevel::HighAnomaly,);
    }

    #[test]
    fn signature_counts_are_correct() {
        let snapshot = test_snapshot();

        assert_eq!(snapshot.signature_valid_count(), 0,);

        assert_eq!(snapshot.signature_unsigned_count(), 1,);

        assert_eq!(snapshot.signature_invalid_count(), 1,);

        assert_eq!(snapshot.signature_unknown_count(), 0,);
    }

    #[test]
    fn empty_snapshot_is_safe() {
        let snapshot = ProcessSecuritySnapshot::default();

        assert_eq!(snapshot.observed_count(), 0,);

        assert_eq!(snapshot.suspicious_count(), 0,);

        assert_eq!(snapshot.highest_risk_score(), 0,);

        assert_eq!(snapshot.highest_risk_level(), ProcessRiskLevel::Safe,);

        assert!(snapshot.highest_risk_process_detail().is_none());
    }

    #[test]
    fn process_detail_is_created_correctly() {
        let snapshot = test_snapshot();

        let detail = snapshot.process_detail(3).expect("detail missing");

        assert_eq!(detail.pid, 3,);

        assert_eq!(detail.risk_score, 80,);

        assert_eq!(detail.signature_status, CodeSignatureStatus::Invalid,);

        assert_eq!(
            detail.signature_metadata.identifier.as_deref(),
            Some("com.aegisgrid.high",),
        );

        assert_eq!(
            detail.signature_metadata.team_identifier.as_deref(),
            Some("AEGISTEAM01",),
        );

        assert_eq!(detail.sha256.as_deref(), Some("highhash",),);

        assert_eq!(detail.signal_count(), 2,);
    }

    #[test]
    fn highest_risk_process_detail_returns_first_process() {
        let snapshot = test_snapshot();

        let detail = snapshot
            .highest_risk_process_detail()
            .expect("detail missing");

        assert_eq!(detail.pid, 3,);

        assert_eq!(detail.risk_score, 80,);

        assert_eq!(detail.risk_level, ProcessRiskLevel::HighAnomaly,);
    }

    #[test]
    fn review_process_details_returns_all_review_processes() {
        let snapshot = test_snapshot();

        let details = snapshot.review_process_details();

        assert_eq!(details.len(), 2,);

        assert_eq!(details[0].pid, 3,);

        assert_eq!(details[1].pid, 2,);
    }

    #[test]
    fn sha256_is_calculated_correctly() {
        let path = unique_test_path("sha256");

        fs::write(&path, b"abc").expect("test file write failed");

        let hash = calculate_file_sha256(&path).expect("hash missing");

        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_hash_cache_updates_after_file_change() {
        let path = unique_test_path("hash_cache");

        fs::write(&path, b"abc").expect("test file write failed");

        let mut analyzer = ProcessSecurityAnalyzer::new();

        let first = analyzer.file_sha256(&path).expect("first hash missing");

        let cached = analyzer.file_sha256(&path).expect("cached hash missing");

        assert_eq!(first, cached,);

        fs::write(&path, b"abcd").expect("changed test file write failed");

        let second = analyzer.file_sha256(&path).expect("second hash missing");

        assert_ne!(first, second,);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn signature_metadata_is_parsed_correctly() {
        let output = "
Executable=/Applications/Test.app/Contents/MacOS/Test
Identifier=com.example.test
Authority=Developer ID Application: Example GmbH (ABC123XYZ)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=ABC123XYZ
";

        let metadata = parse_code_signature_metadata(output);

        assert_eq!(metadata.identifier.as_deref(), Some("com.example.test",),);

        assert_eq!(metadata.team_identifier.as_deref(), Some("ABC123XYZ",),);

        assert_eq!(metadata.authorities.len(), 3,);

        assert_eq!(
            metadata.authorities[0],
            "Developer ID Application: Example GmbH (ABC123XYZ)",
        );
    }

    #[test]
    fn missing_team_identifier_is_not_stored() {
        let output = "
Identifier=aegisgrid_process_test
TeamIdentifier=not set
";

        let metadata = parse_code_signature_metadata(output);

        assert_eq!(
            metadata.identifier.as_deref(),
            Some("aegisgrid_process_test",),
        );

        assert!(metadata.team_identifier.is_none());

        assert!(metadata.authorities.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_file_adds_unusual_permissions_signal() {
        let path = unique_test_path("world_writable");

        fs::write(&path, b"test").expect("test file write failed");

        let mut permissions = fs::metadata(&path).expect("metadata missing").permissions();

        permissions.set_mode(0o777);

        fs::set_permissions(&path, permissions).expect("permissions update failed");

        let mut signals = Vec::new();

        add_unusual_permissions_signal(&path, &mut signals);

        assert_eq!(signals, vec![ProcessRiskSignal::UnusualPermissions,],);

        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn normal_executable_permissions_do_not_add_signal() {
        let path = unique_test_path("normal_permissions");

        fs::write(&path, b"test").expect("test file write failed");

        let mut permissions = fs::metadata(&path).expect("metadata missing").permissions();

        permissions.set_mode(0o755);

        fs::set_permissions(&path, permissions).expect("permissions update failed");

        let mut signals = Vec::new();

        add_unusual_permissions_signal(&path, &mut signals);

        assert!(signals.is_empty());

        let _ = fs::remove_file(path);
    }
}
