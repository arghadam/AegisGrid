use application::ports::SystemMonitor;
use domain::system::{SystemIdentity, SystemSnapshot};
use std::time::{Duration, Instant};
use sysinfo::{Disks, System};

#[cfg(target_os = "macos")]
use std::path::Path;

const STORAGE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const PROCESS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

pub struct SysinfoSystemMonitor {
    system: System,
    disks: Disks,
    last_storage_refresh: Instant,
    last_process_refresh: Instant,
    cached_storage_used: u64,
    cached_storage_total: u64,
    cached_process_count: usize,
}

impl SysinfoSystemMonitor {
    pub fn new() -> Self {
        let system = System::new_all();
        let disks = Disks::new_with_refreshed_list();
        let now = Instant::now();

        let (storage_used, storage_total) = storage_values(&disks);
        let process_count = system.processes().len();

        Self {
            system,
            disks,
            last_storage_refresh: now,
            last_process_refresh: now,
            cached_storage_used: storage_used,
            cached_storage_total: storage_total,
            cached_process_count: process_count,
        }
    }
}

impl Default for SysinfoSystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemMonitor for SysinfoSystemMonitor {
    fn identity(&self) -> SystemIdentity {
        let hostname = System::host_name().unwrap_or_else(|| "Unbekannt".to_owned());
        let operating_system = System::long_os_version()
            .or_else(System::name)
            .unwrap_or_else(|| "Unbekanntes Betriebssystem".to_owned());

        SystemIdentity {
            hostname,
            operating_system,
        }
    }

    fn snapshot(&mut self) -> SystemSnapshot {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();

        if self.last_process_refresh.elapsed() >= PROCESS_REFRESH_INTERVAL {
            self.system
                .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            self.cached_process_count = self.system.processes().len();
            self.last_process_refresh = Instant::now();
        }

        if self.last_storage_refresh.elapsed() >= STORAGE_REFRESH_INTERVAL {
            self.disks.refresh(true);
            let (used, total) = storage_values(&self.disks);
            self.cached_storage_used = used;
            self.cached_storage_total = total;
            self.last_storage_refresh = Instant::now();
        }

        SystemSnapshot {
            cpu_percent: self.system.global_cpu_usage(),
            memory_used_bytes: self.system.used_memory(),
            memory_total_bytes: self.system.total_memory(),
            storage_used_bytes: self.cached_storage_used,
            storage_total_bytes: self.cached_storage_total,
            process_count: self.cached_process_count,
        }
    }
}

fn storage_values(disks: &Disks) -> (u64, u64) {
    #[cfg(target_os = "macos")]
    {
        // macOS/APFS exposes multiple logical volumes from the same physical
        // container (for example System and Data). Summing all entries counts
        // the same SSD capacity multiple times. The root mount represents the
        // capacity that AegisGrid should show for the system drive.
        if let Some(root_disk) = disks
            .iter()
            .find(|disk| disk.mount_point() == Path::new("/"))
        {
            return single_disk_storage_values(
                root_disk.total_space(),
                root_disk.available_space(),
            );
        }

        // Defensive fallback for unusual macOS mount configurations: use the
        // largest reported volume instead of summing APFS sibling volumes.
        if let Some(largest_disk) = disks.iter().max_by_key(|disk| disk.total_space()) {
            return single_disk_storage_values(
                largest_disk.total_space(),
                largest_disk.available_space(),
            );
        }

        (0, 0)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let total = disks.iter().map(|disk| disk.total_space()).sum::<u64>();

        let available = disks.iter().map(|disk| disk.available_space()).sum::<u64>();

        (total.saturating_sub(available), total)
    }
}

fn single_disk_storage_values(total: u64, available: u64) -> (u64, u64) {
    (total.saturating_sub(available), total)
}
