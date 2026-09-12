use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Debug, Clone, Copy, Default)]
pub struct ApplicationResourceSnapshot {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

impl ApplicationResourceSnapshot {
    pub fn memory_megabytes(self) -> f64 {
        self.memory_bytes as f64 / 1024.0 / 1024.0
    }
}

pub struct SysinfoApplicationResourceMonitor {
    system: System,
    pid: Option<sysinfo::Pid>,
}

impl SysinfoApplicationResourceMonitor {
    pub fn new() -> Self {
        Self {
            system: System::new(),
            pid: sysinfo::get_current_pid().ok(),
        }
    }

    pub fn snapshot(&mut self) -> Option<ApplicationResourceSnapshot> {
        let pid = self.pid?;

        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory(),
        );

        let process = self.system.process(pid)?;

        Some(ApplicationResourceSnapshot {
            cpu_percent: process.cpu_usage(),
            memory_bytes: process.memory(),
        })
    }
}

impl Default for SysinfoApplicationResourceMonitor {
    fn default() -> Self {
        Self::new()
    }
}
