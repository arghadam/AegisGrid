use domain::system::SystemSnapshot;

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDashboardViewModel {
    pub cpu_percent: f32,
    pub memory_percent: f64,
    pub storage_used_gb: f64,
    pub storage_total_gb: f64,
    pub process_count: usize,
}

impl From<SystemSnapshot> for SystemDashboardViewModel {
    fn from(snapshot: SystemSnapshot) -> Self {
        let memory_percent = if snapshot.memory_total_bytes == 0 {
            0.0
        } else {
            snapshot.memory_used_bytes as f64 / snapshot.memory_total_bytes as f64 * 100.0
        };

        const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

        Self {
            cpu_percent: snapshot.cpu_percent,
            memory_percent,
            storage_used_gb: snapshot.storage_used_bytes as f64 / GIB,
            storage_total_gb: snapshot.storage_total_bytes as f64 / GIB,
            process_count: snapshot.process_count,
        }
    }
}
