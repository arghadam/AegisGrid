#[derive(Debug, Clone, Default)]
pub struct SystemIdentity {
    pub hostname: String,
    pub operating_system: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSnapshot {
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub storage_used_bytes: u64,
    pub storage_total_bytes: u64,
    pub process_count: usize,
}
