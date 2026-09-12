#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkSnapshot {
    pub download_bytes_per_second: f64,
    pub upload_bytes_per_second: f64,
    pub active_connection_count: usize,
}
