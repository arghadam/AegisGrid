use async_trait::async_trait;
use domain::security::{SecurityEvent, SecurityEventSeverity};
use std::error::Error;

#[async_trait]
pub trait SecurityEventRepository: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    async fn append(
        &self,
        severity: SecurityEventSeverity,
        message: &str,
    ) -> Result<(), Self::Error>;

    async fn recent(&self, limit: usize) -> Result<Vec<SecurityEvent>, Self::Error>;
}
