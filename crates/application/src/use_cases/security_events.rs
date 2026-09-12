use crate::ports::SecurityEventRepository;
use domain::security::{SecurityEvent, SecurityEventSeverity};

pub struct RecordSecurityEvent<R> {
    repository: R,
}

impl<R> RecordSecurityEvent<R>
where
    R: SecurityEventRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        severity: SecurityEventSeverity,
        message: &str,
    ) -> Result<(), R::Error> {
        self.repository.append(severity, message).await
    }
}

pub struct ReadRecentSecurityEvents<R> {
    repository: R,
}

impl<R> ReadRecentSecurityEvents<R>
where
    R: SecurityEventRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, limit: usize) -> Result<Vec<SecurityEvent>, R::Error> {
        self.repository.recent(limit).await
    }
}
