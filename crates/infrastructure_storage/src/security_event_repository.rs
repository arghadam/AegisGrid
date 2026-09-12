use application::ports::SecurityEventRepository;
use async_trait::async_trait;
use domain::security::{SecurityEvent, SecurityEventSeverity};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct SqliteSecurityEventRepository {
    pool: SqlitePool,
}

impl SqliteSecurityEventRepository {
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecurityEventRepository for SqliteSecurityEventRepository {
    type Error = sqlx::Error;

    async fn append(
        &self,
        severity: SecurityEventSeverity,
        message: &str,
    ) -> Result<(), Self::Error> {
        sqlx::query("INSERT INTO security_events (severity, message) VALUES (?, ?)")
            .bind(severity_text(severity))
            .bind(message)
            .execute(&self.pool)
            .await?;

        sqlx::query(
            r#"
            DELETE FROM security_events
            WHERE id NOT IN (
                SELECT id FROM security_events
                ORDER BY id DESC
                LIMIT 1000
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn recent(&self, limit: usize) -> Result<Vec<SecurityEvent>, Self::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, occurred_at, severity, message
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            "#,
        )
        .bind(limit.min(500) as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| SecurityEvent {
                id: row.get("id"),
                occurred_at: row.get("occurred_at"),
                severity: parse_severity(row.get::<String, _>("severity").as_str()),
                message: row.get("message"),
            })
            .collect())
    }
}

fn severity_text(severity: SecurityEventSeverity) -> &'static str {
    match severity {
        SecurityEventSeverity::Info => "INFO",
        SecurityEventSeverity::Warning => "WARNUNG",
        SecurityEventSeverity::Critical => "KRITISCH",
    }
}

fn parse_severity(value: &str) -> SecurityEventSeverity {
    match value {
        "KRITISCH" => SecurityEventSeverity::Critical,
        "WARNUNG" => SecurityEventSeverity::Warning,
        _ => SecurityEventSeverity::Info,
    }
}
