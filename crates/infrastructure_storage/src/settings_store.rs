use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppSettingsStore {
    pool: SqlitePool,
}

impl AppSettingsStore {
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn load_animation_enabled(
        &self,
        default: bool,
    ) -> Result<bool, sqlx::Error> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM app_settings WHERE key = 'animation_enabled' LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(match value.as_deref() {
            Some("0") => false,
            Some("1") => true,
            _ => default,
        })
    }

    pub async fn load_auto_lock_minutes(
        &self,
        default: i32,
    ) -> Result<i32, sqlx::Error> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT value FROM app_settings WHERE key = 'auto_lock_minutes' LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(value
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| matches!(*value, 0 | 5 | 15 | 30))
            .unwrap_or(default))
    }

    pub async fn save(
        &self,
        animation_enabled: bool,
        auto_lock_minutes: i32,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO app_settings (key, value)
            VALUES ('animation_enabled', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
        )
        .bind(if animation_enabled { "1" } else { "0" })
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO app_settings (key, value)
            VALUES ('auto_lock_minutes', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
        )
        .bind(auto_lock_minutes.to_string())
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }
}
