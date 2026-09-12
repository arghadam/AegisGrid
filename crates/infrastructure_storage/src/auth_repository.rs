use application::ports::AuthRepository;
use async_trait::async_trait;
use domain::auth::{StoredCredential, UserAccount};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct SqliteAuthRepository {
    pool: SqlitePool,
}

impl SqliteAuthRepository {
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthRepository for SqliteAuthRepository {
    type Error = sqlx::Error;

    async fn has_any_account(&self) -> Result<bool, Self::Error> {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users LIMIT 1)",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(exists != 0)
    }

    async fn find_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredCredential>, Self::Error> {
        let row = sqlx::query(
            "SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| StoredCredential {
            user_id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
        }))
    }

    async fn create(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<UserAccount, Self::Error> {
        let result = sqlx::query(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        )
        .bind(username)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        Ok(UserAccount {
            id: result.last_insert_rowid(),
            username: username.to_owned(),
        })
    }

    async fn update_password_hash(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            "UPDATE users SET password_hash = ? WHERE username = ?",
        )
        .bind(password_hash)
        .bind(username)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_username(&self, username: &str) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
