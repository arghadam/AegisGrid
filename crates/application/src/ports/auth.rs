use async_trait::async_trait;
use domain::auth::{StoredCredential, UserAccount};
use std::error::Error;

#[async_trait]
pub trait AuthRepository: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    async fn has_any_account(&self) -> Result<bool, Self::Error>;

    async fn find_by_username(
        &self,
        username: &str,
    ) -> Result<Option<StoredCredential>, Self::Error>;

    async fn create(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<UserAccount, Self::Error>;

    async fn update_password_hash(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), Self::Error>;

    async fn delete_by_username(&self, username: &str) -> Result<(), Self::Error>;
}

pub trait CredentialStore: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    fn store_password_hash(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), Self::Error>;

    fn load_password_hash(&self, username: &str) -> Result<String, Self::Error>;

    fn delete_password_hash(&self, username: &str) -> Result<(), Self::Error>;
}

pub trait PasswordHasher: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    fn hash_password(&self, password: &str) -> Result<String, Self::Error>;
    fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, Self::Error>;
}

#[async_trait]
pub trait BiometricAuthenticator: Clone + Send + Sync + 'static {
    type Error: Error + Send + Sync + 'static;

    async fn is_available(&self) -> Result<bool, Self::Error>;
    async fn authenticate(&self, reason: &str) -> Result<bool, Self::Error>;
}
