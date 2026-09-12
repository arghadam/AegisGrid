#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    pub user_id: i64,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationStatus {
    Authenticated,
    InvalidCredentials,
    Locked,
}
