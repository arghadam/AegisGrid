mod biometric_authenticator;
mod credential_store;
mod password_hashing;

pub use credential_store::SecureCredentialStore;
pub use password_hashing::Argon2PasswordHasher;

#[cfg(target_os = "macos")]
pub use biometric_authenticator::MacOsBiometricAuthenticator;
