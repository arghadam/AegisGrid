use application::ports::PasswordHasher;
use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct PasswordHashingError(String);

impl fmt::Display for PasswordHashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PasswordHashingError {}

#[derive(Clone, Default)]
pub struct Argon2PasswordHasher;

impl Argon2PasswordHasher {
    pub const fn new() -> Self {
        Self
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    type Error = PasswordHashingError;

    fn hash_password(&self, password: &str) -> Result<String, Self::Error> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| PasswordHashingError(error.to_string()))
    }

    fn verify_password(&self, password: &str, password_hash: &str) -> Result<bool, Self::Error> {
        let parsed = PasswordHash::new(password_hash)
            .map_err(|error| PasswordHashingError(error.to_string()))?;

        match Argon2::default().verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(error) => Err(PasswordHashingError(error.to_string())),
        }
    }
}
