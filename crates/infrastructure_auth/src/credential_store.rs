use application::ports::CredentialStore;
use std::{error::Error, fmt};

const SERVICE_NAME: &str = "de.aegisgrid.desktop.password-hash";

#[derive(Debug)]
pub struct CredentialStoreError(String);

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CredentialStoreError {}

#[derive(Clone, Copy, Default)]
pub struct SecureCredentialStore;

impl CredentialStore for SecureCredentialStore {
    type Error = CredentialStoreError;

    fn store_password_hash(&self, username: &str, password_hash: &str) -> Result<(), Self::Error> {
        keyring::Entry::new(SERVICE_NAME, username)
            .map_err(|error| CredentialStoreError(error.to_string()))?
            .set_password(password_hash)
            .map_err(|error| CredentialStoreError(error.to_string()))
    }

    fn load_password_hash(&self, username: &str) -> Result<String, Self::Error> {
        keyring::Entry::new(SERVICE_NAME, username)
            .map_err(|error| CredentialStoreError(error.to_string()))?
            .get_password()
            .map_err(|error| CredentialStoreError(error.to_string()))
    }

    fn delete_password_hash(&self, username: &str) -> Result<(), Self::Error> {
        let entry = keyring::Entry::new(SERVICE_NAME, username)
            .map_err(|error| CredentialStoreError(error.to_string()))?;

        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(CredentialStoreError(error.to_string())),
        }
    }
}
