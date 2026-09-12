use crate::ports::{AuthRepository, CredentialStore, PasswordHasher};
use domain::auth::{AuthenticationStatus, UserAccount};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCK_DURATION: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy)]
struct LoginAttemptState {
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

fn attempts() -> &'static Mutex<HashMap<String, LoginAttemptState>> {
    static ATTEMPTS: OnceLock<Mutex<HashMap<String, LoginAttemptState>>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug)]
pub enum CreateInitialAccountError<R, C, H> {
    AlreadyConfigured,
    EmptyUsername,
    UsernameTooLong,
    PasswordTooShort,
    PasswordTooLong,
    PasswordMismatch,
    Repository(R),
    CredentialStore(C),
    PasswordHash(H),
    Rollback {
        repository_error: R,
        credential_store_error: C,
    },
}

pub struct CreateInitialAccount<R, C, H> {
    repository: R,
    credential_store: C,
    password_hasher: H,
}

impl<R, C, H> CreateInitialAccount<R, C, H>
where
    R: AuthRepository,
    C: CredentialStore,
    H: PasswordHasher,
{
    pub const fn new(repository: R, credential_store: C, password_hasher: H) -> Self {
        Self {
            repository,
            credential_store,
            password_hasher,
        }
    }

    pub async fn execute(
        &self,
        username: &str,
        password: &str,
        password_confirmation: &str,
    ) -> Result<UserAccount, CreateInitialAccountError<R::Error, C::Error, H::Error>> {
        let username = username.trim();

        if username.is_empty() {
            return Err(CreateInitialAccountError::EmptyUsername);
        }
        if username.chars().count() > 64 {
            return Err(CreateInitialAccountError::UsernameTooLong);
        }
        if password.len() < 12 {
            return Err(CreateInitialAccountError::PasswordTooShort);
        }
        if password.len() > 512 {
            return Err(CreateInitialAccountError::PasswordTooLong);
        }
        if password != password_confirmation {
            return Err(CreateInitialAccountError::PasswordMismatch);
        }

        if self
            .repository
            .has_any_account()
            .await
            .map_err(CreateInitialAccountError::Repository)?
        {
            return Err(CreateInitialAccountError::AlreadyConfigured);
        }

        let password_hash = self
            .password_hasher
            .hash_password(password)
            .map_err(CreateInitialAccountError::PasswordHash)?;

        self.credential_store
            .store_password_hash(username, &password_hash)
            .map_err(CreateInitialAccountError::CredentialStore)?;

        match self.repository.create(username, &password_hash).await {
            Ok(account) => Ok(account),
            Err(repository_error) => match self.credential_store.delete_password_hash(username) {
                Ok(()) => Err(CreateInitialAccountError::Repository(repository_error)),
                Err(credential_store_error) => Err(CreateInitialAccountError::Rollback {
                    repository_error,
                    credential_store_error,
                }),
            },
        }
    }
}

#[derive(Debug)]
pub enum LoginError<R, C, H> {
    Repository(R),
    CredentialStore(C),
    PasswordHash(H),
}

pub struct Login<R, C, H> {
    repository: R,
    credential_store: C,
    password_hasher: H,
}

impl<R, C, H> Login<R, C, H>
where
    R: AuthRepository,
    C: CredentialStore,
    H: PasswordHasher,
{
    pub const fn new(repository: R, credential_store: C, password_hasher: H) -> Self {
        Self {
            repository,
            credential_store,
            password_hasher,
        }
    }

    pub async fn execute(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticationStatus, LoginError<R::Error, C::Error, H::Error>> {
        let username = username.trim();

        if is_locked(username) {
            return Ok(AuthenticationStatus::Locked);
        }

        let Some(stored) = self
            .repository
            .find_by_username(username)
            .await
            .map_err(LoginError::Repository)?
        else {
            record_failure(username);
            return Ok(AuthenticationStatus::InvalidCredentials);
        };

        let keychain_hash = self
            .credential_store
            .load_password_hash(username)
            .map_err(LoginError::CredentialStore)?;

        // DB und sicherer OS-Speicher müssen übereinstimmen.
        if keychain_hash != stored.password_hash {
            record_failure(username);
            return Ok(AuthenticationStatus::InvalidCredentials);
        }

        let valid = self
            .password_hasher
            .verify_password(password, &stored.password_hash)
            .map_err(LoginError::PasswordHash)?;

        if valid {
            clear_failures(username);
            Ok(AuthenticationStatus::Authenticated)
        } else {
            record_failure(username);
            Ok(if is_locked(username) {
                AuthenticationStatus::Locked
            } else {
                AuthenticationStatus::InvalidCredentials
            })
        }
    }
}

#[derive(Debug)]
pub enum ChangePasswordError<R, C, H> {
    AccountNotFound,
    CurrentPasswordInvalid,
    NewPasswordTooShort,
    NewPasswordTooLong,
    NewPasswordMismatch,
    Repository(R),
    CredentialStore(C),
    PasswordHash(H),
    Rollback {
        repository_error: R,
        credential_store_error: C,
    },
}

pub struct ChangePassword<R, C, H> {
    repository: R,
    credential_store: C,
    password_hasher: H,
}

impl<R, C, H> ChangePassword<R, C, H>
where
    R: AuthRepository,
    C: CredentialStore,
    H: PasswordHasher,
{
    pub const fn new(repository: R, credential_store: C, password_hasher: H) -> Self {
        Self {
            repository,
            credential_store,
            password_hasher,
        }
    }

    pub async fn execute(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
        new_password_confirmation: &str,
    ) -> Result<(), ChangePasswordError<R::Error, C::Error, H::Error>> {
        let username = username.trim();

        if new_password.len() < 12 {
            return Err(ChangePasswordError::NewPasswordTooShort);
        }
        if new_password.len() > 512 {
            return Err(ChangePasswordError::NewPasswordTooLong);
        }
        if new_password != new_password_confirmation {
            return Err(ChangePasswordError::NewPasswordMismatch);
        }

        let Some(stored) = self
            .repository
            .find_by_username(username)
            .await
            .map_err(ChangePasswordError::Repository)?
        else {
            return Err(ChangePasswordError::AccountNotFound);
        };

        let keychain_hash = self
            .credential_store
            .load_password_hash(username)
            .map_err(ChangePasswordError::CredentialStore)?;

        if keychain_hash != stored.password_hash {
            return Err(ChangePasswordError::CurrentPasswordInvalid);
        }

        let current_valid = self
            .password_hasher
            .verify_password(current_password, &stored.password_hash)
            .map_err(ChangePasswordError::PasswordHash)?;

        if !current_valid {
            return Err(ChangePasswordError::CurrentPasswordInvalid);
        }

        let new_hash = self
            .password_hasher
            .hash_password(new_password)
            .map_err(ChangePasswordError::PasswordHash)?;

        self.credential_store
            .store_password_hash(username, &new_hash)
            .map_err(ChangePasswordError::CredentialStore)?;

        match self
            .repository
            .update_password_hash(username, &new_hash)
            .await
        {
            Ok(()) => Ok(()),
            Err(repository_error) => match self
                .credential_store
                .store_password_hash(username, &stored.password_hash)
            {
                Ok(()) => Err(ChangePasswordError::Repository(repository_error)),
                Err(credential_store_error) => Err(ChangePasswordError::Rollback {
                    repository_error,
                    credential_store_error,
                }),
            },
        }
    }
}

fn is_locked(username: &str) -> bool {
    let Ok(mut guard) = attempts().lock() else {
        return false;
    };

    let Some(state) = guard.get_mut(username) else {
        return false;
    };

    if let Some(until) = state.locked_until {
        if Instant::now() < until {
            return true;
        }

        state.failed_attempts = 0;
        state.locked_until = None;
    }

    false
}

fn record_failure(username: &str) {
    let Ok(mut guard) = attempts().lock() else {
        return;
    };

    let state = guard
        .entry(username.to_owned())
        .or_insert(LoginAttemptState {
            failed_attempts: 0,
            locked_until: None,
        });

    state.failed_attempts = state.failed_attempts.saturating_add(1);

    if state.failed_attempts >= MAX_FAILED_ATTEMPTS {
        state.locked_until = Some(Instant::now() + LOCK_DURATION);
    }
}

fn clear_failures(username: &str) {
    if let Ok(mut guard) = attempts().lock() {
        guard.remove(username);
    }
}
