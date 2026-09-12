#[cfg(target_os = "macos")]
use application::ports::BiometricAuthenticator;
#[cfg(target_os = "macos")]
use async_trait::async_trait;
#[cfg(target_os = "macos")]
use std::{error::Error, fmt};

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct BiometricError(String);

#[cfg(target_os = "macos")]
impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(target_os = "macos")]
impl Error for BiometricError {}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Default)]
pub struct MacOsBiometricAuthenticator;

#[cfg(target_os = "macos")]
#[async_trait]
impl BiometricAuthenticator for MacOsBiometricAuthenticator {
    type Error = BiometricError;

    async fn is_available(&self) -> Result<bool, Self::Error> {
        tokio::task::spawn_blocking(|| {
            use localauthentication::prelude::*;

            let context = LAContext::new().map_err(|error| BiometricError(error.to_string()))?;

            context
                .can_evaluate_policy(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .map_err(|error| BiometricError(error.to_string()))
        })
        .await
        .map_err(|error| BiometricError(error.to_string()))?
    }

    async fn authenticate(&self, reason: &str) -> Result<bool, Self::Error> {
        let reason = reason.to_owned();

        tokio::task::spawn_blocking(move || {
            use localauthentication::prelude::*;

            let context = LAContext::new().map_err(|error| BiometricError(error.to_string()))?;

            context
                .evaluate_policy(LAPolicy::DeviceOwnerAuthenticationWithBiometrics, &reason)
                .map_err(|error| BiometricError(error.to_string()))
        })
        .await
        .map_err(|error| BiometricError(error.to_string()))?
    }
}
