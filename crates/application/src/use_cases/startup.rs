use crate::ports::AuthRepository;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    InitialSetup,
    Login,
}

pub struct DetermineStartupMode<R> {
    repository: R,
}

impl<R> DetermineStartupMode<R>
where
    R: AuthRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn execute(&self) -> Result<StartupMode, R::Error> {
        Ok(if self.repository.has_any_account().await? {
            StartupMode::Login
        } else {
            StartupMode::InitialSetup
        })
    }
}
