//! Reservierte Infrastrukturgrenze für spätere lokale/optionale KI-Analyse.
//! In der aktuellen Version werden keine erfundenen KI-Sicherheitswerte erzeugt.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiIntegrationState {
    Disabled,
}

pub const fn state() -> AiIntegrationState {
    AiIntegrationState::Disabled
}
