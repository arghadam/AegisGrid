use domain::{
    network::NetworkSnapshot,
    security::SecuritySnapshot,
    system::{SystemIdentity, SystemSnapshot},
};

pub trait SystemMonitor {
    fn identity(&self) -> SystemIdentity;
    fn snapshot(&mut self) -> SystemSnapshot;
}

pub trait NetworkMonitor {
    fn snapshot(&mut self) -> NetworkSnapshot;
}

pub trait SecurityMonitor {
    fn snapshot(&mut self) -> SecuritySnapshot;
}
