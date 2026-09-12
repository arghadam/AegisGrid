use crate::ports::{NetworkMonitor, SecurityMonitor, SystemMonitor};
use domain::{
    network::NetworkSnapshot,
    security::SecuritySnapshot,
    system::SystemSnapshot,
};

pub struct ReadSystemSnapshot<M> {
    monitor: M,
}

impl<M> ReadSystemSnapshot<M>
where
    M: SystemMonitor,
{
    pub const fn new(monitor: M) -> Self {
        Self { monitor }
    }

    pub fn execute(&mut self) -> SystemSnapshot {
        self.monitor.snapshot()
    }
}

pub struct ReadNetworkSnapshot<M> {
    monitor: M,
}

impl<M> ReadNetworkSnapshot<M>
where
    M: NetworkMonitor,
{
    pub const fn new(monitor: M) -> Self {
        Self { monitor }
    }

    pub fn execute(&mut self) -> NetworkSnapshot {
        self.monitor.snapshot()
    }
}

pub struct ReadSecuritySnapshot<M> {
    monitor: M,
}

impl<M> ReadSecuritySnapshot<M>
where
    M: SecurityMonitor,
{
    pub const fn new(monitor: M) -> Self {
        Self { monitor }
    }

    pub fn execute(&mut self) -> SecuritySnapshot {
        self.monitor.snapshot()
    }
}
