mod details;
mod network_monitor;

pub use details::{read_network_details, NetworkDetailsSnapshot};
pub use network_monitor::SysinfoNetworkMonitor;
