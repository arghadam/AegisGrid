mod details;
mod network_monitor;

pub use details::{NetworkDetailsSnapshot, read_network_details};
pub use network_monitor::SysinfoNetworkMonitor;
