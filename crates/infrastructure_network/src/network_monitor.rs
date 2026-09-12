use application::ports::NetworkMonitor;
use domain::network::NetworkSnapshot;
use netstat2::{AddressFamilyFlags, ProtocolFlags, get_sockets_info};
use std::time::{Duration, Instant};
use sysinfo::Networks;

const CONNECTION_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

pub struct SysinfoNetworkMonitor {
    networks: Networks,
    last_refresh: Instant,
    last_connection_refresh: Instant,
    cached_connection_count: usize,
}

impl SysinfoNetworkMonitor {
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            last_refresh: Instant::now(),
            last_connection_refresh: Instant::now()
                .checked_sub(CONNECTION_REFRESH_INTERVAL)
                .unwrap_or_else(Instant::now),
            cached_connection_count: 0,
        }
    }
}

impl Default for SysinfoNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMonitor for SysinfoNetworkMonitor {
    fn snapshot(&mut self) -> NetworkSnapshot {
        let elapsed = self.last_refresh.elapsed().as_secs_f64().max(0.001);
        self.networks.refresh(true);
        self.last_refresh = Instant::now();

        let received = self
            .networks
            .iter()
            .map(|(_, data)| data.received())
            .sum::<u64>();
        let transmitted = self
            .networks
            .iter()
            .map(|(_, data)| data.transmitted())
            .sum::<u64>();

        if self.last_connection_refresh.elapsed() >= CONNECTION_REFRESH_INTERVAL {
            self.cached_connection_count = active_connection_count();
            self.last_connection_refresh = Instant::now();
        }

        NetworkSnapshot {
            download_bytes_per_second: received as f64 / elapsed,
            upload_bytes_per_second: transmitted as f64 / elapsed,
            active_connection_count: self.cached_connection_count,
        }
    }
}

fn active_connection_count() -> usize {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    get_sockets_info(af, proto)
        .map(|sockets| sockets.len())
        .unwrap_or(0)
}
