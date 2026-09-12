use netstat2::{
    get_sockets_info,
    AddressFamilyFlags,
    ProtocolFlags,
    ProtocolSocketInfo,
    TcpState,
};
use std::collections::HashSet;
use sysinfo::{Pid, System};

#[derive(Debug, Clone, Default)]
pub struct NetworkDetailsSnapshot {
    pub active_connection_count: usize,
    pub listening_port_count: usize,
    pub connections_table: String,
    pub listening_ports_table: String,
}

pub fn read_network_details(
    connection_limit: usize,
    port_limit: usize,
) -> NetworkDetailsSnapshot {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let Ok(sockets) = get_sockets_info(af, proto) else {
        return NetworkDetailsSnapshot {
            connections_table: "NETZWERKDETAILS NICHT VERFÜGBAR".to_owned(),
            listening_ports_table: "PORTDETAILS NICHT VERFÜGBAR".to_owned(),
            ..NetworkDetailsSnapshot::default()
        };
    };

    let mut system = System::new_all();
    system.refresh_all();

    let mut connection_rows = Vec::new();
    let mut port_rows = Vec::new();
    let mut unique_ports = HashSet::new();

    for socket in &sockets {
        let process = process_label(&system, &socket.associated_pids);

        match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                if tcp.state == TcpState::Listen {
                    let key = format!("TCP|{}|{}", tcp.local_addr, tcp.local_port);
                    if unique_ports.insert(key) {
                        port_rows.push(format!(
                            "TCP | {}:{} | {}",
                            tcp.local_addr,
                            tcp.local_port,
                            process,
                        ));
                    }
                } else {
                    connection_rows.push(format!(
                        "TCP | {}:{} -> {}:{} | {:?} | {}",
                        tcp.local_addr,
                        tcp.local_port,
                        tcp.remote_addr,
                        tcp.remote_port,
                        tcp.state,
                        process,
                    ));
                }
            }
            ProtocolSocketInfo::Udp(udp) => {
                let key = format!("UDP|{}|{}", udp.local_addr, udp.local_port);
                if unique_ports.insert(key) {
                    port_rows.push(format!(
                        "UDP | {}:{} | {}",
                        udp.local_addr,
                        udp.local_port,
                        process,
                    ));
                }

                connection_rows.push(format!(
                    "UDP | {}:{} | {}",
                    udp.local_addr,
                    udp.local_port,
                    process,
                ));
            }
        }
    }

    connection_rows.sort();
    port_rows.sort();

    let active_connection_count = connection_rows.len();
    let listening_port_count = port_rows.len();

    NetworkDetailsSnapshot {
        active_connection_count,
        listening_port_count,
        connections_table: render_rows(
            &connection_rows,
            connection_limit,
            "KEINE AKTIVEN VERBINDUNGEN",
        ),
        listening_ports_table: render_rows(
            &port_rows,
            port_limit,
            "KEINE OFFENEN PORTS ERKANNT",
        ),
    }
}

fn process_label(system: &System, pids: &[u32]) -> String {
    if pids.is_empty() {
        return "PID —".to_owned();
    }

    pids.iter()
        .take(3)
        .map(|pid| {
            let pid_value = *pid;
            let name = system
                .process(Pid::from_u32(pid_value))
                .map(|process| process.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| "UNBEKANNT".to_owned());

            format!("PID {} {}", pid_value, name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_rows(rows: &[String], limit: usize, empty_text: &str) -> String {
    if rows.is_empty() {
        return empty_text.to_owned();
    }

    let effective_limit = limit.max(1);
    let mut output = rows
        .iter()
        .take(effective_limit)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");

    let remaining = rows.len().saturating_sub(effective_limit);
    if remaining > 0 {
        output.push_str(&format!("\n\n+ {} WEITERE EINTRÄGE", remaining));
    }

    output
}
