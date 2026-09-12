use sysinfo::{Components, Disks, System};

#[derive(Debug, Clone, Default)]
pub struct HardwareDetailsSnapshot {
    pub cpu: String,
    pub cores: String,
    pub memory: String,
    pub disks: String,
    pub sensors: String,
}

pub fn read_hardware_details() -> HardwareDetailsSnapshot {
    let mut system = System::new_all();
    system.refresh_cpu_all();
    system.refresh_memory();

    let cpu = system
        .cpus()
        .first()
        .map(|cpu| format!("{} // {} MHz", cpu.brand(), cpu.frequency(),))
        .unwrap_or_else(|| "UNBEKANNT".to_owned());

    let physical = System::physical_core_count()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "—".to_owned());

    let logical = system.cpus().len();
    let cores = format!("PHYSISCH: {} // LOGISCH: {}", physical, logical,);

    let gib = 1024.0 * 1024.0 * 1024.0;
    let memory = format!(
        "GESAMT {:.1} GB // VERWENDET {:.1} GB",
        system.total_memory() as f64 / gib,
        system.used_memory() as f64 / gib,
    );

    let disks = Disks::new_with_refreshed_list();
    let disk_text = if disks.is_empty() {
        "KEINE DATENTRÄGERINFORMATIONEN VERFÜGBAR".to_owned()
    } else {
        disks
            .iter()
            .map(|disk| {
                format!(
                    "{} | {} | {:.1}/{:.1} GB",
                    disk.name().to_string_lossy(),
                    disk.mount_point().to_string_lossy(),
                    (disk.total_space().saturating_sub(disk.available_space())) as f64 / gib,
                    disk.total_space() as f64 / gib,
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let components = Components::new_with_refreshed_list();
    let sensor_rows = components
        .iter()
        .filter_map(|component| {
            component.temperature().map(|temperature| {
                let critical = component
                    .critical()
                    .map(|value| format!(" // KRITISCH {:.1} °C", value))
                    .unwrap_or_default();

                format!("{} | {:.1} °C{}", component.label(), temperature, critical,)
            })
        })
        .collect::<Vec<_>>();

    let sensors = if sensor_rows.is_empty() {
        "KEINE TEMPERATURSENSOREN VOM BETRIEBSSYSTEM FREIGEGEBEN".to_owned()
    } else {
        sensor_rows.join("\n")
    };

    HardwareDetailsSnapshot {
        cpu,
        cores,
        memory,
        disks: disk_text,
        sensors,
    }
}
