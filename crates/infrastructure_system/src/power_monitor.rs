use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSource {
    Ac,
    Battery,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub struct PowerSnapshot {
    pub source: PowerSource,
    pub battery_percent: Option<f32>,
}

impl Default for PowerSnapshot {
    fn default() -> Self {
        Self {
            source: PowerSource::Unknown,
            battery_percent: None,
        }
    }
}

pub struct SystemPowerMonitor;

impl SystemPowerMonitor {
    pub const fn new() -> Self {
        Self
    }

    pub fn snapshot(&self) -> PowerSnapshot {
        platform_power_snapshot()
    }
}

impl Default for SystemPowerMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
fn platform_power_snapshot() -> PowerSnapshot {
    let Ok(output) = Command::new("/usr/bin/pmset").args(["-g", "batt"]).output() else {
        return PowerSnapshot::default();
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let source = if text.contains("AC Power") {
        PowerSource::Ac
    } else if text.contains("Battery Power") {
        PowerSource::Battery
    } else {
        PowerSource::Unknown
    };

    let battery_percent = text
        .split_whitespace()
        .find_map(|part| part.strip_suffix("%;").or_else(|| part.strip_suffix('%')))
        .and_then(|value| value.parse::<f32>().ok());

    PowerSnapshot {
        source,
        battery_percent,
    }
}

#[cfg(target_os = "windows")]
fn platform_power_snapshot() -> PowerSnapshot {
    let script = r#"
$b = Get-CimInstance Win32_Battery | Select-Object -First 1
if ($null -eq $b) { Write-Output 'AC|'; exit }
$source = if ($b.BatteryStatus -eq 2) { 'AC' } else { 'BATTERY' }
Write-Output ($source + '|' + $b.EstimatedChargeRemaining)
"#;

    let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    else {
        return PowerSnapshot::default();
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut parts = text.trim().split('|');

    let source = match parts.next().unwrap_or_default() {
        "AC" => PowerSource::Ac,
        "BATTERY" => PowerSource::Battery,
        _ => PowerSource::Unknown,
    };

    let battery_percent = parts.next().and_then(|value| value.parse::<f32>().ok());

    PowerSnapshot {
        source,
        battery_percent,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_power_snapshot() -> PowerSnapshot {
    PowerSnapshot::default()
}
