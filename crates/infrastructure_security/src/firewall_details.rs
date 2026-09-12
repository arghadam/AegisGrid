use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct FirewallDetailsSnapshot {
    pub status: String,
    pub profiles: String,
    pub rules: String,
}

pub fn read_firewall_details() -> FirewallDetailsSnapshot {
    platform_firewall_details()
}

#[cfg(target_os = "macos")]
fn platform_firewall_details() -> FirewallDetailsSnapshot {
    const TOOL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

    let status = run_command(TOOL, &["--getglobalstate"])
        .unwrap_or_else(|| "FIREWALL-STATUS NICHT VERFÜGBAR".to_owned());

    let stealth = run_command(TOOL, &["--getstealthmode"])
        .unwrap_or_else(|| "STEALTH-MODUS NICHT VERFÜGBAR".to_owned());

    let signed = run_command(TOOL, &["--getallowsigned"])
        .unwrap_or_else(|| "SIGNIERTE APPS: STATUS NICHT VERFÜGBAR".to_owned());

    let profiles = format!("{}\n{}\n{}", status, stealth, signed,);

    let rules = run_command(TOOL, &["--listapps"])
        .map(|value| truncate_lines(&value, 80))
        .unwrap_or_else(|| "FIREWALL-REGELN NICHT VERFÜGBAR".to_owned());

    FirewallDetailsSnapshot {
        status,
        profiles,
        rules,
    }
}

#[cfg(target_os = "windows")]
fn platform_firewall_details() -> FirewallDetailsSnapshot {
    let profiles_script = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize | Out-String -Width 220";

    let rules_script = "Get-NetFirewallRule -Enabled True | Select-Object -First 80 DisplayName,Direction,Action,Profile | Format-Table -AutoSize | Out-String -Width 220";

    let profiles = run_command(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", profiles_script],
    )
    .unwrap_or_else(|| "FIREWALL-PROFILE NICHT VERFÜGBAR".to_owned());

    let status = if profiles.to_lowercase().contains("true") {
        "WINDOWS FIREWALL // MINDESTENS EIN PROFIL AKTIV".to_owned()
    } else {
        "WINDOWS FIREWALL // STATUS PRÜFEN".to_owned()
    };

    let rules = run_command(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", rules_script],
    )
    .map(|value| truncate_lines(&value, 80))
    .unwrap_or_else(|| "FIREWALL-REGELN NICHT VERFÜGBAR".to_owned());

    FirewallDetailsSnapshot {
        status,
        profiles,
        rules,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_firewall_details() -> FirewallDetailsSnapshot {
    FirewallDetailsSnapshot {
        status: "NICHT UNTERSTÜTZTE PLATTFORM".to_owned(),
        profiles: "NICHT VERFÜGBAR".to_owned(),
        rules: "NICHT VERFÜGBAR".to_owned(),
    }
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;

    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    if text.is_empty() && !stderr.is_empty() {
        text = stderr;
    }

    if text.is_empty() { None } else { Some(text) }
}

fn truncate_lines(value: &str, maximum: usize) -> String {
    let rows = value.lines().collect::<Vec<_>>();

    if rows.len() <= maximum {
        return value.trim().to_owned();
    }

    let mut output = rows
        .iter()
        .take(maximum)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    output.push_str(&format!(
        "\n\n+ {} WEITERE ZEILEN",
        rows.len().saturating_sub(maximum),
    ));

    output
}
