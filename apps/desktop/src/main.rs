use std::{
    cell::Cell,
    collections::VecDeque,
    process::{Command, Stdio},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use application::{
    ports::SystemMonitor,
    use_cases::{
        ChangePassword, ChangePasswordError, CreateInitialAccount, CreateInitialAccountError,
        DetermineStartupMode, Login, LoginError, ReadNetworkSnapshot, ReadRecentSecurityEvents,
        ReadSecuritySnapshot, ReadSystemSnapshot, RecordSecurityEvent, StartupMode,
    },
};
use chrono::Local;
use domain::{
    auth::AuthenticationStatus,
    security::{
        FileIntegrityStatus, FirewallStatus, ProcessRiskLevel, ProcessRiskSignal,
        ProcessSecurityStatus, SecurityEvent, SecurityEventSeverity, SecuritySnapshot,
        ThreatStatus,
    },
};
use infrastructure_auth::{Argon2PasswordHasher, SecureCredentialStore};
use infrastructure_network::{SysinfoNetworkMonitor, read_network_details};
use infrastructure_security::{
    CodeSignatureStatus, LocalSecurityMonitor, ProcessAnomalyReason, ProcessSecurityAnalyzer,
    ProcessSecurityDetail, ProcessSecuritySnapshot, read_firewall_details,
    reset_integrity_baseline,
};
use infrastructure_storage::{
    AppSettingsStore, SqliteAuthRepository, SqliteSecurityEventRepository, database::open_database,
};
use infrastructure_system::{
    PowerSnapshot, PowerSource, SysinfoApplicationResourceMonitor, SysinfoSystemMonitor,
    SystemPowerMonitor, read_hardware_details, read_process_inventory,
};
use presentation::view_models::SystemDashboardViewModel;

#[cfg(target_os = "macos")]
use application::ports::BiometricAuthenticator;

#[cfg(target_os = "macos")]
use infrastructure_auth::MacOsBiometricAuthenticator;

slint::include_modules!();

const SECURITY_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

const PROCESS_ANALYSIS_UPDATE_INTERVAL: Duration = Duration::from_secs(30);

const POWER_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

const NORMAL_SYSTEM_INTERVAL: Duration = Duration::from_secs(1);

const NORMAL_NETWORK_INTERVAL: Duration = Duration::from_secs(2);

const NORMAL_RESOURCE_INTERVAL: Duration = Duration::from_secs(10);

const BATTERY_SYSTEM_INTERVAL: Duration = Duration::from_secs(2);

const BATTERY_NETWORK_INTERVAL: Duration = Duration::from_secs(4);

const BATTERY_RESOURCE_INTERVAL: Duration = Duration::from_secs(20);

const LOW_POWER_SYSTEM_INTERVAL: Duration = Duration::from_secs(3);

const LOW_POWER_NETWORK_INTERVAL: Duration = Duration::from_secs(6);

const LOW_POWER_RESOURCE_INTERVAL: Duration = Duration::from_secs(30);

const BACKGROUND_SYSTEM_INTERVAL: Duration = Duration::from_secs(5);

const BACKGROUND_NETWORK_INTERVAL: Duration = Duration::from_secs(10);

const BACKGROUND_RESOURCE_INTERVAL: Duration = Duration::from_secs(30);

const ACTIVE_LOOP_SLEEP: Duration = Duration::from_secs(1);

const BACKGROUND_LOOP_SLEEP: Duration = Duration::from_secs(2);

const LOW_BATTERY_THRESHOLD_PERCENT: f32 = 30.0;

const HIGH_CPU_THRESHOLD_PERCENT: f32 = 20.0;

const HIGH_MEMORY_THRESHOLD_MB: f64 = 256.0;

const REQUIRED_HIGH_RESOURCE_SAMPLES: u8 = 2;

const NETWORK_HISTORY_SIZE: usize = 36;

const LOG_HISTORY_SIZE: usize = 40;

const MAX_PROCESS_DETAILS_IN_LOG: usize = 3;

const MAX_PROCESS_TABLE_ROWS: usize = 12;

const TERMINAL_HISTORY_SIZE: usize = 24;

const TERMINAL_OUTPUT_LIMIT: usize = 32 * 1024;

const TERMINAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitoringMode {
    Normal,
    Battery,
    LowPower,
}

#[derive(Debug, Clone)]
struct ProcessDetailUi {
    available: bool,
    pid: String,
    name: String,
    path: String,
    sha256: String,
    risk: String,
    status: String,
    signature: String,
    identifier: String,
    team_id: String,
    authorities: String,
    reason: String,
    signals: String,
}

#[derive(Debug, Clone)]
struct ProcessAnalysisUiUpdate {
    checked: String,
    observed: String,
    review: String,
    high: String,
    highest: String,
    table: String,
    detail: ProcessDetailUi,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    observability::initialize();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let database = runtime.block_on(open_database())?;

    let startup_repository = SqliteAuthRepository::new(database.clone());

    let startup_mode = runtime.block_on(DetermineStartupMode::new(startup_repository).execute())?;

    let app = AppWindow::new()?;

    app.set_statusmeldung("".into());

    let settings_store = AppSettingsStore::new(database.clone());

    let animation_enabled = runtime.block_on(settings_store.load_animation_enabled(true))?;

    let auto_lock_minutes = runtime.block_on(settings_store.load_auto_lock_minutes(5))?;

    app.set_animation_aktiv(animation_enabled);

    app.set_auto_lock_minuten(auto_lock_minutes);

    if matches!(startup_mode, StartupMode::Login) {
        let saved_username: Option<String> = runtime.block_on(
            sqlx::query_scalar("SELECT username FROM users ORDER BY id LIMIT 1")
                .fetch_optional(&database),
        )?;

        if let Some(username) = saved_username {
            app.set_benutzername(username.into());
        }
    }

    let monitoring_started = Arc::new(AtomicBool::new(false));

    let window_active = Arc::new(AtomicBool::new(true));

    configure_window_activity(&app, window_active.clone());

    app.set_ansicht(match startup_mode {
        StartupMode::InitialSetup => 0,
        StartupMode::Login => 1,
    });

    configure_initial_setup(
        &app,
        &runtime,
        database.clone(),
        monitoring_started.clone(),
        window_active.clone(),
    );

    configure_password_login(
        &app,
        &runtime,
        database.clone(),
        monitoring_started.clone(),
        window_active.clone(),
    );

    configure_touch_id(
        &app,
        &runtime,
        database.clone(),
        monitoring_started,
        window_active,
    );

    configure_local_terminal(&app);

    configure_network_details(&app);

    configure_hardware_details(&app);

    configure_process_inventory(&app);

    configure_firewall_details(&app);

    configure_security_history(&app, &runtime, database.clone());

    configure_settings_persistence(&app, &runtime, database.clone());

    configure_integrity_baseline_reset(&app);

    configure_password_change(&app, &runtime, database);

    let animation_timer = slint::Timer::default();

    let animation_app = app.as_weak();

    let animation_phase = Rc::new(Cell::new(0.0_f32));

    let animation_phase_for_timer = animation_phase.clone();

    animation_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(50),
        move || {
            let Some(app) = animation_app.upgrade() else {
                return;
            };

            let view = app.get_ansicht();

            if (view != 2 && view != 3) || !app.get_fenster_aktiv() || !app.get_animation_aktiv() {
                return;
            }

            let next_phase = animation_phase_for_timer.get() + 1.5;

            let wrapped_phase = if next_phase >= 10_000.0 {
                0.0
            } else {
                next_phase
            };

            animation_phase_for_timer.set(wrapped_phase);

            app.set_network_3d_phase(wrapped_phase);
        },
    );

    let auto_lock_timer = slint::Timer::default();

    let auto_lock_app = app.as_weak();

    let background_since = Rc::new(Cell::new(None::<Instant>));

    let background_since_for_timer = background_since.clone();

    auto_lock_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(1),
        move || {
            let Some(app) = auto_lock_app.upgrade() else {
                return;
            };

            let view = app.get_ansicht();

            let authenticated_view = matches!(view, 2 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12);

            if !authenticated_view {
                background_since_for_timer.set(None);
                return;
            }

            let minutes = app.get_auto_lock_minuten();

            if minutes <= 0 || app.get_fenster_aktiv() {
                background_since_for_timer.set(None);
                return;
            }

            let since = match background_since_for_timer.get() {
                Some(value) => value,
                None => {
                    let now = Instant::now();

                    background_since_for_timer.set(Some(now));

                    now
                }
            };

            if since.elapsed() >= Duration::from_secs(minutes as u64 * 60) {
                background_since_for_timer.set(None);

                app.set_kennwort("".into());

                app.set_statusmeldung("AEGISGRID WURDE AUTOMATISCH GESPERRT.".into());

                app.set_ansicht(1);
            }
        },
    );

    app.run()?;

    Ok(())
}

fn configure_local_terminal(app: &AppWindow) {
    let history = Arc::new(Mutex::new(VecDeque::<String>::with_capacity(
        TERMINAL_HISTORY_SIZE,
    )));

    let execute_app = app.as_weak();

    let execute_history = history.clone();

    app.on_terminal_ausfuehren(move |command| {
        let command = command.to_string().trim().to_owned();

        if command.is_empty() {
            return;
        }

        if let Some(app) = execute_app.upgrade() {
            app.set_terminal_status("AUSFÜHRUNG...".into());
        }

        let app_weak = execute_app.clone();

        let history = execute_history.clone();

        thread::spawn(move || {
            let result = execute_terminal_command(&command);

            let rendered = {
                let Ok(mut history) = history.lock() else {
                    return;
                };

                if history.len() >= TERMINAL_HISTORY_SIZE {
                    history.pop_front();
                }

                history.push_back(format!("> {}\n{}", command, result,));

                render_terminal_history(&history)
            };

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_terminal_ausgabe(rendered.into());

                app.set_terminal_status("BEREIT".into());
            });
        });
    });

    let clear_app = app.as_weak();

    let clear_history = history;

    app.on_terminal_leeren(move || {
        if let Ok(mut history) = clear_history.lock() {
            history.clear();
        }

        if let Some(app) = clear_app.upgrade() {
            app.set_terminal_ausgabe("AEGISGRID TERMINAL BEREIT".into());

            app.set_terminal_status("BEREIT".into());
        }
    });
}

fn configure_network_details(app: &AppWindow) {
    let app_weak = app.as_weak();

    app.on_netzwerk_details_aktualisieren(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_netzwerk_details_status("AKTUALISIERUNG LÄUFT...".into());
        }

        let app_weak = app_weak.clone();

        thread::spawn(move || {
            let snapshot = read_network_details(80, 80);

            let connections = snapshot.connections_table;

            let ports = snapshot.listening_ports_table;

            let active_count = snapshot.active_connection_count.to_string();

            let port_count = snapshot.listening_port_count.to_string();

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_netzwerk_verbindungen(connections.into());

                app.set_netzwerk_ports(ports.into());

                app.set_netzwerk_verbindungen_anzahl(active_count.into());

                app.set_netzwerk_ports_anzahl(port_count.into());

                app.set_netzwerk_details_status("AKTUALISIERT".into());
            });
        });
    });
}

fn configure_hardware_details(app: &AppWindow) {
    let app_weak = app.as_weak();

    app.on_hardware_details_aktualisieren(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_hardware_status("AKTUALISIERUNG LÄUFT...".into());
        }

        let app_weak = app_weak.clone();

        thread::spawn(move || {
            let snapshot = read_hardware_details();

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_hardware_cpu(snapshot.cpu.into());

                app.set_hardware_cores(snapshot.cores.into());

                app.set_hardware_memory(snapshot.memory.into());

                app.set_hardware_disks(snapshot.disks.into());

                app.set_hardware_sensors(snapshot.sensors.into());

                app.set_hardware_status("AKTUALISIERT".into());
            });
        });
    });
}

fn configure_process_inventory(app: &AppWindow) {
    let app_weak = app.as_weak();

    app.on_prozessliste_aktualisieren(move |query| {
        let query = query.to_string();

        if let Some(app) = app_weak.upgrade() {
            app.set_prozessliste_status("AKTUALISIERUNG LÄUFT...".into());
        }

        let app_weak = app_weak.clone();

        thread::spawn(move || {
            let snapshot = read_process_inventory(&query, 120);

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_prozessliste_gesamt(snapshot.total_count.to_string().into());

                app.set_prozessliste_treffer(snapshot.matched_count.to_string().into());

                app.set_prozessliste_tabelle(snapshot.table.into());

                app.set_prozessliste_status("AKTUALISIERT".into());
            });
        });
    });
}

fn configure_firewall_details(app: &AppWindow) {
    let app_weak = app.as_weak();

    app.on_firewall_details_aktualisieren(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_firewall_details_status("AKTUALISIERUNG LÄUFT...".into());
        }

        let app_weak = app_weak.clone();

        thread::spawn(move || {
            let snapshot = read_firewall_details();

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_firewall_details_zustand(snapshot.status.into());

                app.set_firewall_details_profile(snapshot.profiles.into());

                app.set_firewall_details_regeln(snapshot.rules.into());

                app.set_firewall_details_status("AKTUALISIERT".into());
            });
        });
    });
}

fn configure_security_history(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
) {
    let app_weak = app.as_weak();

    let runtime_handle = runtime.handle().clone();

    app.on_sicherheitsverlauf_aktualisieren(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_sicherheitsverlauf_status("WIRD GELADEN...".into());
        }

        let repository = SqliteSecurityEventRepository::new(database.clone());

        let use_case = ReadRecentSecurityEvents::new(repository);

        let app_weak = app_weak.clone();

        runtime_handle.spawn(async move {
            let result = use_case.execute(120).await;

            let (history, status) = match result {
                Ok(events) => (render_security_events(&events), "AKTUALISIERT"),
                Err(_) => (
                    "SICHERHEITSVERLAUF KONNTE NICHT GELADEN WERDEN".to_owned(),
                    "FEHLER",
                ),
            };

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_sicherheitsverlauf(history.into());

                app.set_sicherheitsverlauf_status(status.into());
            });
        });
    });
}

fn configure_integrity_baseline_reset(app: &AppWindow) {
    let app_weak = app.as_weak();

    app.on_integritaets_basiswert_neu(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_einstellungen_status("NEUER BASISWERT WIRD ERSTELLT...".into());
        }

        let app_weak = app_weak.clone();

        thread::spawn(move || {
            let success = reset_integrity_baseline();

            let _ = app_weak.upgrade_in_event_loop(move |app| {
                app.set_einstellungen_status(if success {
                    "DATEI-INTEGRITÄTS-BASISWERT ERFOLGREICH AKTUALISIERT.".into()
                } else {
                    "BASISWERT KONNTE NICHT AKTUALISIERT WERDEN.".into()
                });
            });
        });
    });
}

fn configure_settings_persistence(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
) {
    let runtime_handle = runtime.handle().clone();

    app.on_einstellungen_geaendert(move |animation_enabled, auto_lock_minutes| {
        let store = AppSettingsStore::new(database.clone());

        runtime_handle.spawn(async move {
            let _ = store.save(animation_enabled, auto_lock_minutes).await;
        });
    });
}

fn configure_password_change(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
) {
    let app_weak = app.as_weak();

    let runtime_handle = runtime.handle().clone();

    app.on_kennwort_aendern(
        move |username, current_password, new_password, confirmation| {
            let username = username.to_string();

            let current_password = current_password.to_string();

            let new_password = new_password.to_string();

            let confirmation = confirmation.to_string();

            let repository = SqliteAuthRepository::new(database.clone());

            let use_case = ChangePassword::new(
                repository,
                SecureCredentialStore,
                Argon2PasswordHasher::new(),
            );

            let app_weak = app_weak.clone();

            runtime_handle.spawn(async move {
                let result = use_case
                    .execute(&username, &current_password, &new_password, &confirmation)
                    .await;

                let _ = app_weak.upgrade_in_event_loop(move |app| match result {
                    Ok(()) => {
                        app.set_aktuelles_kennwort("".into());

                        app.set_neues_kennwort("".into());

                        app.set_neues_kennwort_bestaetigung("".into());

                        app.set_einstellungen_status("KENNWORT ERFOLGREICH GEÄNDERT.".into());
                    }

                    Err(error) => {
                        app.set_einstellungen_status(change_password_error_message(&error).into());
                    }
                });
            });
        },
    );
}

fn execute_terminal_command(command: &str) -> String {
    let mut process = terminal_shell_command(command);

    process.stdout(Stdio::piped());

    process.stderr(Stdio::piped());

    let Ok(mut child) = process.spawn() else {
        return "FEHLER: SHELL KONNTE NICHT GESTARTET WERDEN".to_owned();
    };

    let started = Instant::now();

    let mut timed_out = false;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                return format!("FEHLER: {}", error,);
            }
        }

        if started.elapsed() >= TERMINAL_COMMAND_TIMEOUT {
            timed_out = true;

            let _ = child.kill();

            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            return format!("FEHLER: {}", error,);
        }
    };

    let mut text = String::new();

    let stdout = String::from_utf8_lossy(&output.stdout);

    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stdout.trim().is_empty() {
        text.push_str(stdout.trim_end());
    }

    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }

        text.push_str(stderr.trim_end());
    }

    if timed_out {
        if !text.is_empty() {
            text.push('\n');
        }

        text.push_str("[ABGEBROCHEN: ZEITLIMIT 12 SEKUNDEN]");
    } else if text.is_empty() {
        text.push_str("[BEFEHL ERFOLGREICH // KEINE AUSGABE]");
    }

    truncate_terminal_output(text)
}

#[cfg(target_os = "windows")]
fn terminal_shell_command(command: &str) -> Command {
    let mut shell = Command::new("powershell");

    shell.args(["-NoProfile", "-NonInteractive", "-Command", command]);

    shell
}

#[cfg(not(target_os = "windows"))]
fn terminal_shell_command(command: &str) -> Command {
    let shell_path = if std::path::Path::new("/bin/zsh").exists() {
        "/bin/zsh"
    } else {
        "/bin/sh"
    };

    let mut shell = Command::new(shell_path);

    shell.args(["-lc", command]);

    shell
}

fn truncate_terminal_output(value: String) -> String {
    if value.len() <= TERMINAL_OUTPUT_LIMIT {
        return value;
    }

    let tail = value
        .chars()
        .rev()
        .take(TERMINAL_OUTPUT_LIMIT)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();

    format!("[AUSGABE GEKÜRZT]\n{}", tail,)
}

fn render_terminal_history(history: &VecDeque<String>) -> String {
    if history.is_empty() {
        return "AEGISGRID TERMINAL BEREIT".to_owned();
    }

    truncate_terminal_output(history.iter().cloned().collect::<Vec<_>>().join("\n\n"))
}

fn render_security_events(events: &[SecurityEvent]) -> String {
    if events.is_empty() {
        return "NOCH KEINE SICHERHEITSEREIGNISSE".to_owned();
    }

    events
        .iter()
        .map(|event| {
            format!(
                "[{}] [{}] {}",
                event.occurred_at,
                security_event_severity_text(event.severity,),
                event.message,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn security_event_severity_text(severity: SecurityEventSeverity) -> &'static str {
    match severity {
        SecurityEventSeverity::Info => "INFO",
        SecurityEventSeverity::Warning => "WARNUNG",
        SecurityEventSeverity::Critical => "KRITISCH",
    }
}

fn persist_security_event(
    runtime_handle: &tokio::runtime::Handle,
    database: &sqlx::SqlitePool,
    severity: SecurityEventSeverity,
    message: impl Into<String>,
) {
    let repository = SqliteSecurityEventRepository::new(database.clone());

    let use_case = RecordSecurityEvent::new(repository);

    let message = message.into();

    runtime_handle.spawn(async move {
        let _ = use_case.execute(severity, &message).await;
    });
}

fn configure_window_activity(app: &AppWindow, window_active: Arc<AtomicBool>) {
    app.on_fensteraktivitaet_geaendert(move |active| {
        window_active.store(active, Ordering::Release);
    });
}

fn configure_initial_setup(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
    monitoring_started: Arc<AtomicBool>,
    window_active: Arc<AtomicBool>,
) {
    let app_weak = app.as_weak();

    let runtime_handle = runtime.handle().clone();

    app.on_ersteinrichtung_absenden(move |username, password, password_confirmation| {
        let username = username.to_string();

        let password = password.to_string();

        let password_confirmation = password_confirmation.to_string();

        let repository = SqliteAuthRepository::new(database.clone());

        let use_case = CreateInitialAccount::new(
            repository,
            SecureCredentialStore,
            Argon2PasswordHasher::new(),
        );

        let app_weak = app_weak.clone();

        let monitoring_started = monitoring_started.clone();

        let window_active = window_active.clone();

        let monitoring_runtime_handle = runtime_handle.clone();

        let monitoring_database = database.clone();

        runtime_handle.spawn(async move {
            let result = use_case
                .execute(&username, &password, &password_confirmation)
                .await;

            let _ = app_weak.upgrade_in_event_loop(move |app| match result {
                Ok(_) => {
                    app.set_kennwort("".into());

                    app.set_kennwort_bestaetigung("".into());

                    app.set_statusmeldung("".into());

                    app.set_ansicht(2);

                    start_monitoring_once(
                        &app,
                        monitoring_started,
                        window_active,
                        monitoring_runtime_handle,
                        monitoring_database,
                    );
                }

                Err(error) => {
                    app.set_statusmeldung(setup_error_message(&error).into());
                }
            });
        });
    });
}

fn configure_password_login(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
    monitoring_started: Arc<AtomicBool>,
    window_active: Arc<AtomicBool>,
) {
    let app_weak = app.as_weak();

    let runtime_handle = runtime.handle().clone();

    app.on_anmeldung_absenden(move |username, password| {
        let username = username.to_string();

        let password = password.to_string();

        let repository = SqliteAuthRepository::new(database.clone());

        let use_case = Login::new(
            repository,
            SecureCredentialStore,
            Argon2PasswordHasher::new(),
        );

        let app_weak = app_weak.clone();

        let monitoring_started = monitoring_started.clone();

        let window_active = window_active.clone();

        let monitoring_runtime_handle = runtime_handle.clone();

        let monitoring_database = database.clone();

        runtime_handle.spawn(async move {
            let result = use_case.execute(&username, &password).await;

            let _ = app_weak.upgrade_in_event_loop(move |app| match result {
                Ok(AuthenticationStatus::Authenticated) => {
                    app.set_kennwort("".into());

                    app.set_statusmeldung("".into());

                    app.set_ansicht(2);

                    start_monitoring_once(
                        &app,
                        monitoring_started,
                        window_active,
                        monitoring_runtime_handle,
                        monitoring_database,
                    );
                }

                Ok(AuthenticationStatus::InvalidCredentials) => {
                    app.set_kennwort("".into());

                    app.set_statusmeldung("Benutzername oder Kennwort ist falsch.".into());
                }

                Ok(AuthenticationStatus::Locked) => {
                    app.set_statusmeldung("Die Anmeldung ist vorübergehend gesperrt.".into());
                }

                Err(error) => {
                    app.set_statusmeldung(login_error_message(&error).into());
                }
            });
        });
    });
}

#[cfg(target_os = "macos")]
fn configure_touch_id(
    app: &AppWindow,
    runtime: &tokio::runtime::Runtime,
    database: sqlx::SqlitePool,
    monitoring_started: Arc<AtomicBool>,
    window_active: Arc<AtomicBool>,
) {
    let authenticator = MacOsBiometricAuthenticator;

    let available = runtime
        .block_on(authenticator.is_available())
        .unwrap_or(false);

    app.set_touch_id_verfuegbar(available);

    if !available {
        return;
    }

    let app_weak = app.as_weak();

    let runtime_handle = runtime.handle().clone();

    app.on_touch_id_anmeldung(move || {
        if let Some(app) = app_weak.upgrade() {
            app.set_touch_id_erfolgreich(false);

            app.set_touch_id_status("SICHERER SENSORZUGRIFF WIRD VORBEREITET".into());

            app.set_ansicht(3);
        }

        let app_weak = app_weak.clone();

        let monitoring_started = monitoring_started.clone();

        let window_active = window_active.clone();

        let monitoring_runtime_handle = runtime_handle.clone();

        let monitoring_database = database.clone();

        runtime_handle.spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;

            let status_view = app_weak.clone();

            let _ = status_view.upgrade_in_event_loop(|app| {
                app.set_touch_id_status("WARTE AUF TOUCH-ID-BESTÄTIGUNG".into());
            });

            let authenticator = MacOsBiometricAuthenticator;

            let result = authenticator
                .authenticate("AegisGrid mit Touch ID entsperren")
                .await;

            match result {
                Ok(true) => {
                    let success_view = app_weak.clone();

                    let _ = success_view.upgrade_in_event_loop(|app| {
                        app.set_touch_id_erfolgreich(true);

                        app.set_touch_id_status("IDENTITÄT BESTÄTIGT // ZUGRIFF GEWÄHRT".into());
                    });

                    tokio::time::sleep(Duration::from_millis(1000)).await;

                    let _ = app_weak.upgrade_in_event_loop(move |app| {
                        app.set_kennwort("".into());

                        app.set_statusmeldung("".into());

                        app.set_touch_id_status("".into());

                        app.set_touch_id_erfolgreich(false);

                        app.set_ansicht(2);

                        start_monitoring_once(
                            &app,
                            monitoring_started,
                            window_active,
                            monitoring_runtime_handle,
                            monitoring_database,
                        );
                    });
                }

                Ok(false) => {
                    show_touch_id_error(app_weak, "TOUCH ID WURDE NICHT BESTÄTIGT").await;
                }

                Err(_) => {
                    show_touch_id_error(app_weak, "TOUCH ID KONNTE NICHT VERWENDET WERDEN").await;
                }
            }
        });
    });
}

#[cfg(target_os = "macos")]
async fn show_touch_id_error(app_weak: slint::Weak<AppWindow>, message: &'static str) {
    let error_view = app_weak.clone();

    let _ = error_view.upgrade_in_event_loop(move |app| {
        app.set_touch_id_erfolgreich(false);

        app.set_touch_id_status(message.into());
    });

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let _ = app_weak.upgrade_in_event_loop(|app| {
        app.set_touch_id_status("".into());

        app.set_statusmeldung("Biometrische Anmeldung fehlgeschlagen.".into());

        app.set_ansicht(1);
    });
}

#[cfg(not(target_os = "macos"))]
fn configure_touch_id(
    app: &AppWindow,
    _runtime: &tokio::runtime::Runtime,
    _database: sqlx::SqlitePool,
    _monitoring_started: Arc<AtomicBool>,
    _window_active: Arc<AtomicBool>,
) {
    app.set_touch_id_verfuegbar(false);
}

fn start_monitoring_once(
    app: &AppWindow,
    monitoring_started: Arc<AtomicBool>,
    window_active: Arc<AtomicBool>,
    runtime_handle: tokio::runtime::Handle,
    database: sqlx::SqlitePool,
) {
    if monitoring_started
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let app_weak = app.as_weak();

    thread::spawn(move || {
        let system_monitor = SysinfoSystemMonitor::new();

        let identity = system_monitor.identity();

        let hostname = identity.hostname;

        let operating_system = identity.operating_system;

        let power_monitor = SystemPowerMonitor::new();

        let mut power_snapshot = power_monitor.snapshot();

        let mut resource_warning_active = false;

        let mut monitoring_mode =
            determine_monitoring_mode(power_snapshot, resource_warning_active);

        let mut current_window_active = window_active.load(Ordering::Acquire);

        let mut previous_window_active = current_window_active;

        let mut log_entries = VecDeque::<String>::with_capacity(LOG_HISTORY_SIZE);

        push_log_event(&mut log_entries, "AegisGrid gestartet");

        push_log_event(&mut log_entries, "Systemüberwachung aktiv");

        push_log_event(&mut log_entries, "Netzwerküberwachung aktiv");

        push_log_event(&mut log_entries, "Sicherheitsüberwachung aktiv");

        push_log_event(&mut log_entries, "Eigenverbrauchsüberwachung aktiv");

        push_log_event(&mut log_entries, "Prozess-Sicherheitsanalyse aktiv");

        push_log_event(&mut log_entries, "Code-Signaturprüfung aktiv");

        push_log_event(&mut log_entries, power_status_text(power_snapshot));

        push_log_event(
            &mut log_entries,
            format!("Energiemodus: {}", monitoring_mode_text(monitoring_mode,),),
        );

        let initial_log = render_log(&log_entries);

        if app_weak
            .upgrade_in_event_loop(move |app| {
                app.set_hostname(hostname.into());

                app.set_betriebssystem(operating_system.into());

                app.set_protokoll(initial_log.into());
            })
            .is_err()
        {
            return;
        }

        let mut system_use_case = ReadSystemSnapshot::new(system_monitor);

        let mut network_use_case = ReadNetworkSnapshot::new(SysinfoNetworkMonitor::new());

        let mut security_use_case = ReadSecuritySnapshot::new(LocalSecurityMonitor::new());

        let mut process_analyzer = ProcessSecurityAnalyzer::new();

        let mut resource_monitor = SysinfoApplicationResourceMonitor::new();

        let now = Instant::now();

        let mut last_system_update = now
            .checked_sub(effective_system_interval(
                monitoring_mode,
                current_window_active,
            ))
            .unwrap_or(now);

        let mut last_network_update = now
            .checked_sub(effective_network_interval(
                monitoring_mode,
                current_window_active,
            ))
            .unwrap_or(now);

        let mut last_security_update = now.checked_sub(SECURITY_UPDATE_INTERVAL).unwrap_or(now);

        let mut last_process_analysis_update = now
            .checked_sub(PROCESS_ANALYSIS_UPDATE_INTERVAL)
            .unwrap_or(now);

        let mut last_resource_update = now
            .checked_sub(effective_resource_interval(
                monitoring_mode,
                current_window_active,
            ))
            .unwrap_or(now);

        let mut last_power_update = now;

        let mut download_history = VecDeque::<f64>::with_capacity(NETWORK_HISTORY_SIZE);

        let mut upload_history = VecDeque::<f64>::with_capacity(NETWORK_HISTORY_SIZE);

        let mut cached_security_snapshot: Option<SecuritySnapshot> = None;

        let mut analyzed_process_count = 0_usize;

        let mut suspicious_process_count = 0_usize;

        let mut previous_firewall: Option<FirewallStatus> = None;

        let mut previous_integrity: Option<FileIntegrityStatus> = None;

        let mut previous_threat: Option<ThreatStatus> = None;

        let mut previous_warning_count: Option<usize> = None;

        let mut previous_process_status: Option<ProcessSecurityStatus> = None;

        let mut previous_suspicious_process_count: Option<usize> = None;

        let mut high_resource_samples = 0_u8;

        thread::sleep(Duration::from_millis(500));

        loop {
            let mut log_changed = false;

            let mut security_state_changed = false;

            let mut process_detail_update: Option<ProcessAnalysisUiUpdate> = None;

            current_window_active = window_active.load(Ordering::Acquire);

            if current_window_active != previous_window_active {
                if current_window_active {
                    push_log_event(&mut log_entries, "Fensterstatus: AKTIV // LIVE-MODUS");
                } else {
                    push_log_event(
                        &mut log_entries,
                        "Fensterstatus: HINTERGRUND // MONITORING GEDROSSELT",
                    );
                }

                previous_window_active = current_window_active;

                log_changed = true;
            }

            if last_power_update.elapsed() >= POWER_UPDATE_INTERVAL {
                let new_power_snapshot = power_monitor.snapshot();

                last_power_update = Instant::now();

                if new_power_snapshot.source != power_snapshot.source {
                    push_log_event(&mut log_entries, power_status_text(new_power_snapshot));

                    log_changed = true;
                }

                power_snapshot = new_power_snapshot;

                let new_mode = determine_monitoring_mode(power_snapshot, resource_warning_active);

                if new_mode != monitoring_mode {
                    monitoring_mode = new_mode;

                    push_log_event(
                        &mut log_entries,
                        format!("Energiemodus: {}", monitoring_mode_text(monitoring_mode,),),
                    );

                    log_changed = true;
                }
            }

            let system_update = if last_system_update.elapsed()
                >= effective_system_interval(monitoring_mode, current_window_active)
            {
                let snapshot = system_use_case.execute();

                let view_model = SystemDashboardViewModel::from(snapshot);

                last_system_update = Instant::now();

                let storage_text = if view_model.storage_total_gb > 0.0 {
                    format!(
                        "{:.0} / {:.0} GB",
                        view_model.storage_used_gb, view_model.storage_total_gb,
                    )
                } else {
                    "—".to_owned()
                };

                Some((
                    format!("{:.1} %", view_model.cpu_percent,),
                    format!("{:.1} %", view_model.memory_percent,),
                    storage_text,
                    view_model.process_count.to_string(),
                    Local::now().format("%H:%M:%S").to_string(),
                ))
            } else {
                None
            };

            let network_update = if last_network_update.elapsed()
                >= effective_network_interval(monitoring_mode, current_window_active)
            {
                let snapshot = network_use_case.execute();

                last_network_update = Instant::now();

                push_history_value(&mut download_history, snapshot.download_bytes_per_second);

                push_history_value(&mut upload_history, snapshot.upload_bytes_per_second);

                let maximum = history_maximum(&download_history, &upload_history);

                Some((
                    format_network_rate(snapshot.download_bytes_per_second),
                    format_network_rate(snapshot.upload_bytes_per_second),
                    snapshot.active_connection_count.to_string(),
                    build_graph_path(&download_history, maximum),
                    build_graph_path(&upload_history, maximum),
                    format_network_rate(maximum),
                ))
            } else {
                None
            };

            if last_security_update.elapsed() >= SECURITY_UPDATE_INTERVAL {
                cached_security_snapshot = Some(security_use_case.execute());

                last_security_update = Instant::now();

                security_state_changed = true;
            }

            if last_process_analysis_update.elapsed() >= PROCESS_ANALYSIS_UPDATE_INTERVAL {
                let snapshot = process_analyzer.snapshot();

                last_process_analysis_update = Instant::now();

                analyzed_process_count = snapshot.analyzed_process_count;

                suspicious_process_count = snapshot.suspicious_count();

                let process_table = build_process_review_table(&snapshot);

                let process_detail = build_process_detail_ui(&snapshot);

                process_detail_update = Some(ProcessAnalysisUiUpdate {
                    checked: snapshot.analyzed_process_count.to_string(),

                    observed: snapshot.observed_count().to_string(),

                    review: snapshot.review_recommended_count().to_string(),

                    high: snapshot.high_anomaly_count().to_string(),

                    highest: format!("{}/100", snapshot.highest_risk_score(),),

                    table: process_table,

                    detail: process_detail,
                });

                security_state_changed = true;

                if previous_suspicious_process_count.is_none() {
                    push_log_event(
                        &mut log_entries,
                        format!(
                            "Prozessanalyse: {} Prozesse geprüft // {} auffällig // höchstes Risiko {}/100",
                            analyzed_process_count,
                            suspicious_process_count,
                            snapshot.highest_risk_score(),
                        ),
                    );

                    if suspicious_process_count > 0 {
                        persist_security_event(
                            &runtime_handle,
                            &database,
                            SecurityEventSeverity::Warning,
                            format!(
                                "Prozessanalyse: {} auffällig // höchstes Risiko {}/100",
                                suspicious_process_count,
                                snapshot.highest_risk_score(),
                            ),
                        );
                    }

                    log_changed = true;
                } else if previous_suspicious_process_count != Some(suspicious_process_count) {
                    push_log_event(
                        &mut log_entries,
                        format!(
                            "Prozessanalyse geändert: {} auffällig // höchstes Risiko {}/100",
                            suspicious_process_count,
                            snapshot.highest_risk_score(),
                        ),
                    );

                    persist_security_event(
                        &runtime_handle,
                        &database,
                        if suspicious_process_count > 0 {
                            SecurityEventSeverity::Warning
                        } else {
                            SecurityEventSeverity::Info
                        },
                        format!(
                            "Prozessanalyse geändert: {} auffällig // höchstes Risiko {}/100",
                            suspicious_process_count,
                            snapshot.highest_risk_score(),
                        ),
                    );

                    log_changed = true;
                }

                if suspicious_process_count > 0
                    && previous_suspicious_process_count != Some(suspicious_process_count)
                {
                    for suspicious in snapshot
                        .suspicious_processes
                        .iter()
                        .take(MAX_PROCESS_DETAILS_IN_LOG)
                    {
                        push_log_event(
                            &mut log_entries,
                            format!(
                                "PROZESSANOMALIE // PID {} // {} // RISIKO {}/100 // {} // SIGNATUR {} // {}",
                                suspicious.pid,
                                suspicious.name,
                                suspicious.risk_score,
                                process_risk_level_text(suspicious.risk_level,),
                                code_signature_status_text(suspicious.signature_status,),
                                process_anomaly_reason_text(&suspicious.reason,),
                            ),
                        );

                        persist_security_event(
                            &runtime_handle,
                            &database,
                            if suspicious.risk_score >= 80 {
                                SecurityEventSeverity::Critical
                            } else {
                                SecurityEventSeverity::Warning
                            },
                            format!(
                                "Prozessanomalie: PID {} // {} // Risiko {}/100 // Signatur {}",
                                suspicious.pid,
                                suspicious.name,
                                suspicious.risk_score,
                                code_signature_status_text(suspicious.signature_status,),
                            ),
                        );
                    }

                    log_changed = true;
                }

                if suspicious_process_count == 0
                    && previous_suspicious_process_count.is_some_and(|count| count > 0)
                {
                    push_log_event(&mut log_entries, "Prozessanomalien nicht mehr vorhanden");

                    persist_security_event(
                        &runtime_handle,
                        &database,
                        SecurityEventSeverity::Info,
                        "Prozessanomalien nicht mehr vorhanden",
                    );

                    log_changed = true;
                }

                previous_suspicious_process_count = Some(suspicious_process_count);
            }

            let security_update = if security_state_changed {
                cached_security_snapshot.map(|snapshot| {
                    let combined = snapshot.combine_with_process_analysis(
                        analyzed_process_count,
                        suspicious_process_count,
                    );

                    if previous_firewall != Some(combined.firewall_status) {
                        push_log_event(
                            &mut log_entries,
                            format!(
                                "Firewall: {}",
                                firewall_status_text(combined.firewall_status,),
                            ),
                        );

                        persist_security_event(
                            &runtime_handle,
                            &database,
                            match combined.firewall_status {
                                FirewallStatus::Enabled => SecurityEventSeverity::Info,
                                FirewallStatus::Disabled => SecurityEventSeverity::Warning,
                                FirewallStatus::Unknown => SecurityEventSeverity::Warning,
                            },
                            format!(
                                "Firewall: {}",
                                firewall_status_text(combined.firewall_status,),
                            ),
                        );

                        previous_firewall = Some(combined.firewall_status);

                        log_changed = true;
                    }

                    if previous_integrity != Some(combined.file_integrity_status) {
                        push_log_event(
                            &mut log_entries,
                            format!(
                                "Datei-Integrität: {}",
                                file_integrity_status_text(combined.file_integrity_status,),
                            ),
                        );

                        persist_security_event(
                            &runtime_handle,
                            &database,
                            match combined.file_integrity_status {
                                FileIntegrityStatus::Changed | FileIntegrityStatus::Missing => {
                                    SecurityEventSeverity::Critical
                                }
                                FileIntegrityStatus::Unknown => SecurityEventSeverity::Warning,
                                FileIntegrityStatus::BaselineCreated
                                | FileIntegrityStatus::Intact => SecurityEventSeverity::Info,
                            },
                            format!(
                                "Datei-Integrität: {}",
                                file_integrity_status_text(combined.file_integrity_status,),
                            ),
                        );

                        previous_integrity = Some(combined.file_integrity_status);

                        log_changed = true;
                    }

                    if previous_process_status != Some(combined.process_status) {
                        push_log_event(
                            &mut log_entries,
                            format!(
                                "Prozess-Sicherheitsstatus: {}",
                                process_status_text(
                                    combined.process_status,
                                    combined.suspicious_process_count,
                                ),
                            ),
                        );

                        if combined.process_status == ProcessSecurityStatus::ReviewRecommended {
                            persist_security_event(
                                &runtime_handle,
                                &database,
                                SecurityEventSeverity::Warning,
                                format!(
                                    "Prozess-Sicherheitsstatus: {}",
                                    process_status_text(
                                        combined.process_status,
                                        combined.suspicious_process_count,
                                    ),
                                ),
                            );
                        }

                        previous_process_status = Some(combined.process_status);

                        log_changed = true;
                    }

                    if previous_warning_count != Some(combined.warning_count) {
                        push_log_event(
                            &mut log_entries,
                            format!("Sicherheitswarnungen: {}", combined.warning_count,),
                        );

                        if combined.warning_count > 0 {
                            persist_security_event(
                                &runtime_handle,
                                &database,
                                SecurityEventSeverity::Warning,
                                format!("Sicherheitswarnungen: {}", combined.warning_count,),
                            );
                        }

                        previous_warning_count = Some(combined.warning_count);

                        log_changed = true;
                    }

                    if previous_threat != Some(combined.threat_status) {
                        push_log_event(
                            &mut log_entries,
                            format!(
                                "Bedrohungsstatus: {}",
                                threat_status_text(combined.threat_status,),
                            ),
                        );

                        persist_security_event(
                            &runtime_handle,
                            &database,
                            match combined.threat_status {
                                ThreatStatus::BasicProtectionActive => SecurityEventSeverity::Info,
                                ThreatStatus::ProtectionReduced
                                | ThreatStatus::ReviewRecommended => SecurityEventSeverity::Warning,
                                ThreatStatus::IntegrityWarning => SecurityEventSeverity::Critical,
                            },
                            format!(
                                "Bedrohungsstatus: {}",
                                threat_status_text(combined.threat_status,),
                            ),
                        );

                        previous_threat = Some(combined.threat_status);

                        log_changed = true;
                    }

                    (
                        combined.open_port_count.to_string(),
                        firewall_status_text(combined.firewall_status).to_owned(),
                        file_integrity_status_text(combined.file_integrity_status).to_owned(),
                        process_status_text(
                            combined.process_status,
                            combined.suspicious_process_count,
                        ),
                        combined.warning_count.to_string(),
                        threat_status_text(combined.threat_status).to_owned(),
                    )
                })
            } else {
                None
            };

            if last_resource_update.elapsed()
                >= effective_resource_interval(monitoring_mode, current_window_active)
            {
                last_resource_update = Instant::now();

                if let Some(snapshot) = resource_monitor.snapshot() {
                    let memory_mb = snapshot.memory_megabytes();

                    let high_load = snapshot.cpu_percent >= HIGH_CPU_THRESHOLD_PERCENT
                        || memory_mb >= HIGH_MEMORY_THRESHOLD_MB;

                    if high_load {
                        high_resource_samples = high_resource_samples.saturating_add(1);
                    } else {
                        high_resource_samples = 0;
                    }

                    if high_resource_samples >= REQUIRED_HIGH_RESOURCE_SAMPLES
                        && !resource_warning_active
                    {
                        resource_warning_active = true;

                        push_log_event(
                            &mut log_entries,
                            format!(
                                "PERFORMANCE: Eigenverbrauch erhöht // CPU {:.1} % // RAM {:.0} MB",
                                snapshot.cpu_percent, memory_mb,
                            ),
                        );

                        log_changed = true;
                    }

                    if !high_load && resource_warning_active {
                        resource_warning_active = false;

                        push_log_event(
                            &mut log_entries,
                            format!(
                                "PERFORMANCE: Eigenverbrauch wieder normal // CPU {:.1} % // RAM {:.0} MB",
                                snapshot.cpu_percent, memory_mb,
                            ),
                        );

                        log_changed = true;
                    }

                    let new_mode =
                        determine_monitoring_mode(power_snapshot, resource_warning_active);

                    if new_mode != monitoring_mode {
                        monitoring_mode = new_mode;

                        push_log_event(
                            &mut log_entries,
                            format!("Energiemodus: {}", monitoring_mode_text(monitoring_mode,),),
                        );

                        log_changed = true;
                    }
                }
            }

            let log_update = if log_changed {
                Some(render_log(&log_entries))
            } else {
                None
            };

            let update_result = app_weak.upgrade_in_event_loop(move |app| {
                if let Some((cpu, ram, storage, processes, time)) = system_update {
                    app.set_cpu_wert(cpu.into());

                    app.set_ram_wert(ram.into());

                    app.set_speicher_wert(storage.into());

                    app.set_prozesse_wert(processes.into());

                    app.set_systemzeit(time.into());
                }

                if let Some((download, upload, connections, download_path, upload_path, scale)) =
                    network_update
                {
                    app.set_download_wert(download.into());

                    app.set_upload_wert(upload.into());

                    app.set_verbindungen_wert(connections.into());

                    app.set_download_pfad(download_path.into());

                    app.set_upload_pfad(upload_path.into());

                    app.set_netzwerk_skala(scale.into());
                }

                if let Some((
                    open_ports,
                    firewall,
                    integrity,
                    process_status,
                    warning_count,
                    threat_status,
                )) = security_update
                {
                    app.set_offene_ports(open_ports.into());

                    app.set_firewall_status(firewall.into());

                    app.set_datei_integritaet_status(integrity.into());

                    app.set_prozess_status(process_status.into());

                    app.set_sicherheitswarnungen(warning_count.into());

                    app.set_threat_status(threat_status.into());
                }

                if let Some(process_update) = process_detail_update {
                    app.set_prozess_geprueft(process_update.checked.into());

                    app.set_prozess_hinweise(process_update.observed.into());

                    app.set_prozess_pruefung(process_update.review.into());

                    app.set_prozess_hoch(process_update.high.into());

                    app.set_prozess_hoechstes_risiko(process_update.highest.into());

                    app.set_prozess_tabelle(process_update.table.into());

                    app.set_prozess_detail_verfuegbar(process_update.detail.available);

                    app.set_prozess_detail_pid(process_update.detail.pid.into());

                    app.set_prozess_detail_name(process_update.detail.name.into());

                    app.set_prozess_detail_pfad(process_update.detail.path.into());

                    app.set_prozess_detail_sha256(process_update.detail.sha256.into());

                    app.set_prozess_detail_risiko(process_update.detail.risk.into());

                    app.set_prozess_detail_status(process_update.detail.status.into());

                    app.set_prozess_detail_signatur(process_update.detail.signature.into());

                    app.set_prozess_detail_identifier(process_update.detail.identifier.into());

                    app.set_prozess_detail_team_id(process_update.detail.team_id.into());

                    app.set_prozess_detail_authorities(process_update.detail.authorities.into());

                    app.set_prozess_detail_grund(process_update.detail.reason.into());

                    app.set_prozess_detail_signale(process_update.detail.signals.into());
                }

                if let Some(log_text) = log_update {
                    app.set_protokoll(log_text.into());
                }
            });

            if update_result.is_err() {
                break;
            }

            thread::sleep(if current_window_active {
                ACTIVE_LOOP_SLEEP
            } else {
                BACKGROUND_LOOP_SLEEP
            });
        }
    });
}

fn build_process_detail_ui(snapshot: &ProcessSecuritySnapshot) -> ProcessDetailUi {
    let Some(detail) = snapshot.highest_risk_process_detail() else {
        return ProcessDetailUi {
            available: false,

            pid: "—".to_owned(),

            name: "—".to_owned(),

            path: "—".to_owned(),

            sha256: "—".to_owned(),

            risk: "—".to_owned(),

            status: "—".to_owned(),

            signature: "—".to_owned(),

            identifier: "—".to_owned(),

            team_id: "—".to_owned(),

            authorities: "—".to_owned(),

            reason: "—".to_owned(),

            signals: "—".to_owned(),
        };
    };

    ProcessDetailUi {
        available: true,

        pid: detail.pid.to_string(),

        name: detail.name.clone(),

        path: detail.executable_path.to_string_lossy().into_owned(),

        sha256: detail
            .sha256
            .clone()
            .unwrap_or_else(|| "NICHT VERFÜGBAR".to_owned()),

        risk: format!("{}/100", detail.risk_score,),

        status: process_risk_level_text(detail.risk_level).to_owned(),

        signature: code_signature_status_text(detail.signature_status).to_owned(),

        identifier: detail
            .signature_metadata
            .identifier
            .clone()
            .unwrap_or_else(|| "NICHT VORHANDEN".to_owned()),

        team_id: detail
            .signature_metadata
            .team_identifier
            .clone()
            .unwrap_or_else(|| "NICHT VORHANDEN".to_owned()),

        authorities: build_signature_authorities_text(&detail),

        reason: process_anomaly_reason_text(&detail.primary_reason).to_owned(),

        signals: build_process_signal_details(&detail),
    }
}

fn build_signature_authorities_text(detail: &ProcessSecurityDetail) -> String {
    if detail.signature_metadata.authorities.is_empty() {
        return "NICHT VORHANDEN".to_owned();
    }

    detail.signature_metadata.authorities.join("\n")
}

fn build_process_signal_details(detail: &ProcessSecurityDetail) -> String {
    if detail.signals.is_empty() {
        return "KEINE RISIKO-SIGNALE".to_owned();
    }

    let mut output = String::new();

    for signal in &detail.signals {
        if !output.is_empty() {
            output.push('\n');
        }

        output.push_str(&format!(
            "● {}  +{}",
            process_risk_signal_text(signal.signal,),
            signal.score,
        ));
    }

    output
}

fn process_risk_signal_text(signal: ProcessRiskSignal) -> &'static str {
    match signal {
        ProcessRiskSignal::TemporaryDirectory => "TEMPORÄRES VERZEICHNIS",

        ProcessRiskSignal::CacheDirectory => "CACHE-VERZEICHNIS",

        ProcessRiskSignal::DownloadsDirectory => "DOWNLOADS",

        ProcessRiskSignal::UnsignedExecutable => "NICHT SIGNIERTE DATEI",

        ProcessRiskSignal::InvalidSignature => "UNGÜLTIGE CODE-SIGNATUR",

        ProcessRiskSignal::UnusualPermissions => "UNGEWÖHNLICHE DATEIRECHTE",
    }
}

fn build_process_review_table(snapshot: &ProcessSecuritySnapshot) -> String {
    if snapshot.suspicious_processes.is_empty() {
        return "KEINE PROZESSE MIT PRÜFBEDARF".to_owned();
    }

    let mut output = String::new();

    for process in snapshot
        .suspicious_processes
        .iter()
        .take(MAX_PROCESS_TABLE_ROWS)
    {
        let name = truncate_table_text(&process.name, 22);

        let line = format!(
            "{} | {} | {}/100 | {} | {} | {}\n",
            process.pid,
            name,
            process.risk_score,
            code_signature_status_text(process.signature_status,),
            process_anomaly_short_text(&process.reason,),
            process_risk_level_short_text(process.risk_level,),
        );

        output.push_str(&line);
    }

    let remaining = snapshot
        .suspicious_processes
        .len()
        .saturating_sub(MAX_PROCESS_TABLE_ROWS);

    if remaining > 0 {
        output.push_str(&format!("\n+ {} WEITERE PROZESSE", remaining,));
    }

    output
}

fn truncate_table_text(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_owned();
    }

    let keep = maximum.saturating_sub(3);

    let mut result: String = value.chars().take(keep).collect();

    result.push_str("...");

    result
}

fn process_status_text(status: ProcessSecurityStatus, suspicious_count: usize) -> String {
    match status {
        ProcessSecurityStatus::Safe => {
            format!("SICHER // {} AUFFÄLLIG", suspicious_count,)
        }

        ProcessSecurityStatus::ReviewRecommended => {
            format!("PRÜFUNG EMPFOHLEN // {} AUFFÄLLIG", suspicious_count,)
        }

        ProcessSecurityStatus::Unknown => "NOCH NICHT ANALYSIERT".to_owned(),
    }
}

fn process_risk_level_text(level: ProcessRiskLevel) -> &'static str {
    match level {
        ProcessRiskLevel::Safe => "UNAUFFÄLLIG",

        ProcessRiskLevel::Observe => "BEOBACHTEN",

        ProcessRiskLevel::ReviewRecommended => "PRÜFUNG EMPFOHLEN",

        ProcessRiskLevel::HighAnomaly => "HOHE AUFFÄLLIGKEIT",
    }
}

fn process_risk_level_short_text(level: ProcessRiskLevel) -> &'static str {
    match level {
        ProcessRiskLevel::Safe => "OK",

        ProcessRiskLevel::Observe => "BEOBACHTEN",

        ProcessRiskLevel::ReviewRecommended => "PRÜFUNG",

        ProcessRiskLevel::HighAnomaly => "HOCH",
    }
}

fn code_signature_status_text(status: CodeSignatureStatus) -> &'static str {
    match status {
        CodeSignatureStatus::Valid => "GÜLTIG",

        CodeSignatureStatus::Unsigned => "NICHT SIGNIERT",

        CodeSignatureStatus::Invalid => "UNGÜLTIG",

        CodeSignatureStatus::Unknown => "UNBEKANNT",
    }
}

fn process_anomaly_short_text(reason: &ProcessAnomalyReason) -> &'static str {
    match reason {
        ProcessAnomalyReason::TemporaryDirectory => "TEMP",

        ProcessAnomalyReason::CacheDirectory => "CACHE",

        ProcessAnomalyReason::DownloadsDirectory => "DOWNLOADS",
    }
}

fn process_anomaly_reason_text(reason: &ProcessAnomalyReason) -> &'static str {
    match reason {
        ProcessAnomalyReason::TemporaryDirectory => "START AUS TEMPORÄREM VERZEICHNIS",

        ProcessAnomalyReason::CacheDirectory => "START AUS CACHE-VERZEICHNIS",

        ProcessAnomalyReason::DownloadsDirectory => "START AUS DOWNLOADS",
    }
}

fn determine_monitoring_mode(
    power: PowerSnapshot,
    resource_warning_active: bool,
) -> MonitoringMode {
    if resource_warning_active {
        return MonitoringMode::LowPower;
    }

    match power.source {
        PowerSource::Battery => {
            if power
                .battery_percent
                .is_some_and(|percent| percent <= LOW_BATTERY_THRESHOLD_PERCENT)
            {
                MonitoringMode::LowPower
            } else {
                MonitoringMode::Battery
            }
        }

        PowerSource::Ac | PowerSource::Unknown => MonitoringMode::Normal,
    }
}

fn effective_system_interval(mode: MonitoringMode, window_active: bool) -> Duration {
    if !window_active {
        return BACKGROUND_SYSTEM_INTERVAL;
    }

    system_interval(mode)
}

fn effective_network_interval(mode: MonitoringMode, window_active: bool) -> Duration {
    if !window_active {
        return BACKGROUND_NETWORK_INTERVAL;
    }

    network_interval(mode)
}

fn effective_resource_interval(mode: MonitoringMode, window_active: bool) -> Duration {
    if !window_active {
        return BACKGROUND_RESOURCE_INTERVAL;
    }

    resource_interval(mode)
}

fn system_interval(mode: MonitoringMode) -> Duration {
    match mode {
        MonitoringMode::Normal => NORMAL_SYSTEM_INTERVAL,

        MonitoringMode::Battery => BATTERY_SYSTEM_INTERVAL,

        MonitoringMode::LowPower => LOW_POWER_SYSTEM_INTERVAL,
    }
}

fn network_interval(mode: MonitoringMode) -> Duration {
    match mode {
        MonitoringMode::Normal => NORMAL_NETWORK_INTERVAL,

        MonitoringMode::Battery => BATTERY_NETWORK_INTERVAL,

        MonitoringMode::LowPower => LOW_POWER_NETWORK_INTERVAL,
    }
}

fn resource_interval(mode: MonitoringMode) -> Duration {
    match mode {
        MonitoringMode::Normal => NORMAL_RESOURCE_INTERVAL,

        MonitoringMode::Battery => BATTERY_RESOURCE_INTERVAL,

        MonitoringMode::LowPower => LOW_POWER_RESOURCE_INTERVAL,
    }
}

fn monitoring_mode_text(mode: MonitoringMode) -> &'static str {
    match mode {
        MonitoringMode::Normal => "NORMAL",

        MonitoringMode::Battery => "AKKU-SPARMODUS",

        MonitoringMode::LowPower => "LOW-POWER",
    }
}

fn power_status_text(snapshot: PowerSnapshot) -> String {
    match snapshot.source {
        PowerSource::Ac => "Stromversorgung: NETZTEIL".to_owned(),

        PowerSource::Battery => match snapshot.battery_percent {
            Some(percent) => {
                format!("Stromversorgung: AKKU // {:.0} %", percent,)
            }

            None => "Stromversorgung: AKKU".to_owned(),
        },

        PowerSource::Unknown => "Stromversorgung: UNBEKANNT".to_owned(),
    }
}

fn push_log_event(log: &mut VecDeque<String>, message: impl Into<String>) {
    if log.len() == LOG_HISTORY_SIZE {
        log.pop_front();
    }

    let timestamp = Local::now().format("%H:%M:%S").to_string();

    log.push_back(format!("[{}] {}", timestamp, message.into(),));
}

fn render_log(log: &VecDeque<String>) -> String {
    let mut output = String::new();

    for (index, entry) in log.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }

        output.push_str("> ");

        output.push_str(entry);
    }

    output
}

fn firewall_status_text(status: FirewallStatus) -> &'static str {
    match status {
        FirewallStatus::Enabled => "AKTIV",

        FirewallStatus::Disabled => "DEAKTIVIERT",

        FirewallStatus::Unknown => "UNBEKANNT",
    }
}

fn file_integrity_status_text(status: FileIntegrityStatus) -> &'static str {
    match status {
        FileIntegrityStatus::BaselineCreated => "BASISWERT ERSTELLT",

        FileIntegrityStatus::Intact => "INTAKT",

        FileIntegrityStatus::Changed => "ÄNDERUNG ERKANNT",

        FileIntegrityStatus::Missing => "DATEI FEHLT",

        FileIntegrityStatus::Unknown => "UNBEKANNT",
    }
}

fn threat_status_text(status: ThreatStatus) -> &'static str {
    match status {
        ThreatStatus::BasicProtectionActive => "BASISSCHUTZ AKTIV",

        ThreatStatus::ProtectionReduced => "SCHUTZ REDUZIERT",

        ThreatStatus::ReviewRecommended => "PRÜFUNG EMPFOHLEN",

        ThreatStatus::IntegrityWarning => "INTEGRITÄTSWARNUNG",
    }
}

fn push_history_value(history: &mut VecDeque<f64>, value: f64) {
    if history.len() == NETWORK_HISTORY_SIZE {
        history.pop_front();
    }

    history.push_back(value.max(0.0));
}

fn history_maximum(download: &VecDeque<f64>, upload: &VecDeque<f64>) -> f64 {
    download
        .iter()
        .chain(upload.iter())
        .copied()
        .fold(1024.0, f64::max)
}

fn build_graph_path(history: &VecDeque<f64>, maximum: f64) -> String {
    if history.is_empty() {
        return String::new();
    }

    const WIDTH: f64 = 1000.0;

    const HEIGHT: f64 = 300.0;

    let denominator = NETWORK_HISTORY_SIZE.saturating_sub(1).max(1) as f64;

    let mut path = String::with_capacity(history.len() * 24);

    for (index, value) in history.iter().enumerate() {
        let x = index as f64 / denominator * WIDTH;

        let normalized = (value / maximum).clamp(0.0, 1.0);

        let y = HEIGHT - normalized * (HEIGHT - 12.0);

        if index == 0 {
            path.push_str(&format!("M {:.1} {:.1}", x, y,));
        } else {
            path.push_str(&format!(" L {:.1} {:.1}", x, y,));
        }
    }

    path
}

fn format_network_rate(bytes_per_second: f64) -> String {
    const KIB: f64 = 1024.0;

    const MIB: f64 = KIB * 1024.0;

    const GIB: f64 = MIB * 1024.0;

    if bytes_per_second >= GIB {
        format!("{:.2} GB/s", bytes_per_second / GIB,)
    } else if bytes_per_second >= MIB {
        format!("{:.2} MB/s", bytes_per_second / MIB,)
    } else if bytes_per_second >= KIB {
        format!("{:.1} KB/s", bytes_per_second / KIB,)
    } else {
        format!("{:.0} B/s", bytes_per_second.max(0.0,),)
    }
}

fn setup_error_message<R, C, H>(error: &CreateInitialAccountError<R, C, H>) -> &'static str {
    match error {
        CreateInitialAccountError::AlreadyConfigured => "AegisGrid wurde bereits eingerichtet.",

        CreateInitialAccountError::EmptyUsername => "Bitte einen Benutzernamen eingeben.",

        CreateInitialAccountError::UsernameTooLong => "Der Benutzername ist zu lang.",

        CreateInitialAccountError::PasswordTooShort => {
            "Das Kennwort muss mindestens 12 Zeichen haben."
        }

        CreateInitialAccountError::PasswordTooLong => "Das Kennwort ist zu lang.",

        CreateInitialAccountError::PasswordMismatch => "Die Kennwörter stimmen nicht überein.",

        CreateInitialAccountError::Repository(_) => {
            "Das Benutzerkonto konnte nicht gespeichert werden."
        }

        CreateInitialAccountError::CredentialStore(_) => {
            "Der sichere Kennwortspeicher ist nicht verfügbar."
        }

        CreateInitialAccountError::PasswordHash(_) => {
            "Das Kennwort konnte nicht sicher verarbeitet werden."
        }

        CreateInitialAccountError::Rollback { .. } => {
            "Die Einrichtung konnte nicht vollständig zurückgesetzt werden."
        }
    }
}

fn change_password_error_message<R, C, H>(error: &ChangePasswordError<R, C, H>) -> &'static str {
    match error {
        ChangePasswordError::AccountNotFound => "Das Benutzerkonto wurde nicht gefunden.",

        ChangePasswordError::CurrentPasswordInvalid => "Das aktuelle Kennwort ist falsch.",

        ChangePasswordError::NewPasswordTooShort => {
            "Das neue Kennwort muss mindestens 12 Zeichen haben."
        }

        ChangePasswordError::NewPasswordTooLong => "Das neue Kennwort ist zu lang.",

        ChangePasswordError::NewPasswordMismatch => "Die neuen Kennwörter stimmen nicht überein.",

        ChangePasswordError::Repository(_) => "Das neue Kennwort konnte nicht gespeichert werden.",

        ChangePasswordError::CredentialStore(_) => {
            "Der sichere Kennwortspeicher ist nicht verfügbar."
        }

        ChangePasswordError::PasswordHash(_) => {
            "Das Kennwort konnte nicht sicher verarbeitet werden."
        }

        ChangePasswordError::Rollback { .. } => {
            "Die Kennwortänderung konnte nicht vollständig zurückgesetzt werden."
        }
    }
}

fn login_error_message<R, C, H>(error: &LoginError<R, C, H>) -> &'static str {
    match error {
        LoginError::Repository(_) => "Die Benutzerdaten konnten nicht gelesen werden.",

        LoginError::CredentialStore(_) => "Der sichere Kennwortspeicher ist nicht verfügbar.",

        LoginError::PasswordHash(_) => "Die Anmeldung konnte nicht sicher geprüft werden.",
    }
}
