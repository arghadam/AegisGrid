# AegisGrid 1.0

AegisGrid ist eine native, lokale Cyber-Security-Desktop-Anwendung in **Rust + Slint** für macOS und Windows. Die Oberfläche ist vollständig deutsch und folgt einem dunklen eDEX-/Cyber-HUD-Stil. Sicherheitswerte werden lokal aus dem Betriebssystem gelesen; es werden keine erfundenen Threat-Werte angezeigt.

## Hauptfunktionen

### Anmeldung und Kontoschutz

- Ersteinrichtung mit lokalem Administratorkonto
- Argon2-Kennworthashing
- OS-Keyring/Credential Manager als zusätzlicher sicherer Hash-Speicher
- macOS Touch ID über LocalAuthentication
- Login-Brute-Force-Schutz
- manuelles Sperren
- konfigurierbare Hintergrund-Auto-Sperre
- sicherer Kennwortwechsel
- keine Klartextkennwörter in DB oder Logs

### System und Hardware

- echte CPU-, RAM-, Speicher- und Prozesswerte
- Hardware-/Sensorseite mit CPU, Kernen, RAM und Datenträgern
- Temperaturwerte, wenn das Betriebssystem sie über `sysinfo` freigibt
- Energiequelle Netzteil/Akku
- adaptiver Akku-/Low-Power-/Hintergrundmodus
- Überwachung des AegisGrid-Eigenverbrauchs

### Netzwerk

- echter Download-/Upload-Durchsatz
- Live-Netzwerkgraph
- aktive Socket-Verbindungen
- TCP-/UDP-Portdetails
- PID-/Prozesszuordnung, soweit vom Betriebssystem geliefert
- separate Netzwerk-Detailseite

### Prozess-Sicherheit

- lokale Prozessanalyse mit Risiko 0–100
- temporäre, Cache- und Download-Ausführungspfade
- ungewöhnliche Unix-Dateirechte
- macOS Code-Signaturprüfung über `codesign`
- Windows Authenticode-Prüfung über PowerShell
- SHA-256 des auffälligen Executables
- Signatur-Identifier, Team-ID und Authority/Zertifikatsinformationen
- Prozess-Detailseite
- vollständiger Prozess-Explorer mit Suche nach PID, Name oder Pfad
- keine automatische Prozessbeendigung

### Sicherheitszentrale

- macOS-/Windows-Firewallstatus
- Firewall-Detailansicht mit Profilen/Systemoptionen und Regeln
- offene Ports
- persistenter SHA-256-Dateiintegritäts-Basiswert
- bewusstes Zurücksetzen des Integritäts-Basiswerts in den Einstellungen
- persistenter Security-Verlauf in SQLite
- Warnungs-/Bedrohungsstatus im Dashboard

### eDEX-/Command-Center-Oberfläche

- schwarzes/neongrünes HUD
- Live-Systemprotokoll
- lokales interaktives Terminal
- leichtgewichtiges animiertes 3D-HUD-Netzwerkobjekt
- Scan-Linie, Orbit-Punkte, Radar-Wellen, Parallax-Ebenen, Datenströme und pulsierende Knoten
- Animation ca. 20 FPS und im Hintergrund pausiert
- Animation in den Einstellungen deaktivierbar

## Architektur

```text
AegisGrid/
├── apps/desktop                  # Composition Root / native Desktop-App
├── crates/domain                 # Fachmodelle und Risikologik
├── crates/application            # Ports + Use-Cases
├── crates/infrastructure_auth    # Argon2, Keyring, Touch ID
├── crates/infrastructure_system  # System, Hardware, Energie, Prozesse
├── crates/infrastructure_network # Netzwerk, Sockets, Ports
├── crates/infrastructure_security# Firewall, Integrität, Prozessanalyse
├── crates/infrastructure_storage # SQLite, Settings, Security-History
├── crates/infrastructure_ai      # absichtlich noch ohne Fake-AI
├── crates/observability          # Tracing/Logging
├── crates/presentation           # ViewModels + Slint UI
├── docs
├── packaging
└── scripts
```

Die Domain-Schicht kennt keine Slint-, SQL-, Keyring- oder Betriebssystemdetails. Infrastructure implementiert die Ports der Application-Schicht.

## Voraussetzungen

### macOS

- macOS 13 oder neuer
- Apple Silicon oder Intel Mac
- Rust Stable über `rustup`
- Xcode Command Line Tools

Die `.cargo/config.toml` enthält den Swift-Runtime-RPATH `/usr/lib/swift`, der für die LocalAuthentication-Brücke benötigt wird.

### Windows

- Windows 10/11
- Rust Stable mit MSVC Toolchain
- Visual Studio Build Tools / C++ Build Tools
- PowerShell

## Entwickeln und prüfen

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Start:

```bash
cargo run -p aegisgrid-desktop
```

## Release

### macOS `.app` + `.dmg`

```bash
./packaging/macos/build_release.sh
```

Ohne Developer-ID entsteht ein lokaler ad-hoc-signierter Build. Für öffentliche Distribution müssen eigene Apple-Signing-/Notarisierungsdaten bereitgestellt werden. Details: `RELEASE_CHECKLIST.md`.

### Windows `.exe` + ZIP

```powershell
./packaging/windows/build_release.ps1
```

Optional kann der Release mit einem eigenen PFX-Code-Signing-Zertifikat signiert werden.

## Lokale Daten und Recovery

- macOS: `~/.aegisgrid/`
- Windows: `%LOCALAPPDATA%\AegisGrid\`

Recovery/Reset: `docs/security/RECOVERY.md`.

## Sicherheitsgrenzen

AegisGrid ist ein lokales Monitoring- und Analysewerkzeug. Es ist **kein Cloud-Antivirus**, behauptet keinen Malware-Nachweis ohne belastbare Signale, lädt keine Dateien automatisch hoch und beendet keine Prozesse automatisch. `infrastructure_ai` bleibt absichtlich ohne künstliche Threat-Scores, bis eine echte überprüfbare AI-Funktion angebunden wird.
