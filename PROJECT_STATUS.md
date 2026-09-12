# AegisGrid 1.0 – Projektstatus

Stand: 12.09.2026

## Integriert

- Clean Architecture / Rust Workspace
- lokale Ersteinrichtung, Login, Argon2, Keyring
- macOS Touch ID
- manuelle Sperre + Hintergrund-Auto-Sperre
- Kennwortwechsel
- echtes System-/Hardware-Monitoring
- Energie-/Performance-Drosselung
- Live-Netzwerkdurchsatz und Graph
- Netzwerk-Detailansicht mit Sockets, Ports und PID-/Prozesszuordnung
- Prozess-Sicherheitsanalyse mit Risiko 0–100
- Prozessdetail mit SHA-256 und Signatur-Metadaten
- Prozess-Explorer mit Suche
- macOS- und Windows-Code-Signaturprüfung
- ungewöhnliche Unix-Dateirechte
- Firewallstatus + Firewall-Detailansicht
- persistenter Datei-Integritäts-Basiswert
- persistenter Security-Verlauf in SQLite
- lokales interaktives Terminal
- Einstellungen für Animation, Auto-Sperre, Kennwort und Integritätsbasis
- Hardware-/Sensorseite
- eDEX-inspiriertes animiertes 3D-HUD
- macOS `.app/.dmg` Release-Skript
- Windows `.exe/ZIP` Release-Skript
- optionale externe Code-Signierung über eigene Zertifikate
- Recovery-/Reset-Skripte
- CI für macOS und Windows

## Bewusste Sicherheitsgrenzen

- keine Cloud-Dateiuploads
- kein automatisches Killen von Prozessen
- keine erfundenen AI-/Malware-Scores
- kein verstecktes Recovery-Kennwort oder Backdoor
- keine automatische öffentliche Software-Verteilung ohne eigene Signing-/Release-Infrastruktur

## Release-Bezeichnung

Der Quellstand ist als **AegisGrid 1.0** organisiert. Eine öffentliche signierte/notarisierte Distribution kann erst mit den Zertifikaten des tatsächlichen Herausgebers erzeugt werden.
