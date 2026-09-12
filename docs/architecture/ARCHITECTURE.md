# Architektur

## Schichten

### Domain
Enthält ausschließlich Fachmodelle: Authentifizierungsstatus, System-/Netzwerk-Snapshots, Security-Status und das Prozess-Risikomodell.

### Application
Definiert Ports (`AuthRepository`, `SystemMonitor`, `NetworkMonitor`, `SecurityMonitor`, Biometrie usw.) und orchestriert Use-Cases. Keine direkte Slint-, SQL-, sysinfo- oder OS-Abhängigkeit.

### Infrastructure
Getrennte Adapter für Auth, Storage, System, Netzwerk und Security. Plattformcode wird mit `cfg(target_os)` isoliert.

### Presentation
Enthält ViewModels und die Slint-Oberfläche. Die UI kennt keine SQL- oder nativen Betriebssystem-APIs.

### apps/desktop
Composition Root. Baut Adapter und Use-Cases zusammen, verbindet sie mit Slint und kontrolliert die Monitoring-Zeitpläne.

## Performance-Regeln

- kein unnötiges Busy-Waiting
- UI-Thread wird nicht mit System-/Security-Scans blockiert
- Prozesse: 30 s Analyseintervall
- Security: 10 s Orchestrierungsintervall; teure Einzelprüfungen intern gecacht
- File-Integrity: 120 s
- Signatur-/Hash-Caches: 300 s
- Netzwerk-/Systemintervalle passen sich Energie- und Fensterstatus an
- 3D-HUD: ca. 20 FPS, nur auf Dashboard/Touch-ID und nur bei aktivem Fenster

## Datenfluss

```text
Slint UI
   ↑
apps/desktop
   ↓
Application Use-Cases
   ↓ Ports
Infrastructure Adapter
   ↓
OS / SQLite / Keyring / sysinfo / netstat
```
