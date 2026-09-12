# Recovery und lokaler Reset

AegisGrid speichert seine Daten bewusst lokal.

## macOS

- SQLite, Einstellungen und Integritätsbasis: `~/.aegisgrid/`
- Kennworthash zusätzlich im macOS Keychain unter dem Service
  `de.aegisgrid.desktop.password-hash`

Sicherer Reset mit Backup:

```bash
./scripts/reset_local_data.sh <BENUTZERNAME>
```

Der bisherige Datenordner wird zuerst nach `~/.aegisgrid-backup-<Zeitstempel>` verschoben.

## Windows

- SQLite, Einstellungen und Integritätsbasis: `%LOCALAPPDATA%\AegisGrid\`
- Kennworthash zusätzlich im Windows Credential Manager

```powershell
./scripts/reset_local_data.ps1
```

Das Skript sichert den lokalen Datenordner. Credentials werden auf Windows bewusst nicht automatisch gelöscht.

## Kennwort vergessen

AegisGrid enthält absichtlich keine Hintertür und kein wiederherstellbares Klartextkennwort.
Wenn das Kennwort verloren ist und keine funktionierende biometrische Anmeldung verfügbar ist,
muss ein lokaler Reset durchgeführt und ein neues Konto eingerichtet werden.
