# Security-Modell

## Authentifizierung

- Benutzerkonto wird lokal in SQLite verwaltet.
- Kennwort wird mit Argon2 + zufälligem Salt gehasht.
- Der Hash wird zusätzlich im OS-Keyring gehalten; beim Login müssen DB und Keyring übereinstimmen.
- Nach 5 Fehlversuchen wird der Benutzername für 5 Minuten in-memory gesperrt.
- macOS kann Touch ID über LocalAuthentication nutzen.
- Windows nutzt in dieser Version Benutzername + Kennwort.

## Prozess-Risikoscore

| Signal | Punkte |
|---|---:|
| temporäres Verzeichnis | 30 |
| Cache-Verzeichnis | 15 |
| Downloads-Verzeichnis | 20 |
| Signatur fehlt | 35 |
| Signatur ungültig | 50 |
| ungewöhnliche Dateirechte | 15 |

Score wird bei 100 begrenzt.

| Score | Einstufung |
|---:|---|
| 0–29 | Unauffällig |
| 30–59 | Beobachten |
| 60–79 | Prüfung empfohlen |
| 80–100 | Hohe Auffälligkeit |

Ein Score ist eine technische Heuristik und **kein automatischer Malware-Nachweis**.

## Code-Signaturen

### macOS
- Verifikation: `/usr/bin/codesign --verify --strict`
- Metadaten: `codesign -d --verbose=4`

### Windows
- Verifikation/Metadaten: PowerShell `Get-AuthenticodeSignature`

## Dateiintegrität

Beim ersten Scan wird ein SHA-256-Basiswert der laufenden AegisGrid-Binärdatei im Arbeitsspeicher erzeugt. Spätere Scans vergleichen dagegen. Der Basiswert wird bewusst nicht als unveränderliche externe Vertrauenswurzel dargestellt.

## Datenschutz

AegisGrid sendet in dieser Version keine Security-Daten an einen Cloud-Dienst. Die angezeigten Werte stammen aus lokalen APIs/Tools.
