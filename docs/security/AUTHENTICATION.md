# Authentifizierung

## Ersteinrichtung
- Benutzername darf nicht leer sein und maximal 64 Zeichen haben.
- Kennwort: mindestens 12 Zeichen, maximal 512 Bytes.
- Bestätigung muss übereinstimmen.

## Speicherung
- SQLite: Benutzername + Argon2-Hash
- OS-Keyring: zweiter Hash-Abgleich
- Klartextkennwort wird nicht gespeichert.

## Touch ID
Nur auf macOS. AegisGrid verwendet die Apple-Policy `DeviceOwnerAuthenticationWithBiometrics`. Die eigentliche biometrische Prüfung erfolgt durch macOS; AegisGrid erhält nur Erfolg/Fehler.
