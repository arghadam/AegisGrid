# AegisGrid 1.0 – Release-Checkliste

## Vor jedem Release

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- Setup/Login testen
- macOS Touch ID testen
- Sperren und Auto-Sperre testen
- Passwortwechsel testen
- Dashboard/Systemwerte testen
- Netzwerkdetails und offene Ports testen
- Prozessanalyse + Prozess-Explorer testen
- Firewall-Detailseite testen
- Datei-Integritäts-Basiswert testen
- Security-Verlauf testen
- Hardware-/Sensoransicht testen
- lokales Terminal testen
- 3D-HUD mit Animation AN/AUS testen
- Hintergrunddrosselung und Eigenverbrauch prüfen

## macOS

```bash
./packaging/macos/build_release.sh
```

Ohne `AEGISGRID_CODESIGN_IDENTITY` wird ein lokaler ad-hoc-signierter Build erzeugt.
Für Distribution außerhalb des eigenen Macs ist eine gültige Apple Developer-ID nötig.
Optional kann ein `AEGISGRID_NOTARY_PROFILE` für `notarytool` gesetzt werden.

## Windows

```powershell
./packaging/windows/build_release.ps1
```

Optional kann eine PFX-Datei über `AEGISGRID_SIGN_CERT` und das Kennwort über
`AEGISGRID_SIGN_CERT_PASSWORD` bereitgestellt werden.

## Keine falschen Release-Aussagen

Ohne eigene Apple-/Windows-Signaturzertifikate ist AegisGrid nicht offiziell signiert oder notarisiert.
Die lokale Sicherheitsanalyse ist kein Cloud-Antivirus und beendet keine Prozesse automatisch.
