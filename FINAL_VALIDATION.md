# Final Validation

## Automatisch in der Artefakt-Umgebung geprüft

- alle TOML-Dateien syntaktisch geparst
- alle Rust-/Slint-Dateien auf ausgeglichene Klammern geprüft
- alle Slint-Imports und Bildpfade auf vorhandene Dateien geprüft
- alle Rust-`mod`-Deklarationen auf vorhandene Moduldateien geprüft
- keine leeren Quelldateien
- keine TODO/FIXME/PLACEHOLDER-Markierungen
- ZIP enthält keine `target`-, Datenbank-, `.DS_Store`- oder Git-Artefakte

## Rust-Build

Die Artefakt-Umgebung dieses Chats enthält kein Rust/Cargo. Deshalb muss die endgültige native Kompilierung auf einem Rust-System ausgeführt werden:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

Die im Chat zuvor getesteten Hauptfunktionen (Dashboard, Prozessanalyse, SHA-256, Signatur-Metadaten und 3D-HUD bis zum bestätigten Stand) wurden auf dem macOS-System des Projekts erfolgreich ausgeführt. Die Finalisierung enthält zusätzlich konservative Struktur-, Packaging- und Performance-Bereinigungen.

## macOS Swift runtime / Touch ID

The repository contains `.cargo/config.toml` with the system Swift runtime rpath
(`/usr/lib/swift`) for Apple Silicon and Intel macOS targets. This is required by
the LocalAuthentication bridge so `cargo run` and test binaries can resolve
`libswift_Concurrency.dylib` at runtime.
