#!/usr/bin/env bash
set -euo pipefail

USERNAME="${1:-}"
DATA_DIR="${HOME}/.aegisgrid"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${HOME}/.aegisgrid-backup-${STAMP}"
SERVICE="de.aegisgrid.desktop.password-hash"

echo "ACHTUNG: Dieses Skript setzt die lokale AegisGrid-Konfiguration zurück."
echo "AegisGrid muss vorher vollständig beendet sein."

if [[ -d "$DATA_DIR" ]]; then
    mv "$DATA_DIR" "$BACKUP"
    echo "Lokale Daten gesichert nach: $BACKUP"
else
    echo "Keine lokalen AegisGrid-Daten gefunden."
fi

if [[ "$(uname -s)" == "Darwin" && -n "$USERNAME" ]]; then
    security delete-generic-password -s "$SERVICE" -a "$USERNAME" >/dev/null 2>&1 || true
    echo "Keychain-Eintrag für '$USERNAME' wurde, falls vorhanden, entfernt."
elif [[ "$(uname -s)" == "Darwin" ]]; then
    echo "Keychain wurde nicht verändert. Optional erneut ausführen mit:"
    echo "  ./scripts/reset_local_data.sh <BENUTZERNAME>"
fi

echo "Beim nächsten Start beginnt AegisGrid mit der Ersteinrichtung."
