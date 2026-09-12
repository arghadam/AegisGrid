$ErrorActionPreference = "Stop"

$DataDir = Join-Path $env:LOCALAPPDATA "AegisGrid"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Backup = Join-Path $env:LOCALAPPDATA "AegisGrid-backup-$Stamp"

Write-Host "ACHTUNG: Dieses Skript setzt die lokale AegisGrid-Konfiguration zurück."
Write-Host "AegisGrid muss vorher vollständig beendet sein."

if (Test-Path $DataDir) {
    Move-Item $DataDir $Backup
    Write-Host "Lokale Daten gesichert nach: $Backup"
} else {
    Write-Host "Keine lokalen AegisGrid-Daten gefunden."
}

Write-Host "Der Windows Credential Manager wird absichtlich nicht automatisch bereinigt."
Write-Host "Falls eine erneute Einrichtung wegen eines alten Credentials scheitert, entfernen Sie den AegisGrid-Eintrag manuell im Windows Credential Manager."
Write-Host "Beim nächsten Start beginnt AegisGrid mit der Ersteinrichtung."
