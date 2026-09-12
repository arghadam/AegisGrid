$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $Root

$Version = "1.0.0"
$Dist = Join-Path $Root "dist\windows"
$Binary = Join-Path $Root "target\release\aegisgrid-desktop.exe"
$ReleaseExe = Join-Path $Dist "AegisGrid.exe"
$Zip = Join-Path $Dist "AegisGrid-$Version-windows-x64.zip"

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo build --release -p aegisgrid-desktop

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Copy-Item $Binary $ReleaseExe -Force

if ($env:AEGISGRID_SIGN_CERT -and $env:AEGISGRID_SIGN_CERT_PASSWORD) {
    $SignTool = (Get-Command signtool.exe -ErrorAction Stop).Source
    & $SignTool sign `
        /f $env:AEGISGRID_SIGN_CERT `
        /p $env:AEGISGRID_SIGN_CERT_PASSWORD `
        /fd SHA256 `
        /tr "http://timestamp.digicert.com" `
        /td SHA256 `
        $ReleaseExe
}

if (Test-Path $Zip) {
    Remove-Item $Zip -Force
}

Compress-Archive -Path $ReleaseExe -DestinationPath $Zip -CompressionLevel Optimal
$Hash = Get-FileHash -Algorithm SHA256 $Zip
$Hash.Hash.ToLowerInvariant() + "  " + (Split-Path $Zip -Leaf) | Set-Content "$Zip.sha256"

Write-Host "Windows EXE: $ReleaseExe"
Write-Host "Windows ZIP: $Zip"
Write-Host "SHA-256: $Zip.sha256"
