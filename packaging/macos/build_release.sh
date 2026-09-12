#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

APP_NAME="AegisGrid"
BUNDLE_ID="de.aegisgrid.desktop"
VERSION="1.0.0"
DIST="$ROOT/dist/macos"
APP="$DIST/$APP_NAME.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
BINARY="$ROOT/target/release/aegisgrid-desktop"

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo build --release -p aegisgrid-desktop

rm -rf "$APP"
mkdir -p "$MACOS" "$RESOURCES"
cp "$BINARY" "$MACOS/AegisGrid"
chmod +x "$MACOS/AegisGrid"

if [[ -f "$ROOT/assets/biometrics/fingerprint_realistic.png" ]]; then
    cp "$ROOT/assets/biometrics/fingerprint_realistic.png" "$RESOURCES/"
fi

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>de</string>
    <key>CFBundleExecutable</key>
    <string>AegisGrid</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

IDENTITY="${AEGISGRID_CODESIGN_IDENTITY:-}"
if [[ -n "$IDENTITY" ]]; then
    codesign --force --deep --options runtime --timestamp --sign "$IDENTITY" "$APP"
    codesign --verify --deep --strict --verbose=2 "$APP"
else
    # Lokaler Test-Build: ad-hoc signieren, damit das Bundle konsistent ist.
    codesign --force --deep --sign - "$APP"
fi

DMG="$DIST/AegisGrid-${VERSION}.dmg"
rm -f "$DMG"
hdiutil create \
    -volname "AegisGrid ${VERSION}" \
    -srcfolder "$APP" \
    -ov \
    -format UDZO \
    "$DMG"

if [[ -n "${AEGISGRID_NOTARY_PROFILE:-}" && -n "$IDENTITY" ]]; then
    xcrun notarytool submit "$DMG" \
        --keychain-profile "$AEGISGRID_NOTARY_PROFILE" \
        --wait
    xcrun stapler staple "$DMG"
fi

shasum -a 256 "$DMG" > "$DMG.sha256"

echo "macOS App: $APP"
echo "macOS DMG: $DMG"
echo "SHA-256: $DMG.sha256"
