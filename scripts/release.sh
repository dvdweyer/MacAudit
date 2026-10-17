#!/bin/zsh
# Builds a Release archive, exports it signed with Developer ID, optionally notarizes it,
# and installs it into /Applications, replacing any previous MacAudit installation.
#
# Usage: scripts/release.sh [--notary-profile NAME] [--skip-install]
#   --notary-profile NAME  notarize and staple using a `xcrun notarytool store-credentials` profile
#   --skip-install         stop after building/exporting
set -euo pipefail

APP_NAME="MacAudit"
BUNDLE_ID="org.afaik.MacAudit"
TEAM_ID="R4J8ZNC9HF"
INSTALL_DIR="/Applications"

notary_profile=""
install=1
while (( $# )); do
    case "$1" in
        --notary-profile) notary_profile="${2:?--notary-profile needs a value}"; shift 2 ;;
        --skip-install) install=0; shift ;;
        -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 64 ;;
    esac
done

root="${0:A:h:h}"
# Outside ~/Documents: iCloud adds extended attributes that make codesign fail.
build="${MACAUDIT_BUILD_DIR:-$HOME/Library/Caches/MacAudit-release}"
build_number="$(date +%Y%m%d%H%M)"
archive="$build/$APP_NAME.xcarchive"
export_dir="$build/export"
app="$export_dir/$APP_NAME.app"

step() { print -P "%B==> $1%b"; }

rm -rf "$archive" "$export_dir"
mkdir -p "$build"

step "Generating Xcode project"
(cd "$root" && xcodegen generate --quiet)

step "Archiving (build $build_number)"
xcodebuild archive \
    -project "$root/$APP_NAME.xcodeproj" -scheme "$APP_NAME" -configuration Release \
    -destination "generic/platform=macOS" \
    -archivePath "$archive" -derivedDataPath "$build/DerivedData" \
    CURRENT_PROJECT_VERSION="$build_number" \
    -quiet

step "Exporting with Developer ID"
cat > "$build/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>developer-id</string>
    <key>teamID</key><string>$TEAM_ID</string>
    <key>signingStyle</key><string>automatic</string>
</dict>
</plist>
EOF
xcodebuild -exportArchive -archivePath "$archive" -exportPath "$export_dir" \
    -exportOptionsPlist "$build/ExportOptions.plist" -quiet

step "Verifying signature"
codesign --verify --deep --strict "$app"
codesign -dvv "$app" 2>&1 | grep -E '^(Authority=Developer ID Application|TeamIdentifier|Runtime)' || true

if [[ -n "$notary_profile" ]]; then
    step "Notarizing"
    zip="$build/$APP_NAME.zip"
    rm -f "$zip"
    ditto -c -k --keepParent "$app" "$zip"
    xcrun notarytool submit "$zip" --keychain-profile "$notary_profile" --wait
    xcrun stapler staple "$app"
    spctl --assess --type execute --verbose "$app"
fi

if (( ! install )); then
    step "Built $app"
    exit 0
fi

target="$INSTALL_DIR/$APP_NAME.app"
step "Installing to $target"

if pgrep -xq "$APP_NAME"; then
    echo "$APP_NAME is running. Quit it and run this script again." >&2
    exit 1
fi
if [[ -e "$target" ]]; then
    existing_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$target/Contents/Info.plist" 2>/dev/null || true)"
    if [[ "$existing_id" != "$BUNDLE_ID" ]]; then
        echo "$target exists but has bundle ID '${existing_id:-unknown}', not $BUNDLE_ID. Not overwriting." >&2
        exit 1
    fi
fi

# Copy next to the target first so the swap is a rename on the same volume.
staging="$INSTALL_DIR/.$APP_NAME.app.installing"
rm -rf "$staging"
ditto "$app" "$staging"
rm -rf "$target"
mv "$staging" "$target"
codesign --verify --deep --strict "$target"

version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$target/Contents/Info.plist")"
step "Installed $APP_NAME $version ($build_number)"
