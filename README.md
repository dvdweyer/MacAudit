# MacAudit

Read-only security and configuration audit for macOS 26+.

- `AuditKit/` — Swift package: audit engine, 15 collectors, JSON/HTML/text reports, snapshot diff, and the `macaudit` CLI.
- `MacAudit/` — SwiftUI app (generated project: `xcodegen generate`).

## Read-only guarantees

- External programs come only from `AllowedCommand` (`AuditKit/Sources/AuditKit/Infra/CommandRunner.swift`): Apple binaries on the sealed system volume with fixed arguments, run without a shell. `InfrastructureTests.allowlistIsReadOnly` rejects any mutating verb.
- SQLite databases (TCC) are copied to a private temporary directory, and only the copy is opened.
- No APIs that trigger privacy prompts. Full Disk Access is granted manually.
- The only files written are exports you choose and snapshots in `~/Library/Application Support/MacAudit/Snapshots`.

## Build

```sh
xcodegen generate
xcodebuild -project MacAudit.xcodeproj -scheme MacAudit build

cd AuditKit
swift build -c release            # CLI at .build/release/macaudit
swift test --scratch-path /tmp/macaudit-build   # use a build dir outside iCloud-synced folders
```

If the project lives in an iCloud-synced folder, put `.build` somewhere else. Otherwise codesign fails with "resource fork, Finder information, or similar detritus not allowed".

## Release and install

```sh
scripts/release.sh                              # archive, Developer ID export, install to /Applications
scripts/release.sh --notary-profile NAME        # also notarize and staple (profile from `xcrun notarytool store-credentials`)
scripts/release.sh --skip-install               # build only
```

The script replaces an existing `/Applications/MacAudit.app`. It won't overwrite a bundle there that has a different bundle ID, and it stops if MacAudit is running. Build output goes to `~/Library/Caches/MacAudit-release` (override with `MACAUDIT_BUILD_DIR`). The Developer ID signature has a designated requirement that doesn't change between releases. Grant Full Disk Access once to the installed app, and the grant stays valid after each reinstall.

## Permissions

- **Full Disk Access** (System Settings › Privacy & Security): needed for privacy permissions (TCC) and Time Machine's latest backup. The app shows a banner when it doesn't have it. The CLI uses the Full Disk Access grant of your terminal app.
- **root** (`sudo macaudit run`) also covers Login/background items (`sfltool dumpbtm`), Location Services clients, other users' crontabs, known Wi-Fi networks, `/etc/sudoers` and device-level profiles.

## CLI

```sh
macaudit sections
macaudit run [--format text|json|html] [-o FILE] [--sections security,network] [--save-snapshot]
macaudit diff old.json new.json
```
