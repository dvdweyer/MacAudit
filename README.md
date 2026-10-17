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

The script replaces an existing `/Applications/MacAudit.app`. It won't overwrite a bundle there that has a different bundle ID, and it stops if MacAudit is running. It waits up to 30 s for the root helper to exit, and stops if it is still running after that. Build output goes to `~/Library/Caches/MacAudit-release` (override with `MACAUDIT_BUILD_DIR`). The Developer ID signature has a designated requirement that doesn't change between releases. Grant Full Disk Access once to the installed app, and the grant stays valid after each reinstall.

## Permissions

- **Full Disk Access** (System Settings › Privacy & Security): needed for privacy permissions (TCC) and Time Machine's latest backup. The app shows a banner when it doesn't have it. The CLI uses the Full Disk Access grant of your terminal app.
- **Root access** (optional) also covers:
  - login and background items (`sfltool dumpbtm`)
  - Location Services clients
  - other users' crontabs
  - known Wi-Fi networks
  - `/etc/sudoers`
  - device-level profiles
  - listening ports of other users' processes
  - signatures of root-only programs

  In the app, install the privileged helper (MacAudit › Settings, or Audit › Root Access…) and allow it in System Settings › General › Login Items & Extensions. For the CLI, use `sudo macaudit run`.

### Privileged helper

The helper is a launch daemon embedded in the app (`Contents/Library/LaunchDaemons`) and registered with `SMAppService`. The app keeps auditing as you, and only root-only reads go to the helper.

**Who can use it.** Only administrators: members of `admin`, checked for every connection. They could read the same data with `sudo`, so the helper saves them a password but gives no new access. A Release helper only accepts the Developer ID-signed app. Debug builds can be attached with a debugger, so only a Debug helper accepts them. The app only talks to a helper signed by the same team.

**What it can do.** Only the requests in `PrivilegedRequest`, further limited by `PrivilegedPolicy`:
- run two allowlisted commands (`sfltool dumpbtm`, `profiles show`)
- read a fixed set of root-only paths, plus the caller's **own** per-user TCC database (found from the files that user's `tccd` has open)
- list two directories
- check code signatures in system and app locations, `/Users/Shared`, temporary folders and the caller's home (not other users' homes)
- list listening sockets

Paths are resolved with `realpath` before checking, so `..` and symlinks can't get around the list.

**Enforced by macOS.** At startup the helper puts itself in a sandbox, and the commands it runs inherit it:
- writes are allowed only in its own temporary and cache folders;
- IP networking is blocked;
- only the two allowlisted commands can be launched.

The helper refuses to start if the sandbox can't be applied. It exits ten seconds after the last connection closes (or after starting, if no connection was accepted), and launchd starts it again when needed.

Other users' crontabs are recorded as schedule and program only; arguments can contain credentials. Snapshots are stored with permissions 0600 in a 0700 folder.

`sudo macaudit` runs the same root-only reads in-process, without the sandbox.

## CLI

```sh
macaudit sections
macaudit run [--format text|json|html] [-o FILE] [--sections security,network] [--save-snapshot]
macaudit diff old.json new.json
```
