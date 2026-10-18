# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

MacAudit is a **strictly read-only** security/configuration audit for macOS 26+ (primary target macOS 27): a Swift package `AuditKit` (engine, collectors, reports, `macaudit` CLI) plus a SwiftUI app. Not sandboxed, not for the App Store.

## Commands

The repo lives in an iCloud-synced folder; build products inside it pick up extended attributes and codesign fails ("resource fork, Finder information, or similar detritus"). Always put build output elsewhere.

```sh
# Package (run in AuditKit/)
swift build --scratch-path /tmp/macaudit-build
swift test  --scratch-path /tmp/macaudit-build                      # plain unit tests, no host app
swift test  --scratch-path /tmp/macaudit-build --filter ParserTests/firewallApps   # single test
/tmp/macaudit-build/debug/macaudit run --format json [--sections security,network]

# App (MacAudit.xcodeproj is generated and git-ignored; edit project.yml, not the project)
xcodegen generate
xcodebuild -project MacAudit.xcodeproj -scheme MacAudit -derivedDataPath /tmp/macaudit-dd build

# Release: archive, Developer ID export, optional notarization, install into /Applications
scripts/release.sh [--notary-profile NAME] [--skip-install]
```

Versioning: `MARKETING_VERSION` (project-level settings in `project.yml`, shared by app and helper) and `AuditEngine.toolVersion` in `Engine/Engine.swift` must match. Bump only when app/package code changes (not for scripts/docs); tags are `vX.Y.Z` on the commit that carries the version.

## Architecture

- **Collectors** (`Sources/AuditKit/Collectors/`, one per report section) conform to `Collector` and fill a `SectionResult` via `collect(into:context:)`. Registration is the `AuditEngine.allCollectors` list; the engine runs them concurrently in a TaskGroup.
- **SectionResult helpers** (`Engine/Engine.swift`): `run(_:context:expectNonZeroExit:)` executes an allowlisted command, records it as a data source and degrades `Coverage` on failure; `note(file:)`/`note(api:)` record other sources; `add(_:)` appends an `AuditItem`. Every section must report its data sources and set coverage to `.partial`/`.unavailable` with a reason when root or Full Disk Access is missing — never silently omit data.
- **AuditItem ids are stable keys** (e.g. `tcc:<service>:<client>`, `firewall:app:<path>`); `ReportDiff` matches snapshots by id, so don't put volatile values in ids.
- **Findings** carry a `Severity` (info/notice/warning/critical) and a rationale. Keep false positives down: Apple defaults, Safari web apps, TestFlight builds and root-unreadable files (`SigningInfo.Status.unreadable`) are deliberately not flagged.
- **Parsing is separated from I/O**: parsers are pure `static func`s in `extension Parsers` next to each collector, tested in `Tests/AuditKitTests/ParserTests.swift` against captured real output. Add a fixture test when changing a parser.
- **Root access** (`Infra/Privileged.swift`, `Infra/PrivilegedHelper.swift`, `MacAuditHelper/`): collectors never check for root themselves. They use `context.privileged` (`section.runPrivileged`, `section.readPrivileged`, `privileged.listDirectory/listeningSockets`), and `CodeSignInspector` falls back to it for unreadable files. It is `LocalPrivilegedAccess` when the process is root (CLI under sudo), `XPCPrivilegedAccess` when the app's SMAppService helper is enabled, otherwise nil (add a coverage note with `Privileges.rootHint`). New root-only reads must be added to `PrivilegedPolicy` (commands/paths). Requests are checked against the `PrivilegedCaller` (the helper only accepts admins, and limits TCC.db and signing paths to the caller). The helper's sandbox only allows writes in its own scratch folders and running `PrivilegedService.executables`, so a new privileged command needs no other change. The audit itself always runs as the user, so per-user preferences stay correct. Running everything in the sandboxed helper isn't possible because `system_profiler SPiBridgeDataType` and `pluginkit -A` return nothing inside any sandbox.
- **Infra**: `CodeSignInspector` (actor, SecStaticCode: Apple/App Store/Developer ID/notarized/TestFlight/ad-hoc), `PlistReader`, `SQLiteSnapshotReader`, `DirectoryService` (OpenDirectory), `ProcSockets` (libproc), `Privileges` (root / FDA detection).
- **Reports** (`Report/`): JSON (sorted keys, ISO-8601, `schemaVersion`), self-contained HTML, text, `ReportDiff`, `SnapshotStore` (`~/Library/Application Support/MacAudit/Snapshots`). The app makes PDF from the HTML via an offscreen WKWebView.

## Read-only rules (do not break)

- External programs only via the `AllowedCommand` enum in `Infra/CommandRunner.swift`: absolute Apple binary paths, fixed arguments, no shell, scrubbed env, timeout, output cap. The only dynamic arguments are validated identifiers (`isValidUserName`). New cases must also be added to the manual `allCases` list; `InfrastructureTests.allowlistIsReadOnly` rejects mutating verbs.
- SQLite databases (TCC.db etc.) are never opened in place: `SQLiteSnapshotReader` copies db/-wal/-shm to a temp dir and opens the copy read-only.
- No APIs that trigger privacy (TCC) prompts — Contacts, Location, Bluetooth, Apple Events, Accessibility, etc. Only Full Disk Access, granted manually by the user.
- The only writes are user-chosen exports and the snapshot store.

## Platform gotchas

- On macOS 27 the kernel returns an empty `net.inet.*.pcblist_n` to non-Apple processes and to Apple tools they spawn (`netstat` sees no sockets). `NetworkCollector` falls back to `ProcSockets` (libproc), which only sees the current user's processes unless run as root.
- On macOS 27 the per-user TCC.db is no longer in `~/Library/Application Support/com.apple.TCC/`; it lives in `/private/var/containers/Data/ProtectedSystem/<UUID>/Data/Library/Application Support/com.apple.TCC/TCC.db`, which Full Disk Access does not unlock. `PrivacyPermissionsCollector.userDatabasePath` finds it via the user's tccd open files; Full Disk Access detection (`Privileges.hasFullDiskAccess`) probes the system TCC.db instead. Per-user grants (Camera, Microphone, Automation, Files & Folders, …) can't be read on Macs without MDM. Apple did this on purpose: Full Disk Access used to let any app write its own grants, and the container is now gated by a private entitlement that root is not expected to bypass. The only replacement, `tccutil list`, works only on MDM-enrolled Macs. The system TCC.db (Accessibility, Screen Recording, Input Monitoring, Full Disk Access) is still readable with Full Disk Access. Don't spend time looking for workarounds; details and sources are in `docs/tcc-macos-27.md`.
- Root-only data (`sfltool dumpbtm`, Location Services, other users' crontabs, Wi-Fi networks, `/etc/sudoers`, device profiles) is covered only when the CLI runs under `sudo`.
- Signing: team `R4J8ZNC9HF`, bundle id `org.afaik.MacAudit`, hardened runtime. A stable team signature is required so the Full Disk Access grant survives rebuilds — don't switch to ad-hoc signing.
