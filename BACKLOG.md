# Backlog

Known coverage gaps and unverified areas, as of v0.0.4.

## Blocked by macOS 27 (even with Full Disk Access)

- **Per-user TCC grants** (Camera, Microphone, Automation, Files & Folders, …). The user TCC.db moved to `/private/var/containers/Data/ProtectedSystem/<UUID>/Data/Library/Application Support/com.apple.TCC/TCC.db`; reads fail with "Operation not permitted". `TCCAccessCopyInformation` is refused without a private entitlement. Only system-scope grants (Full Disk Access, Accessibility, Screen Recording, …) are shown.
  - [ ] Check whether root can read it (`sudo head -c 16 <path> | xxd`); if so, change the coverage note to "requires root".
- **Listening sockets of other users' and root processes.** The kernel returns an empty `net.inet.*.pcblist_n` to non-Apple processes (and to `netstat` spawned by them). The libproc fallback only sees the current user's processes without root.

## Requires root

The app runs as the user, so these are reported as partial; `sudo macaudit run` covers them.

- [ ] Login and background items (`sfltool dumpbtm`)
- [ ] Location Services clients (`/var/db/locationd/clients.plist`)
- [ ] Other users' crontabs
- [ ] Known Wi-Fi networks
- [ ] `/etc/sudoers` (files in `/etc/sudoers.d` are read)
- [ ] Device-level configuration profiles
- [ ] Code-signing checks of root-only-readable binaries (reported as "not readable without root", not flagged)

## Heuristic or incomplete

- [ ] **Find My Mac** is inferred from the presence of the Find My token in NVRAM; "Not detected" does not prove it is off.
- [ ] **Bluetooth Sharing** is inferred from a running `OBEXAgent` or the legacy ByHost `com.apple.Bluetooth` `PrefKeyServicesEnabled` key. Where macOS 27 stores the setting is unknown; the "On" path has not been observed. Verify by turning it on, auditing, and turning it off.
- [ ] **Staleness** is only flagged for XProtect signatures, not for XProtect Remediator or Gatekeeper configuration data.

## Unverified against real output

- [ ] `sfltool dumpbtm` parser (needs root; tested only with synthetic output)
- [ ] Device-level `profiles show` parser (needs root; tested only with synthetic output)
- [ ] PDF export (app only)
- [ ] App UI (not exercised by automated tests)
