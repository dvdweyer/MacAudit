# Backlog

Known coverage gaps and unverified areas, as of v0.0.6.

## Verify with the privileged helper (needs a real root run)

The helper and `sudo macaudit` now cover the root-only data below, but none of it has been seen working as root yet: root can't be run unattended from the dev session. Install the helper, run an audit, and check each item.

- [ ] Helper registration and approval flow (Settings › Root access, then System Settings › Login Items & Extensions)
- [ ] A standard (non-admin) account is refused by the helper, and the root-access notes still appear in its report
- [ ] `sfltool dumpbtm` and `profiles show` still work as root under the tightened sandbox (own scratch folders only, no IP networking, exec limited to those two programs)
- [ ] Login and background items: `sfltool dumpbtm` under the helper's no-write sandbox, and the `btmDump` parser on real output (it has only seen synthetic output so far)
- [ ] Device-level profiles: `profiles show -type configuration` as root under the sandbox, and the `configurationProfiles` parser on device-level output
- [ ] Location Services clients (`/var/db/locationd/clients.plist`)
- [ ] Other users' crontabs (`/usr/lib/cron/tabs`)
- [ ] Known Wi-Fi networks (`/Library/Preferences/com.apple.wifi.known-networks.plist`)
- [ ] `/etc/sudoers` and root-only files in `/etc/sudoers.d`
- [ ] Listening ports of root and other users' processes (libproc as root)
- [ ] Code-signing checks of root-only-readable binaries through the helper
- [ ] Per-user TCC database through the helper. It may still be denied: the ProtectedSystem container is not opened by Full Disk Access, and root access is unknown. If denied, the coverage note says so.

## Blocked by macOS 27

- **Per-user TCC grants** (Camera, Microphone, Automation, Files & Folders, …) without root. The user TCC.db lives at `/private/var/containers/Data/ProtectedSystem/<UUID>/Data/Library/Application Support/com.apple.TCC/TCC.db`; Full Disk Access does not open it, and `TCCAccessCopyInformation` needs a private entitlement.
- **Full audit inside a sandbox**: `system_profiler SPiBridgeDataType` returns nothing and `pluginkit -A` is refused in any sandbox, which is why the helper only does root-only reads.

## Heuristic or incomplete

- [ ] **Find My Mac** is inferred from the presence of the Find My token in NVRAM; "Not detected" does not prove it is off.
- [ ] **Bluetooth Sharing** is inferred from a running `OBEXAgent` or the legacy ByHost `com.apple.Bluetooth` `PrefKeyServicesEnabled` key. Where macOS 27 stores the setting is unknown, and the "On" path has not been observed. To verify, turn it on, run an audit, then turn it off.
- [ ] **Staleness thresholds** for XProtect Remediator and Gatekeeper data (180 days, notice) are based on gaps of 112–122 days seen on one Mac. Revisit them when more update history is available.
- [ ] **`sudo macaudit`** runs root-only reads in-process without the helper's sandbox, and audits root's home directory and preferences rather than the invoking user's (`SUDO_USER`).

## Unverified against real output

- [ ] PDF export (app only)
- [ ] App UI, including the new Settings › Root access pane (not exercised by automated tests)
