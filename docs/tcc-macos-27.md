# Per-user TCC grants on macOS 27

Investigated 2026-10-18 on macOS 27.0.1 (26A434), a Mac not enrolled in MDM. "Verified" means observed on that Mac; everything else is from the sources listed at the end.

## Summary

Since macOS 27, the per-user privacy grants (Camera, Microphone, Automation, Files & Folders, Photos, Contacts, Calendars, Reminders, …) can't be read on a Mac that isn't MDM-managed. Neither Full Disk Access nor, as far as is known, root gets past it. Apple's replacement, `tccutil list`, only works on MDM-managed Macs. The system TCC.db is still readable with Full Disk Access, so MacAudit still covers the grants stored there.

## What changed

Apple's macOS 27 enterprise release notes (support article 148830) say:

- "Apps can no longer access the local TCC database directly."
- The new `tccutil list` command "can report current privacy authorizations for specified services or apps on managed devices. Refer to `tccutil --info` for more information."

The per-user database moved from `~/Library/Application Support/com.apple.TCC/TCC.db` to:

```
/private/var/containers/Data/ProtectedSystem/<UUID>/Data/Library/Application Support/com.apple.TCC/TCC.db
```

The system database is unchanged at `/Library/Application Support/com.apple.TCC/TCC.db`.

## Findings on this Mac (verified)

**The file**
- The database and its parent directories belong to the user (`drwx------ donald staff`, file `-rw-r--r--`), with no BSD flags and no ACLs.
- `stat` works, but `open`, `ls`, and `xattr` on the container fail with `EPERM` ("Operation not permitted"), even from a process with Full Disk Access.
- So the block is not Unix permissions. It is enforced by the kernel's container protection. Researchers name the private entitlement `com.apple.private.security.protected-system-container` as the gate (not confirmed by Apple).
- The `<UUID>` is not the IOPlatformUUID, and how it is derived is unknown. MacAudit finds the path from the files the user's `tccd` has open (`PrivacyPermissionsCollector.userDatabasePath`, via libproc).

**`tccutil list`**
- `/usr/bin/tccutil` contains a `list` verb:
  - `list -s SERVICE` shows every bundle ID with a record for that service.
  - `list -b BUNDLE_ID` shows every service with a record for that bundle ID.
  - `list -s SERVICE -b BUNDLE_ID` shows whether that pair is granted or denied.
- It reads through tccd with `tcc_server_message_get_authorization_records_by_service` / `_by_identity`. It has the private entitlement `com.apple.private.tcc.manager.access.read` (services `kTCCServiceAll`, `kTCCServiceSystemPolicyAllFiles`).
- It imports `CP_IsEnrolledWithMDMv1` and `CP_DeviceIsEnrolledViaDEP` from ConfigurationProfiles.framework. On this Mac (`profiles status -type enrollment`: no DEP, no MDM), every `list` call prints the reset-only usage text and exits 64.
- Root wouldn't change that, because the check is on enrollment.
- It also refuses to run inside a sandbox (`sandbox_check`, "Operation not permitted from sandbox").
- The output format has not been seen yet.

**What the system TCC.db still holds** (read from a copy with Full Disk Access), as the `access.service` value:

| Service | Shown as |
|---|---|
| `kTCCServiceAccessibility` | Accessibility |
| `kTCCServiceScreenCapture` | Screen Recording |
| `kTCCServiceListenEvent` | Input Monitoring |
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access |
| `kTCCServiceDeveloperTool` | Developer Tools |
| `kTCCServiceEndpointSecurityClient` | Endpoint Security |

**Unified log**
- `tccd` logs every decision as `AUTHREQ_ATTRIBUTION` (who is asking: responsible, accessing and requesting process) and `AUTHREQ_RESULT` (`authValue`, `authReason`). `AUTHREQ_RESULT` doesn't name the service.
- These entries only cover apps that asked recently, and they leave the log within hours.
- They are a record of recent activity, not a list of grants.

## Why Apple locked it down

Apple has not given a reason. This is the researchers' reading, with my inferences marked.

- **Full Disk Access used to mean all user-level permissions.**
  - An app with Full Disk Access could write its own rows into the user TCC.db and restart tccd. It then had Camera, Microphone or Automation without any prompt.
  - Moving the database behind a private entitlement closes that "grant yourself FDA, then write your own TCC rows" path (Reguła; agilenut/dotfiles #110).
- **Attackers did this.**
  - Malware used the technique in the wild; MITRE ATT&CK lists it as T1548.006 (TCC Manipulation).
  - Rows inserted with sqlite produced no Endpoint Security TCC-change event, so security tools didn't see them (oj-sec; Apple Developer Forums).
- **It continues a long pattern.**
  - The system TCC.db went under SIP in macOS Sierra, partly after Dropbox was caught writing itself into it (Kolide).
  - Researchers kept getting Apple's own entitled apps to tamper with the user database for them. Locking it behind an entitlement those apps don't hold ends that whole class (Dowd).
- **Reads are blocked too.**
  - *Inference:* the container protection is all-or-nothing, and the list of grants is itself useful to an attacker: it shows which installed app already has Camera or Automation and is worth hijacking.
  - Apple's replacement is a read-only, record-level SPI used by `tccutil list`.
- **`tccutil list` only works on managed Macs.**
  - Not explained by Apple; FB24881945 asks for it on all Macs.
  - *Inference:* Apple treats a full inventory as something for administrators of managed fleets. On unmanaged Macs, System Settings › Privacy & Security is the place to see grants.

## Ways in, and why each fails

| Approach | Result |
|---|---|
| Read the file with Full Disk Access | `EPERM` (verified) |
| Read it as root (helper or `sudo macaudit`) | Not tested. Expected to fail: the gate is an entitlement, not a uid. Reported access needs SIP disabled. The helper still tries and the coverage note reports the outcome. |
| `TCCAccessCopyInformation`, `tcc_server_message_get_authorization_records_*` | Need `com.apple.private.tcc.*` entitlements. AMFI won't run Developer ID code that claims `com.apple.private.*` entitlements. |
| `tccutil list` | Works only on MDM-managed Macs (verified: refused on this unmanaged Mac) |
| Unified log (`tccd` AUTHREQ entries) | Recent decisions only, short retention, service not named |
| Endpoint Security `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` | Reports changes from then on, not current state. Needs the Apple-approved `com.apple.developer.endpoint-security.client` entitlement and a root daemon. |
| `MDMOverrides.plist` | Only holds profile-managed (PPPC) decisions on managed Macs |
| Reading System Settings through UI scripting | Needs Accessibility, which would trigger a prompt; not allowed for MacAudit |
| SIP disabled | Reported to allow access (Léo Natan, comment on Michael Tsai's post). MacAudit won't depend on it. |

## Implications for MacAudit

- `PrivacyPermissionsCollector` reports the system TCC.db (with Full Disk Access) and marks the per-user part unavailable, with a coverage note.
- When the per-user database can't be read, the section lists a "Review in System Settings" group: one item per user-level permission (`tcc:review:<anchor>`), each with a direct link to its Privacy & Security pane (`x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?<anchor>`). The anchors come from `SecurityPrivacyExtension.appex` (its binary and `TCCServiceList.plist`). `InfrastructureTests.reviewPaneAnchorsExist` checks that they still exist. Screen scraping System Settings was rejected: it would need Accessibility or Screen Recording, would mean operating the window, and the panes don't show every grant (for example, access granted through file pickers).
- Possible addition: on MDM-managed Macs, call `tccutil list -s <service>` (and `-s -b` for granted/denied) through the `AllowedCommand` allowlist. The service names would come from a fixed list. The parser would stay unverified until real output is captured on an enrolled Mac.
- Other tools hit the same wall: osquery/Fleet's `tcc_access` returns only system rows on macOS 27 (fleetdm/fleet #53273).

## Sources

- [Apple: What's new for enterprise in macOS Golden Gate 27](https://support.apple.com/en-us/148830)
- [FB24881945: `tccutil list` unavailable on non-MDM Macs](https://github.com/feedback-assistant/reports/issues/844)
- [fleetdm/fleet #53273: tcc_access table denied access on macOS 27](https://github.com/fleetdm/fleet/issues/53273)
- [Csaba Fitzl on the user TCC.db move](https://x.com/theevilbit/status/2066443202479976461)
- [Rich Dowd: Castles Made of Sand](https://rdowd.com/castles-made-of-sand-the-fragility-of-enforced-privacy-protections/)
- [Wojciech Reguła: Crossing the Golden Gate](https://wojciechregula.blog/post/golden-gate-appdata-protection/)
- [Michael Tsai: Golden Gate Application Support Protection](https://mjtsai.com/blog/2026/07/24/golden-gate-application-support-protection/)
- [agilenut/dotfiles #110](https://github.com/agilenut/dotfiles/pull/110)
- [Blake Crosley: macOS 27 release notes](https://blakecrosley.com/blog/macos-27-release-notes)
- [oj-sec: A Look at macOS TCC Manipulation in the Wild](https://oj-sec.com/blog/20260721/)
- [MITRE ATT&CK T1548.006: TCC Manipulation](https://attack.mitre.org/techniques/T1548/006/)
- [Apple Developer Forums: TCC modify event not sent when TCC.db changed with sqlite](https://origin-devforums.apple.com/forums/thread/792006)
- [Objective-See: Endpoint Security TCC events](https://objective-see.org/blog/blog_0x7F.html)
- [Kolide: macOS Catalina & osquery](https://www.kolide.com/blog/macos-catalina-osquery)
