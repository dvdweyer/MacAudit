import Foundation
import CoreServices

public struct PrivacyPermissionsCollector: Collector {
    public let id = "privacy"
    public let title = "Privacy Permissions"
    public let symbol = "hand.raised"

    public init() {}

    static let systemDB = "/Library/Application Support/com.apple.TCC/TCC.db"
    static let mdmOverrides = "/Library/Application Support/com.apple.TCC/MDMOverrides.plist"
    static let locationClients = "/var/db/locationd/clients.plist"
    static let protectedContainers = "/private/var/containers/Data/ProtectedSystem/"

    /// macOS 27 moved the per-user database from ~/Library into a ProtectedSystem container with a per-install UUID.
    /// The path is taken from the files the user's own tccd has open.
    static func userDatabasePath(home: String) -> String {
        let legacy = home + "/Library/Application Support/com.apple.TCC/TCC.db"
        if FileManager.default.fileExists(atPath: legacy) { return legacy }
        return tccdDatabase(uid: getuid()) ?? legacy
    }

    /// The per-user TCC database held open by that user's tccd.
    static func tccdDatabase(uid: uid_t) -> String? {
        ProcFiles.pids(named: "tccd", uid: uid).flatMap(ProcFiles.openPaths)
            .first { $0.hasSuffix("/com.apple.TCC/TCC.db") && $0 != systemDB }
    }

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let userDB = Self.userDatabasePath(home: context.homeDirectory)
        var unreadable: [String] = []
        for (scope, path) in [("User", userDB), ("System", Self.systemDB)] {
            section.note(file: path)
            let rows: [[String: SQLValue]]
            do {
                rows = try SQLiteSnapshotReader.query(databaseAt: path, sql: "SELECT * FROM access")
            } catch {
                guard let privileged = context.privileged, let main = try? await privileged.readFile(path) else {
                    unreadable.append(scope.lowercased())
                    continue
                }
                section.note(file: path + " (as root)")
                var files = ["": main]
                for suffix in ["-wal", "-shm"] {
                    files[suffix] = try? await privileged.readFile(path + suffix)
                }
                guard let snapshotRows = try? SQLiteSnapshotReader.query(snapshot: files, sql: "SELECT * FROM access") else {
                    unreadable.append(scope.lowercased())
                    continue
                }
                rows = snapshotRows
            }
            for row in rows {
                guard let entry = TCCEntry(row: row, scope: scope) else { continue }
                section.add(await item(for: entry, context: context))
            }
        }

        if !unreadable.isEmpty {
            let hint = if !context.hasFullDiskAccess {
                " Grant Full Disk Access in System Settings › Privacy & Security."
            } else if unreadable == ["user"], userDB.hasPrefix(Self.protectedContainers) {
                " Since macOS 27 the per-user database lives in a protected system container that Full Disk Access does not unlock"
                    + (context.privileged != nil ? " (not even as root)" : "")
                    + ", so user-level grants (Camera, Microphone, Automation, Files & Folders, …) are not shown."
            } else {
                ""
            }
            section.coverage.degrade(to: unreadable.count == 2 ? .unavailable : .partial,
                                     "Could not read the \(unreadable.joined(separator: " and ")) TCC database.\(hint)")
        }

        collectMDMOverrides(into: &section)
        await collectLocation(into: &section, context: context)
    }

    private func item(for entry: TCCEntry, context: AuditContext) async -> AuditItem {
        var details: [String: String] = [
            "Service": entry.service,
            "Scope": entry.scope,
            "Client": entry.client,
            "Client type": entry.clientType == 0 ? "Bundle ID" : "Path",
            "Reason": TCCEntry.reasonName(entry.authReason),
        ]
        if let modified = entry.lastModified { details["Last modified"] = modified.auditString }
        if let target = entry.indirectObject, target != "UNUSED" { details["Target"] = target }

        var findings: [Finding] = []
        let path = Self.resolvePath(entry)
        if let path {
            details["Resolved path"] = path
            if entry.isAllowed, TCCEntry.sensitiveServices.contains(entry.service) {
                let signing = await context.signing.inspect(path: path)
                details.merge(signing.details) { a, _ in a }
                if signing.status == .missing {
                    findings.append(Finding(.notice, "Grant for a missing program",
                        rationale: "The client no longer exists at this path. Stale grants can be reused if something is placed there."))
                } else if signing.isUntrusted {
                    findings.append(Finding(.warning, "\(entry.serviceName) granted to untrusted code",
                        rationale: "\(signing.summary). This permission allows broad access to data or input."))
                }
            }
        } else if entry.isAllowed, TCCEntry.sensitiveServices.contains(entry.service), !entry.client.hasPrefix("com.apple.") {
            findings.append(Finding(.info, "Client app not found",
                                    rationale: "No installed application with this bundle identifier was found."))
        }

        let target = entry.indirectObject.flatMap { $0 == "UNUSED" ? nil : " → \($0)" } ?? ""
        return AuditItem(
            id: "tcc:\(entry.scope):\(entry.service):\(entry.client):\(entry.indirectObject ?? "")",
            group: entry.serviceName,
            title: entry.client + target,
            value: TCCEntry.valueName(entry.authValue),
            details: details,
            findings: findings)
    }

    static func resolvePath(_ entry: TCCEntry) -> String? {
        if entry.clientType == 1 { return entry.client }
        guard let urls = LSCopyApplicationURLsForBundleIdentifier(entry.client as CFString, nil)?
            .takeRetainedValue() as? [URL] else { return nil }
        return urls.first?.path
    }

    private func collectMDMOverrides(into section: inout SectionResult) {
        guard let overrides = PlistReader.dictionary(at: Self.mdmOverrides) else { return }
        section.note(file: Self.mdmOverrides)
        for (client, value) in overrides.sorted(by: { $0.key < $1.key }) {
            let services = (value as? [String: Any])?.keys.sorted() ?? []
            section.add(AuditItem(
                id: "tcc:mdm:\(client)", group: "MDM-managed (PPPC)", title: client,
                value: services.map { TCCEntry.displayName($0) }.joined(separator: ", "),
                details: ["Services": services.joined(separator: "\n")]))
        }
    }

    private func collectLocation(into section: inout SectionResult, context: AuditContext) async {
        guard context.privileged != nil else {
            section.coverage.degrade(to: .partial, "Location Services clients: \(Privileges.rootHint).")
            return
        }
        guard let data = await section.readPrivileged(Self.locationClients, context: context),
              let clients = PlistReader.dictionary(from: data) else { return }
        for (key, raw) in clients.sorted(by: { $0.key < $1.key }) {
            guard let d = raw as? [String: Any] else { continue }
            let auth = d["Authorization"] as? Int ?? 0
            let name = d["BundleId"] as? String ?? d["Executable"] as? String ?? key
            let value = switch auth {
            case 2: "Always"
            case 4: "While using"
            case 1: "Denied"
            default: "Not determined (\(auth))"
            }
            section.add(AuditItem(id: "tcc:location:\(key)", group: "Location Services", title: name, value: value,
                                  details: ["Executable": d["Executable"] as? String ?? ""]))
        }
    }
}

struct TCCEntry {
    var scope: String
    var service: String
    var client: String
    var clientType: Int64
    var authValue: Int64
    var authReason: Int64
    var indirectObject: String?
    var lastModified: Date?

    init?(row: [String: SQLValue], scope: String) {
        guard let service = row["service"]?.string, let client = row["client"]?.string else { return nil }
        self.scope = scope
        self.service = service
        self.client = client
        clientType = row["client_type"]?.int ?? 0
        // Pre-Big Sur schemas used a boolean `allowed` column.
        authValue = row["auth_value"]?.int ?? ((row["allowed"]?.int ?? 0) == 1 ? 2 : 0)
        authReason = row["auth_reason"]?.int ?? 0
        indirectObject = row["indirect_object_identifier"]?.string
        lastModified = row["last_modified"]?.int.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    var isAllowed: Bool { authValue == 2 || authValue == 3 }
    var serviceName: String { Self.displayName(service) }

    static let sensitiveServices: Set<String> = [
        "kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility", "kTCCServiceScreenCapture",
        "kTCCServiceListenEvent", "kTCCServicePostEvent", "kTCCServiceSystemPolicySysAdminFiles",
        "kTCCServiceSystemPolicyAppBundles", "kTCCServiceSystemPolicyAppData", "kTCCServiceEndpointSecurityClient",
        "kTCCServiceRemoteDesktop", "kTCCServiceDeveloperTool", "kTCCServiceAppleEvents",
        "kTCCServiceCamera", "kTCCServiceMicrophone",
    ]

    static let names: [String: String] = [
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceScreenCapture": "Screen & System Audio Recording",
        "kTCCServiceAudioCapture": "System Audio Recording",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Accessibility (synthetic events)",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceAddressBook": "Contacts",
        "kTCCServiceCalendar": "Calendars",
        "kTCCServiceReminders": "Reminders",
        "kTCCServicePhotos": "Photos",
        "kTCCServicePhotosAdd": "Photos (add only)",
        "kTCCServiceMediaLibrary": "Media & Apple Music",
        "kTCCServiceAppleEvents": "Automation",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
        "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
        "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
        "kTCCServiceSystemPolicySysAdminFiles": "Administer Computer",
        "kTCCServiceSystemPolicyAppBundles": "App Management",
        "kTCCServiceSystemPolicyAppData": "App Data",
        "kTCCServiceSystemPolicyDeveloperFiles": "Developer Files",
        "kTCCServiceDeveloperTool": "Developer Tools",
        "kTCCServiceEndpointSecurityClient": "Endpoint Security",
        "kTCCServiceRemoteDesktop": "Remote Desktop",
        "kTCCServiceBluetoothAlways": "Bluetooth",
        "kTCCServiceSpeechRecognition": "Speech Recognition",
        "kTCCServiceFileProviderDomain": "File Provider",
        "kTCCServiceFileProviderPresence": "File Provider Presence",
        "kTCCServiceUbiquity": "iCloud",
        "kTCCServiceFocusStatus": "Focus",
        "kTCCServiceUserAvailability": "Focus Status",
        "kTCCServiceWebBrowserPublicKeyCredential": "Passkeys (browser)",
        "kTCCServiceMotion": "Motion & Fitness",
        "kTCCServiceLiverpool": "CloudKit",
        "kTCCServiceWillow": "Home",
        "kTCCServiceSiri": "Siri",
        "kTCCServicePrototype3Rights": "Authorization plug-in rights",
        "kTCCServicePrototype4Rights": "Authorization plug-in rights",
    ]

    static func displayName(_ service: String) -> String {
        names[service] ?? service.replacingOccurrences(of: "kTCCService", with: "")
    }

    static func valueName(_ value: Int64) -> String {
        switch value {
        case 0: "Denied"
        case 1: "Unknown"
        case 2: "Allowed"
        case 3: "Limited"
        default: "Value \(value)"
        }
    }

    static func reasonName(_ reason: Int64) -> String {
        switch reason {
        case 1: "Error"
        case 2: "User consent"
        case 3: "User set"
        case 4: "System set"
        case 5: "Service policy"
        case 6: "MDM policy"
        case 7: "Override policy"
        case 8: "Missing usage string"
        case 9: "Prompt timeout"
        case 10: "Preflight unknown"
        case 11: "Entitled"
        case 12: "App type policy"
        default: "Code \(reason)"
        }
    }
}
