import Foundation

public struct SharingCollector: Collector {
    public let id = "sharing"
    public let title = "Sharing & Remote Access"
    public let symbol = "person.2.wave.2"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let overrides = await section.run(.launchctlPrintDisabledSystem, context: context)
            .map { Parsers.launchdOverrides($0.stdout) } ?? [:]

        func daemonEnabled(_ plist: String) -> Bool {
            let path = "/System/Library/LaunchDaemons/\(plist).plist"
            section.note(file: path)
            let d = PlistReader.dictionary(at: path) ?? [:]
            guard let label = d["Label"] as? String else { return false }
            if let disabled = overrides[label] { return !disabled }
            return !(d["Disabled"] as? Bool ?? false)
        }

        let printerSharing = await section.run(.cupsSettings, context: context)
            .map { Parsers.cupsSharePrinters($0.stdout) } ?? false

        let group = "Services"
        let services: [(key: String, title: String, enabled: Bool, severity: Severity, rationale: String)] = [
            ("ssh", "Remote Login (SSH)", daemonEnabled("ssh"), .warning,
             "Accepts SSH logins from the network. Ensure strong passwords or key-only authentication."),
            ("screensharing", "Screen Sharing", daemonEnabled("com.apple.screensharing"), .warning,
             "Allows remote viewing and control of the screen."),
            ("remotemanagement", "Remote Management (ARD)", Self.remoteManagementEnabled(), .warning,
             "Allows Apple Remote Desktop administration of this Mac."),
            ("smb", "File Sharing (SMB)", daemonEnabled("com.apple.smbd"), .notice,
             "Shared folders are reachable from the network."),
            ("aeserver", "Remote Apple Events", daemonEnabled("com.apple.eppc"), .warning,
             "Allows apps on other Macs to send Apple Events to this Mac."),
            ("internetsharing", "Internet Sharing", Self.internetSharingEnabled(), .notice,
             "This Mac routes traffic for other devices."),
            ("printersharing", "Printer Sharing", printerSharing, .info,
             "Printers are advertised to the local network."),
            ("contentcaching", "Content Caching", Self.contentCachingEnabled(), .info,
             "This Mac serves cached Apple content to other devices."),
            ("airplay", "AirPlay Receiver", PlistReader.boolPreference("AirplayRecieverEnabled", domain: "com.apple.controlcenter") ?? true, .info,
             "Other devices can stream to this Mac."),
            ("mediasharing", "Media Sharing", PlistReader.boolPreference("home-sharing-enabled", domain: "com.apple.amp.mediasharingd") ?? false, .info,
             "The media library is shared on the local network."),
            ("bluetoothsharing", "Bluetooth Sharing", Self.bluetoothSharingEnabled(), .notice,
             "Nearby Bluetooth devices can send files to or browse files on this Mac."),
        ]
        section.note(file: "/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
        section.note(file: "/Library/Preferences/com.apple.AssetCache.plist")
        section.note(api: "CFPreferences (com.apple.controlcenter, com.apple.amp.mediasharingd, com.apple.Bluetooth ByHost)")
        section.note(api: "libproc (OBEXAgent process)")

        for s in services {
            section.add(AuditItem(id: "sharing:\(s.key)", group: group, title: s.title, value: s.enabled ? "On" : "Off",
                                  findings: s.enabled ? [Finding(s.severity, "\(s.title) is on", rationale: s.rationale)] : []))
        }

        let fileSharingOn = services.first { $0.key == "smb" }?.enabled ?? false
        if let r = await section.run(.sharingList, context: context) {
            for share in Parsers.sharePoints(r.stdout) {
                var findings: [Finding] = []
                if share.guestAccess, fileSharingOn {
                    findings.append(Finding(share.readOnly ? .notice : .warning, "Guest access to shared folder",
                                            rationale: "Anyone on the network can access this folder without a password\(share.readOnly ? "" : ", including writing to it")."))
                }
                section.add(AuditItem(
                    id: "sharing:share:\(share.path)", group: "Shared folders", title: share.name,
                    value: share.path,
                    details: ["SMB shared": share.shared ? "Yes" : "No",
                              "Guest access": share.guestAccess ? "Yes" : "No",
                              "Read-only": share.readOnly ? "Yes" : "No",
                              "Effective": fileSharingOn && share.shared ? "Yes" : "No (File Sharing off)"],
                    findings: findings))
            }
        }
    }

    /// OBEXAgent serves Bluetooth Sharing and only runs while it is on. The ByHost key is how older macOS stored the setting.
    static func bluetoothSharingEnabled() -> Bool {
        let key = CFPreferencesCopyValue("PrefKeyServicesEnabled" as CFString, "com.apple.Bluetooth" as CFString,
                                         kCFPreferencesCurrentUser, kCFPreferencesCurrentHost)
        return (key as? Bool ?? false) || !ProcFiles.pids(named: "OBEXAgent").isEmpty
    }

    static func remoteManagementEnabled() -> Bool {
        FileManager.default.fileExists(atPath: "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd")
    }

    static func internetSharingEnabled() -> Bool {
        let nat = PlistReader.dictionary(at: "/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
        let enabled = (nat?["NAT"] as? [String: Any])?["Enabled"]
        return (enabled as? Int ?? 0) == 1 || (enabled as? Bool ?? false)
    }

    static func contentCachingEnabled() -> Bool {
        PlistReader.dictionary(at: "/Library/Preferences/com.apple.AssetCache.plist")?["Activated"] as? Bool ?? false
    }
}

extension Parsers {
    /// Parses `launchctl print-disabled` into label → disabled.
    static func launchdOverrides(_ output: String) -> [String: Bool] {
        var result: [String: Bool] = [:]
        for line in output.split(separator: "\n") {
            let parts = line.components(separatedBy: "=>")
            guard parts.count == 2 else { continue }
            let label = parts[0].trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            switch parts[1].trimmed {
            case "disabled", "true": result[label] = true
            case "enabled", "false": result[label] = false
            default: break
            }
        }
        return result
    }

    static func cupsSharePrinters(_ output: String) -> Bool {
        output.split(separator: "\n").contains { $0.trimmed == "_share_printers=1" }
    }

    struct SharePoint: Equatable {
        var name: String
        var path: String
        var shared = false
        var guestAccess = false
        var readOnly = false
    }

    static func sharePoints(_ output: String) -> [SharePoint] {
        var shares: [SharePoint] = []
        var current: SharePoint?
        var inSMB = false
        for raw in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw).trimmed
            func value(_ key: String) -> String? {
                guard line.hasPrefix(key + ":") else { return nil }
                return String(line.dropFirst(key.count + 1)).trimmed
            }
            if !inSMB, let name = value("name") {
                if let c = current { shares.append(c) }
                current = SharePoint(name: name, path: "")
            } else if let path = value("path") {
                current?.path = path
            } else if line.hasPrefix("smb:") {
                inSMB = true
            } else if line == "}" {
                inSMB = false
            } else if inSMB {
                if let v = value("shared") { current?.shared = v == "1" }
                if let v = value("guest access") { current?.guestAccess = v == "1" }
                if let v = value("read-only") { current?.readOnly = v == "1" }
            }
        }
        if let c = current { shares.append(c) }
        return shares
    }
}
