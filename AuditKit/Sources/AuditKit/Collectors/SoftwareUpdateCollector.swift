import Foundation

public struct SoftwareUpdateCollector: Collector {
    public let id = "updates"
    public let title = "Software Updates"
    public let symbol = "arrow.down.circle"

    public init() {}

    static let prefsPath = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
    static let managedPath = "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        section.note(file: Self.prefsPath)
        let prefs = PlistReader.dictionary(at: Self.prefsPath) ?? [:]
        let managed = PlistReader.dictionary(at: Self.managedPath) ?? [:]
        if !managed.isEmpty { section.note(file: Self.managedPath) }

        func flag(_ key: String) -> (value: Bool, managed: Bool) {
            if let m = managed[key] as? Bool { return (m, true) }
            return (prefs[key] as? Bool ?? true, false)
        }

        let settings: [(key: String, title: String, severity: Severity, rationale: String)] = [
            ("AutomaticCheckEnabled", "Check for updates automatically", .warning,
             "Without automatic checks, security updates may go unnoticed."),
            ("AutomaticDownload", "Download new updates automatically", .notice,
             "Updates must be downloaded manually before they can be installed."),
            ("AutomaticallyInstallMacOSUpdates", "Install macOS updates automatically", .notice,
             "macOS security patches wait for manual installation."),
            ("CriticalUpdateInstall", "Install security responses and system files", .critical,
             "Rapid security responses and background security improvements will not be installed automatically."),
            ("ConfigDataInstall", "Install system data files (XProtect, Gatekeeper)", .critical,
             "Malware definitions will not be updated automatically."),
        ]
        for s in settings {
            let f = flag(s.key)
            section.add(AuditItem(id: "updates:\(s.key)", group: "Automatic updates", title: s.title,
                                  value: (f.value ? "On" : "Off") + (f.managed ? " (managed)" : ""),
                                  findings: f.value ? [] : [Finding(s.severity, "\(s.title) is off", rationale: s.rationale)]))
        }

        let lastCheck = (prefs["LastFullSuccessfulDate"] ?? prefs["LastSuccessfulDate"]) as? Date
        var checkFindings: [Finding] = []
        if let lastCheck, Date().timeIntervalSince(lastCheck) > 14 * 86_400 {
            checkFindings.append(Finding(.warning, "No successful update check in over 14 days",
                                         rationale: "The Mac may be missing recent security updates."))
        }
        section.add(AuditItem(id: "updates:lastcheck", group: "Status", title: "Last successful check",
                              value: lastCheck?.auditString ?? "Unknown", findings: checkFindings))

        let pending = (prefs["RecommendedUpdates"] as? [[String: Any]]) ?? []
        section.add(AuditItem(id: "updates:pendingcount", group: "Status", title: "Pending recommended updates",
                              value: "\(pending.count)",
                              findings: pending.isEmpty ? [] : [Finding(.warning, "\(pending.count) update(s) pending",
                                  rationale: "Install pending updates to receive the latest security fixes.")]))
        for update in pending {
            let name = update["Display Name"] as? String ?? update["Identifier"] as? String ?? "Update"
            let version = update["Display Version"] as? String ?? ""
            section.add(AuditItem(id: "updates:pending:\(update["Product Key"] as? String ?? name)", group: "Pending",
                                  title: name, value: version))
        }

        for key in ["enforcedSoftwareUpdateDelay", "forceDelayedSoftwareUpdates", "forceDelayedMajorSoftwareUpdates"]
        where managed[key] != nil {
            section.add(AuditItem(id: "updates:managed:\(key)", group: "Managed deferrals", title: key,
                                  value: "\(managed[key]!)"))
        }

        if let installs = prefs["InstallDateDictionary"] as? [String: Date] {
            for (build, date) in installs.sorted(by: { $0.value > $1.value }) {
                section.add(AuditItem(id: "updates:os:\(build)", group: "macOS updates installed", title: build,
                                      value: date.auditString))
            }
        }

        let history = InstallHistory.load()
        section.note(file: InstallHistory.path)
        for entry in history.reversed() {
            let name = entry.name.isEmpty ? (entry.packages.first ?? "Package") : entry.name
            section.add(AuditItem(
                id: "updates:history:\(entry.date.timeIntervalSince1970):\(entry.packages.first ?? name)",
                group: "Install history", title: name,
                value: [entry.version, entry.date.auditString].filter { !$0.isEmpty }.joined(separator: " · "),
                details: ["Installed by": entry.process, "Packages": entry.packages.joined(separator: "\n")]))
        }
    }
}
