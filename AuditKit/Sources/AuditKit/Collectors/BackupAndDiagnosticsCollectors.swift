import Foundation

public struct BackupCollector: Collector {
    public let id = "backup"
    public let title = "Backup"
    public let symbol = "clock.arrow.circlepath"

    public init() {}

    static let prefsPath = "/Library/Preferences/com.apple.TimeMachine.plist"

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        section.note(file: Self.prefsPath)
        let prefs = PlistReader.dictionary(at: Self.prefsPath) ?? [:]
        let auto = prefs["AutoBackup"] as? Bool ?? false
        section.add(AuditItem(id: "backup:auto", group: "Time Machine", title: "Automatic backups", value: auto ? "On" : "Off"))

        let encryption = Dictionary(
            ((prefs["Destinations"] as? [[String: Any]]) ?? []).compactMap { d -> (String, String)? in
                guard let id = d["DestinationID"] as? String else { return nil }
                return (id, d["LastKnownEncryptionState"] as? String ?? "Unknown")
            }, uniquingKeysWith: { a, _ in a })

        var destinations: [[String: String]] = []
        if let r = await section.run(.tmutilDestinationInfo, context: context, expectNonZeroExit: true) {
            destinations = Parsers.tmutilDestinations(r.combined)
        }
        if destinations.isEmpty {
            section.add(AuditItem(id: "backup:none", group: "Time Machine", title: "Destinations", value: "None configured",
                                  findings: [Finding(.notice, "No Time Machine destination",
                                      rationale: "Without backups, ransomware, hardware failure or loss can cause permanent data loss. Ignore if another backup tool is used.")]))
        }
        for d in destinations {
            let id = d["ID"] ?? d["Name"] ?? "destination"
            let enc = encryption[id] ?? "Unknown"
            section.add(AuditItem(id: "backup:dest:\(id)", group: "Time Machine", title: d["Name"] ?? "Destination",
                                  value: d["Kind"] ?? "", details: d.merging(["Encryption": enc]) { a, _ in a },
                                  findings: enc == "NotEncrypted" ? [Finding(.warning, "Backup is not encrypted",
                                      rationale: "Anyone with access to the backup disk can read its contents.")] : []))
        }

        if !destinations.isEmpty,
           let r = await section.run(.tmutilLatestBackup, context: context, expectNonZeroExit: true), r.exitCode == 0 {
            let path = r.stdout.trimmed
            var findings: [Finding] = []
            if let date = Parsers.backupDate(path), Date().timeIntervalSince(date) > 14 * 86_400 {
                findings.append(Finding(.warning, "Last backup older than 14 days", rationale: "Recent changes are not protected."))
            }
            section.add(AuditItem(id: "backup:latest", group: "Time Machine", title: "Latest backup", value: path, findings: findings))
        }
    }
}

public struct DiagnosticsCollector: Collector {
    public let id = "diagnostics"
    public let title = "Analytics & Data Sharing"
    public let symbol = "chart.bar.doc.horizontal"

    public init() {}

    static let crashReporter = "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        section.note(file: Self.crashReporter)
        section.note(api: "CFPreferences (com.apple.assistant.support, com.apple.AdLib)")
        let crash = PlistReader.dictionary(at: Self.crashReporter) ?? [:]
        let group = "Sharing with Apple and developers"

        func add(_ key: String, _ title: String, _ value: Bool?) {
            section.add(AuditItem(id: "diag:\(key)", group: group, title: title,
                                  value: value.map { $0 ? "On" : "Off" } ?? "Not set"))
        }
        add("autosubmit", "Share Mac analytics", crash["AutoSubmit"] as? Bool)
        add("thirdparty", "Share with app developers", crash["ThirdPartyDataSubmit"] as? Bool)
        add("siri", "Siri", PlistReader.boolPreference("Assistant Enabled", domain: "com.apple.assistant.support"))
        add("ads", "Personalised Apple ads", PlistReader.boolPreference("allowApplePersonalizedAdvertising", domain: "com.apple.AdLib"))
        add("siridata", "Improve Siri & Dictation",
            (PlistReader.preference("Siri Data Sharing Opt-In Status", domain: "com.apple.assistant.support") as? Int).map { $0 == 1 })
    }
}

extension Parsers {
    static func tmutilDestinations(_ output: String) -> [[String: String]] {
        var result: [[String: String]] = []
        var current: [String: String] = [:]
        for raw in output.split(separator: "\n") {
            let line = raw.trimmed
            if line.hasPrefix("====") || line.hasPrefix(">") {
                if !current.isEmpty { result.append(current) }
                current = [:]
                continue
            }
            guard let colon = line.range(of: " : ") else { continue }
            current[line[..<colon.lowerBound].trimmed] = line[colon.upperBound...].trimmed
        }
        if !current.isEmpty { result.append(current) }
        return result.filter { $0["Name"] != nil || $0["ID"] != nil }
    }

    /// Backup paths end in a folder such as `2026-10-01-120000.backup` or `2026-10-01-120000`.
    static func backupDate(_ path: String) -> Date? {
        let last = (path as NSString).lastPathComponent.replacingOccurrences(of: ".backup", with: "")
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd-HHmmss"
        return f.date(from: last)
    }
}
