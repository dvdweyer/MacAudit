import Foundation

public struct ProfilesCollector: Collector {
    public let id = "profiles"
    public let title = "Profiles & Device Management"
    public let symbol = "gearshape.2"

    public init() {}

    static let managedPrefs = "/Library/Managed Preferences"

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        if let r = await section.run(.profilesEnrollmentStatus, context: context) {
            let status = Parsers.enrollmentStatus(r.combined)
            let dep = status["Enrolled via DEP"] ?? "Unknown"
            let mdm = status["MDM enrollment"] ?? "Unknown"
            section.add(AuditItem(id: "profiles:dep", group: "Enrollment", title: "Automated Device Enrollment (DEP/ABM)", value: dep))
            section.add(AuditItem(id: "profiles:mdm", group: "Enrollment", title: "MDM enrollment", value: mdm,
                                  findings: mdm.hasPrefix("Yes") ? [Finding(.info, "Mac is managed by MDM",
                                      rationale: "An organisation can install profiles, apps and apply restrictions. Verify this is expected.")] : []))
            if let server = status["MDM server"] {
                section.add(AuditItem(id: "profiles:mdmserver", group: "Enrollment", title: "MDM server", value: server))
            }
        }

        if let r = await section.run(.profilesShowConfiguration, context: context) {
            for p in Parsers.configurationProfiles(r.stdout) {
                let name = p.attributes["profileDisplayName"] ?? p.attributes["profileIdentifier"] ?? "Profile"
                section.add(AuditItem(
                    id: "profiles:profile:\(p.scope):\(p.attributes["profileIdentifier"] ?? name)",
                    group: p.scope == "_computerlevel" ? "Device profiles" : "User profiles (\(p.scope))",
                    title: name, value: p.attributes["profileOrganization"] ?? "",
                    details: p.attributes.merging(["Payload types": p.payloadTypes.joined(separator: "\n")]) { a, _ in a },
                    findings: [Finding(.info, "Configuration profile installed",
                                       rationale: "Profiles can change security settings, install certificates, and configure VPNs or proxies.")]))
            }
            if !context.isRoot {
                section.coverage.degrade(to: .partial, "Device-level profiles may only be listed when run as root.")
            }
        }

        let fm = FileManager.default
        section.note(file: Self.managedPrefs)
        for entry in fm.contents(ofDirectory: Self.managedPrefs) {
            let path = Self.managedPrefs + "/" + entry
            if entry.hasSuffix(".plist") {
                section.add(AuditItem(id: "profiles:managedpref:\(entry)", group: "Managed preferences (computer)",
                                      title: (entry as NSString).deletingPathExtension,
                                      value: "\((PlistReader.dictionary(at: path) ?? [:]).count) keys"))
            } else if fm.isDirectory(path) {
                for file in fm.contents(ofDirectory: path) where file.hasSuffix(".plist") {
                    section.add(AuditItem(id: "profiles:managedpref:\(entry):\(file)", group: "Managed preferences (\(entry))",
                                          title: (file as NSString).deletingPathExtension,
                                          value: "\((PlistReader.dictionary(at: path + "/" + file) ?? [:]).count) keys"))
                }
            }
        }
    }
}

extension Parsers {
    static func enrollmentStatus(_ output: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in output.split(separator: "\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            result[line[..<colon].trimmed] = line[line.index(after: colon)...].trimmed
        }
        return result
    }

    struct ConfigurationProfile: Equatable {
        var scope: String
        var index: Int
        var attributes: [String: String] = [:]
        var payloadTypes: [String] = []
    }

    /// Parses `profiles show` output lines like `_computerlevel[1] attribute: profileIdentifier: com.example`.
    static func configurationProfiles(_ output: String) -> [ConfigurationProfile] {
        var profiles: [String: ConfigurationProfile] = [:]
        var order: [String] = []
        let attr = /^(\S+)\[(\d+)\]\s+attribute:\s+(\w+):\s*(.*)$/
        let payload = /^(\S+)\[(\d+)\]\s+payload\[\d+\]\s+type\s*=\s*(.*)$/
        for raw in output.split(separator: "\n") {
            let line = raw.trimmed
            if let m = line.firstMatch(of: attr) {
                let key = "\(m.1)[\(m.2)]"
                if profiles[key] == nil { order.append(key); profiles[key] = ConfigurationProfile(scope: String(m.1), index: Int(m.2) ?? 0) }
                profiles[key]?.attributes[String(m.3)] = String(m.4).trimmed
            } else if let m = line.firstMatch(of: payload) {
                let key = "\(m.1)[\(m.2)]"
                if profiles[key] == nil { order.append(key); profiles[key] = ConfigurationProfile(scope: String(m.1), index: Int(m.2) ?? 0) }
                profiles[key]?.payloadTypes.append(String(m.3).trimmed)
            }
        }
        return order.compactMap { profiles[$0] }
    }
}
