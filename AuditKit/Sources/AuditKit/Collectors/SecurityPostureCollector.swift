import Foundation

public struct SecurityPostureCollector: Collector {
    public let id = "security"
    public let title = "Security Posture"
    public let symbol = "lock.shield"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let core = "Core protections"

        if let r = await section.run(.csrutilStatus, context: context) {
            let enabled = Parsers.sipEnabled(r.combined)
            section.add(AuditItem(
                id: "security:sip", group: core, title: "System Integrity Protection",
                value: enabled ? "Enabled" : "Disabled or custom",
                details: ["Output": r.combined.trimmed],
                findings: enabled ? [] : [Finding(.critical, "SIP is not fully enabled",
                    rationale: "SIP protects system files, kernel extensions and TCC databases from modification, even by root.")]))
        }

        if let r = await section.run(.spctlStatus, context: context, expectNonZeroExit: true) {
            let enabled = r.combined.contains("assessments enabled")
            section.add(AuditItem(
                id: "security:gatekeeper", group: core, title: "Gatekeeper",
                value: enabled ? "Enabled" : "Disabled",
                findings: enabled ? [] : [Finding(.critical, "Gatekeeper is disabled",
                    rationale: "Downloaded apps are not checked for a valid Developer ID signature and notarization.")]))
        }

        if let r = await section.run(.fdesetupStatus, context: context) {
            let text = r.combined.trimmed
            let on = text.contains("FileVault is On")
            var findings: [Finding] = []
            if !on {
                findings.append(Finding(.warning, "FileVault is off",
                    rationale: "Data at rest is not protected by your login password if the Mac is lost or stolen."))
            }
            section.add(AuditItem(id: "security:filevault", group: core, title: "FileVault",
                                  value: on ? "On" : "Off", details: ["Output": text], findings: findings))
        }

        if let r = await section.run(.screenLockStatus, context: context) {
            let value = Parsers.screenLockDelay(r.combined)
            var findings: [Finding] = []
            if value == "off" {
                findings.append(Finding(.warning, "No password required after sleep or screen saver",
                    rationale: "Anyone with physical access to an unattended Mac can use it."))
            } else if value != "immediate", value != nil {
                findings.append(Finding(.notice, "Delay before password is required",
                    rationale: "A grace period allows access to a recently locked Mac."))
            }
            section.add(AuditItem(id: "security:screenlock", group: core, title: "Require password after sleep",
                                  value: value ?? "Unknown", findings: findings))
        }

        let lockdown = PlistReader.boolPreference("LDMGlobalEnabled", domain: kCFPreferencesAnyApplication as String) ?? false
        section.add(AuditItem(id: "security:lockdown", group: core, title: "Lockdown Mode",
                              value: lockdown ? "On" : "Off"))

        if let r = await section.run(.devToolsSecurityStatus, context: context) {
            let enabled = r.combined.contains("enabled")
            section.add(AuditItem(id: "security:devmode", group: core, title: "Developer mode (DevToolsSecurity)",
                                  value: enabled ? "Enabled" : "Disabled",
                                  findings: enabled ? [Finding(.info, "Developer mode is enabled",
                                      rationale: "Members of the developer group can debug other processes without authentication.")] : []))
        }

        if let r = await section.run(.nvramFindMyToken, context: context, expectNonZeroExit: true) {
            // Only the presence of the token is used; its value is never stored.
            let enabled = r.exitCode == 0
            section.add(AuditItem(id: "security:findmy", group: core, title: "Find My Mac",
                                  value: enabled ? "On" : "Not detected",
                                  details: ["Method": "Presence of the Find My token in NVRAM"],
                                  findings: enabled ? [] : [Finding(.notice, "Find My Mac not detected",
                                      rationale: "No Find My token was found in NVRAM. If Find My is off, Activation Lock and remote lock/erase are unavailable.")]))
        }

        await collectLogin(into: &section)
        await collectFirewall(into: &section, context: context)
    }

    private func collectLogin(into section: inout SectionResult) async {
        let group = "Login window"
        let path = "/Library/Preferences/com.apple.loginwindow.plist"
        section.note(file: path)
        let prefs = PlistReader.dictionary(at: path) ?? [:]

        let autoLogin = prefs["autoLoginUser"] as? String
        let kcpassword = FileManager.default.fileExists(atPath: "/etc/kcpassword")
        section.add(AuditItem(
            id: "security:autologin", group: group, title: "Automatic login",
            value: autoLogin.map { "On (\($0))" } ?? "Off",
            details: ["/etc/kcpassword present": kcpassword ? "Yes" : "No"],
            findings: autoLogin != nil ? [Finding(.warning, "Automatic login is enabled",
                rationale: "The Mac logs in without a password at startup; /etc/kcpassword holds an obfuscated (not encrypted) password.")] : []))

        let guest = prefs["GuestEnabled"] as? Bool ?? false
        section.add(AuditItem(id: "security:guest", group: group, title: "Guest account",
                              value: guest ? "Enabled" : "Disabled",
                              findings: guest ? [Finding(.notice, "Guest account is enabled",
                                  rationale: "Anyone can log in without a password (data is erased at logout).")] : []))

        let hints = (prefs["RetriesUntilHint"] as? Int ?? 0) > 0
        section.add(AuditItem(id: "security:passwordhints", group: group, title: "Password hints",
                              value: hints ? "Shown" : "Hidden",
                              findings: hints ? [Finding(.notice, "Password hints are shown at login",
                                  rationale: "Hints can help an attacker guess the password.")] : []))

        if let hook = prefs["LoginHook"] as? String {
            section.add(AuditItem(id: "security:loginhook", group: group, title: "Login hook", value: hook,
                                  findings: [Finding(.warning, "Legacy login hook configured",
                                      rationale: "Login hooks run as root at every login and are a known persistence mechanism.")]))
        }
        if let hook = prefs["LogoutHook"] as? String {
            section.add(AuditItem(id: "security:logouthook", group: group, title: "Logout hook", value: hook,
                                  findings: [Finding(.warning, "Legacy logout hook configured",
                                      rationale: "Logout hooks run as root and are a known persistence mechanism.")]))
        }
    }

    private func collectFirewall(into section: inout SectionResult, context: AuditContext) async {
        let group = "Application firewall"

        if let r = await section.run(.firewallGlobalState, context: context) {
            let state = Parsers.firewallState(r.combined)
            let value = switch state {
            case 0: "Off"
            case 1: "On"
            case 2: "On (essential services only)"
            default: "Unknown"
            }
            section.add(AuditItem(id: "firewall:state", group: group, title: "Firewall", value: value,
                                  findings: state == 0 ? [Finding(.notice, "Application firewall is off",
                                      rationale: "Incoming connections to listening apps are not filtered. Recommended on portable Macs and untrusted networks.")] : []))
        }
        if let r = await section.run(.firewallStealthMode, context: context) {
            let on = r.combined.lowercased().contains("stealth mode is on")
            section.add(AuditItem(id: "firewall:stealth", group: group, title: "Stealth mode", value: on ? "On" : "Off"))
        }
        if let r = await section.run(.firewallBlockAll, context: context) {
            let on = r.combined.lowercased().contains("set to enabled")
            section.add(AuditItem(id: "firewall:blockall", group: group, title: "Block all incoming", value: on ? "On" : "Off"))
        }
        if let r = await section.run(.firewallAllowSigned, context: context) {
            let lines = r.combined.split(separator: "\n").map(String.init)
            let builtin = lines.first { $0.contains("built-in") }?.contains("ENABLED") ?? false
            let downloaded = lines.first { $0.contains("downloaded") }?.contains("ENABLED") ?? false
            section.add(AuditItem(id: "firewall:allowsigned", group: group, title: "Auto-allow built-in signed software",
                                  value: builtin ? "On" : "Off"))
            section.add(AuditItem(id: "firewall:allowsignedapp", group: group, title: "Auto-allow downloaded signed software",
                                  value: downloaded ? "On" : "Off"))
        }
        if let r = await section.run(.firewallListApps, context: context) {
            for rule in Parsers.firewallApps(r.combined) {
                let signing = await context.signing.inspect(path: rule.path)
                var findings: [Finding] = []
                if rule.allowed, signing.isUntrusted {
                    findings.append(Finding(.warning, "Incoming connections allowed for untrusted code",
                                            rationale: "\(signing.summary). Firewall exceptions should only exist for trusted, signed software."))
                }
                section.add(AuditItem(id: "firewall:app:\(rule.path)", group: "Firewall app rules",
                                      title: (rule.path as NSString).lastPathComponent,
                                      value: rule.allowed ? "Allow incoming" : "Block incoming",
                                      details: ["Path": rule.path].merging(signing.details) { a, _ in a },
                                      findings: findings))
            }
        }
    }
}

extension Parsers {
    static func sipEnabled(_ output: String) -> Bool {
        let first = output.split(separator: "\n").first.map(String.init) ?? ""
        return first.contains("status: enabled.")
    }

    static func screenLockDelay(_ output: String) -> String? {
        guard let range = output.range(of: "screenLock delay is ") else {
            return output.contains("screenLock is off") ? "off" : nil
        }
        return output[range.upperBound...].split(separator: "\n").first.map { String($0).trimmed }
    }

    static func firewallState(_ output: String) -> Int? {
        guard let range = output.range(of: "State = ") else { return nil }
        return Int(output[range.upperBound...].prefix { $0.isNumber })
    }

    struct FirewallRule: Equatable {
        var path: String
        var allowed: Bool
    }

    static func firewallApps(_ output: String) -> [FirewallRule] {
        var rules: [FirewallRule] = []
        var pending: String?
        for line in output.split(separator: "\n").map({ String($0).trimmed }) {
            if let colon = line.range(of: " : "), Int(line[..<colon.lowerBound]) != nil {
                pending = String(line[colon.upperBound...]).trimmed
            } else if let path = pending, line.hasPrefix("(") {
                rules.append(FirewallRule(path: path, allowed: line.contains("Allow")))
                pending = nil
            }
        }
        return rules
    }
}
