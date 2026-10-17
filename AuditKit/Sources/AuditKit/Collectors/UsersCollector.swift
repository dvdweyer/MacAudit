import Foundation
import OpenDirectory

public struct UsersCollector: Collector {
    public let id = "users"
    public let title = "Users & Accounts"
    public let symbol = "person.crop.circle"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        section.note(api: "OpenDirectory (local node)")
        let attrs = [kODAttributeTypeUniqueID, kODAttributeTypeFullName, kODAttributeTypeUserShell,
                     kODAttributeTypeNFSHomeDirectory, kODAttributeTypeAuthenticationAuthority,
                     "dsAttrTypeNative:IsHidden", "dsAttrTypeNative:accountPolicyData"]
        let users: [DirectoryRecord]
        do {
            users = try DirectoryService.records(type: kODRecordTypeUsers, attributes: attrs)
        } catch {
            section.coverage.degrade(to: .unavailable, "OpenDirectory query failed: \(error.localizedDescription)")
            return
        }
        let admins = Set(DirectoryService.groupMembers("admin"))
        section.note(api: "utmpx (wtmp login records)")
        let logins = LoginHistory.latestLogins()

        let human = users.filter { u in
            let uid = Int(u.first(kODAttributeTypeUniqueID) ?? "") ?? -1
            return uid >= 500 && !u.name.hasPrefix("_")
        }.sorted { $0.name < $1.name }

        for user in human {
            let uid = user.first(kODAttributeTypeUniqueID) ?? ""
            let authority = user.attributes[kODAttributeTypeAuthenticationAuthority] ?? []
            let hidden = user.first("dsAttrTypeNative:IsHidden").map { ["1", "YES", "yes"].contains($0) } ?? false
            let disabled = authority.contains { $0.contains("DisabledUser") }
            let isAdmin = admins.contains(user.name)
            var details: [String: String] = [
                "Full name": user.first(kODAttributeTypeFullName) ?? "",
                "UID": uid,
                "Shell": user.first(kODAttributeTypeUserShell) ?? "",
                "Home": user.first(kODAttributeTypeNFSHomeDirectory) ?? "",
                "Administrator": isAdmin ? "Yes" : "No",
                "Hidden": hidden ? "Yes" : "No",
                "Disabled": disabled ? "Yes" : "No",
            ]
            if let policy = user.first("dsAttrTypeNative:accountPolicyData"),
               let dict = (try? PropertyListSerialization.propertyList(from: Data(policy.utf8), format: nil)) as? [String: Any] {
                for (key, label) in [("creationTime", "Created"), ("passwordLastSetTime", "Password last set"),
                                     ("failedLoginTimestamp", "Last failed login")] {
                    if let t = dict[key] as? Double, t > 0 {
                        details[label] = Date(timeIntervalSince1970: t).auditString
                    }
                }
                if let failed = dict["failedLoginCount"] as? Int { details["Failed login count"] = "\(failed)" }
            }
            if let login = logins[user.name] {
                details["Last login"] = "\(login.date.auditString) (\(login.line))"
            } else {
                details["Last login"] = "None recorded"
            }
            if let r = await section.run(.secureTokenStatus(user: user.name), context: context) {
                details["Secure Token"] = r.combined.contains("ENABLED") ? "Enabled" : "Disabled"
            }

            var findings: [Finding] = []
            if hidden {
                findings.append(Finding(.notice, "Hidden user account",
                    rationale: "Hidden accounts do not appear at the login window; ensure this account is expected."))
            }
            section.add(AuditItem(id: "users:user:\(user.name)", group: "Local users", title: user.name,
                                  value: [isAdmin ? "Admin" : "Standard", disabled ? "disabled" : nil].compactMap { $0 }.joined(separator: ", "),
                                  details: details, findings: findings))
        }

        let adminCount = human.filter { admins.contains($0.name) }.count
        section.add(AuditItem(id: "users:admincount", group: "Summary", title: "Administrator accounts", value: "\(adminCount)",
                              details: ["Members of admin group": admins.sorted().joined(separator: ", ")],
                              findings: adminCount > 2 ? [Finding(.info, "Several administrator accounts",
                                  rationale: "Daily use of a standard account limits the impact of malware.")] : []))

        if let root = users.first(where: { $0.name == "root" }) {
            let authority = root.attributes[kODAttributeTypeAuthenticationAuthority] ?? []
            let enabled = authority.contains { $0.contains("ShadowHash") }
            section.add(AuditItem(id: "users:root", group: "Summary", title: "root account", value: enabled ? "Enabled" : "Disabled",
                                  findings: enabled ? [Finding(.warning, "root account is enabled",
                                      rationale: "A password-enabled root account allows direct root login.")] : []))
        }

        await collectPasswordPolicy(into: &section, context: context)
        collectSudoers(into: &section, context: context)
    }

    private func collectPasswordPolicy(into section: inout SectionResult, context: AuditContext) async {
        guard let r = await section.run(.passwordPolicies, context: context) else { return }
        let group = "Password policy"
        let policies = Parsers.passwordPolicies(r.combined)
        let minLength = Parsers.minimumPasswordLength(policies)
        section.add(AuditItem(
            id: "users:pwpolicy:minlength", group: group, title: "Minimum password length",
            value: minLength.map(String.init) ?? "Not enforced",
            findings: (minLength ?? 0) < 8 ? [Finding(.info, "Short minimum password length",
                rationale: "Local account passwords can be shorter than 8 characters. The login password also protects FileVault and the keychain.")] : []))
        for policy in policies {
            section.add(AuditItem(id: "users:pwpolicy:\(policy.identifier)", group: group, title: policy.identifier,
                                  value: policy.content, details: ["Category": policy.category]))
        }
    }

    private func collectSudoers(into section: inout SectionResult, context: AuditContext) {
        let fm = FileManager.default
        var files: [String] = []
        if fm.isReadableFile(atPath: "/etc/sudoers") { files.append("/etc/sudoers") }
        else { section.coverage.degrade(to: .partial, "/etc/sudoers requires root.") }
        files += fm.contents(ofDirectory: "/etc/sudoers.d").map { "/etc/sudoers.d/" + $0 }

        for path in files {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
                section.coverage.degrade(to: .partial, "\(path) not readable.")
                continue
            }
            section.note(file: path)
            for rule in Parsers.sudoRules(text) {
                let nopasswd = rule.contains("NOPASSWD")
                section.add(AuditItem(id: "users:sudo:\(path):\(rule)", group: "sudo rules", title: rule, value: path,
                                      findings: nopasswd ? [Finding(.warning, "sudo without password",
                                          rationale: "Any process running as this user can obtain root for the listed commands.")] : []))
            }
        }
    }
}

extension Parsers {
    struct PasswordPolicy: Equatable {
        var category: String
        var identifier: String
        var content: String
    }

    /// `pwpolicy -getaccountpolicies` prints a header line followed by a plist.
    static func passwordPolicies(_ output: String) -> [PasswordPolicy] {
        guard let start = output.range(of: "<?xml"), let end = output.range(of: "</plist>", options: .backwards),
              let plist = try? PropertyListSerialization.propertyList(
                from: Data(output[start.lowerBound..<end.upperBound].utf8), format: nil) as? [String: Any]
        else { return [] }
        return plist.keys.sorted().flatMap { category in
            (plist[category] as? [[String: Any]] ?? []).map { p in
                PasswordPolicy(category: category,
                               identifier: p["policyIdentifier"] as? String ?? "unnamed",
                               content: p["policyContent"] as? String ?? "")
            }
        }
    }

    /// Minimum length from content rules like `policyAttributePassword matches '.{8,}+'`.
    static func minimumPasswordLength(_ policies: [PasswordPolicy]) -> Int? {
        policies.filter { $0.category == "policyCategoryPasswordContent" }.compactMap { policy -> Int? in
            guard let range = policy.content.range(of: #"\.\{(\d+),"#, options: .regularExpression) else { return nil }
            return Int(policy.content[range].dropFirst(2).dropLast())
        }.max()
    }

    static func sudoRules(_ text: String) -> [String] {
        let defaultRules: Set<String> = ["root ALL = (ALL) ALL", "%admin ALL = (ALL) ALL", "root ALL=(ALL) ALL", "%admin ALL=(ALL) ALL"]
        return text.split(separator: "\n").compactMap { raw in
            let line = raw.trimmed
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("Defaults"),
                  !line.hasPrefix("@include"), !line.hasPrefix("#include"),
                  !["Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias"].contains(where: line.hasPrefix) else { return nil }
            let normalized = line.split(whereSeparator: \.isWhitespace).joined(separator: " ")
            return defaultRules.contains(normalized) ? nil : normalized
        }
    }
}
