import Foundation
import ServiceManagement

public struct PersistenceCollector: Collector {
    public let id = "persistence"
    public let title = "Launch Items & Persistence"
    public let symbol = "arrow.clockwise.circle"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let systemOverrides = await section.run(.launchctlPrintDisabledSystem, context: context)
            .map { Parsers.launchdOverrides($0.stdout) } ?? [:]
        let userOverrides = await section.run(.launchctlPrintDisabledUser(uid: getuid()), context: context)
            .map { Parsers.launchdOverrides($0.stdout) } ?? [:]

        let locations: [(group: String, dir: String, overrides: [String: Bool], systemWide: Bool)] = [
            ("Launch daemons (/Library)", "/Library/LaunchDaemons", systemOverrides, true),
            ("Launch agents (/Library)", "/Library/LaunchAgents", userOverrides, true),
            ("Launch agents (user)", context.homeDirectory + "/Library/LaunchAgents", userOverrides, false),
        ]
        for loc in locations {
            section.note(file: loc.dir)
            for file in FileManager.default.contents(ofDirectory: loc.dir) where file.hasSuffix(".plist") {
                let path = loc.dir + "/" + file
                section.add(await launchItem(path: path, group: loc.group, overrides: loc.overrides,
                                             systemWide: loc.systemWide, context: context))
            }
        }

        for dir in ["/System/Library/LaunchDaemons", "/System/Library/LaunchAgents"] {
            let count = FileManager.default.contents(ofDirectory: dir).filter { $0.hasSuffix(".plist") }.count
            section.add(AuditItem(id: "persist:apple:\(dir)", group: "Apple (sealed system volume)",
                                  title: dir, value: "\(count) items"))
        }

        await collectBackgroundItems(into: &section, context: context)
        await collectCron(into: &section, context: context)
        collectLegacy(into: &section)
        collectShellFiles(into: &section, home: context.homeDirectory)
    }

    private func launchItem(path: String, group: String, overrides: [String: Bool], systemWide: Bool,
                            context: AuditContext) async -> AuditItem {
        let plist = PlistReader.dictionary(at: path) ?? [:]
        let label = plist["Label"] as? String ?? (path as NSString).lastPathComponent
        let args = plist["ProgramArguments"] as? [String] ?? []
        let program = plist["Program"] as? String ?? args.first ?? ""
        let plistDisabled = plist["Disabled"] as? Bool ?? false
        let disabled = overrides[label] ?? plistDisabled

        var details: [String: String] = [
            "Plist": path, "Label": label, "Program": program,
            "Arguments": args.dropFirst().joined(separator: " "),
            "RunAtLoad": "\(plist["RunAtLoad"] as? Bool ?? false)",
            "KeepAlive": plist["KeepAlive"].map { "\($0)" } ?? "false",
        ]
        if let bundle = plist["AssociatedBundleIdentifiers"] {
            details["Associated bundle"] = "\(bundle)"
        }
        let status = SMAppService.statusForLegacyPlist(at: URL(fileURLWithPath: path))
        details["Login Items approval"] = switch status {
        case .enabled: "Enabled"
        case .requiresApproval: "Requires approval"
        case .notRegistered: "Not registered"
        case .notFound: "Not found"
        @unknown default: "Unknown"
        }

        var findings: [Finding] = []
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           systemWide, let owner = attrs[.ownerAccountID] as? Int, owner != 0 {
            findings.append(Finding(.warning, "System launch item not owned by root",
                rationale: "A user-owned plist in /Library can be modified without admin rights to run code at a higher privilege."))
        }
        if !program.isEmpty {
            let resolved = Self.resolveProgram(program)
            if Self.suspiciousLocations.contains(where: { resolved.hasPrefix($0) }) || resolved.contains("/.") {
                findings.append(Finding(.warning, "Program in unusual location",
                    rationale: "Persistence from temporary, shared or hidden folders is a common malware pattern."))
            }
            let interpreters = ["/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python3", "/usr/bin/osascript", "/usr/bin/perl", "/usr/bin/ruby"]
            if interpreters.contains(resolved), args.count > 1 {
                findings.append(Finding(.notice, "Runs a script through an interpreter",
                    rationale: "The script's signature cannot be verified; review its arguments."))
            }
            let signing = await context.signing.inspect(path: resolved)
            details.merge(signing.details) { a, _ in a }
            if signing.status == .missing {
                findings.append(Finding(.notice, "Program not found",
                    rationale: "Leftover from an uninstalled app, or the program path is unusual."))
            } else if signing.isUntrusted {
                findings.append(Finding(.warning, "Untrusted program launched automatically", rationale: signing.summary))
            }
        }
        return AuditItem(id: "persist:launchd:\(path)", group: group, title: label,
                         value: disabled ? "Disabled" : "Enabled", details: details, findings: findings)
    }

    static let suspiciousLocations = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"]

    static func resolveProgram(_ program: String) -> String {
        program.hasPrefix("~") ? (program as NSString).expandingTildeInPath : program
    }

    private func collectBackgroundItems(into section: inout SectionResult, context: AuditContext) async {
        guard context.privileged != nil else {
            section.coverage.degrade(to: .partial,
                "Login Items & background items (Background Task Management database): \(Privileges.rootHint).")
            return
        }
        guard let r = await section.runPrivileged(.sfltoolDumpBTM, context: context) else { return }
        for entry in Parsers.btmDump(r.stdout) {
            let name = entry["Name"] ?? entry["Identifier"] ?? "Item"
            let id = entry["Identifier"] ?? name
            section.add(AuditItem(id: "persist:btm:\(entry["UID"] ?? ""):\(id)", group: "Login & background items",
                                  title: name, value: entry["Disposition"] ?? "",
                                  details: entry))
        }
    }

    private func collectCron(into section: inout SectionResult, context: AuditContext) async {
        if let r = await section.run(.crontabList, context: context, expectNonZeroExit: true), r.exitCode == 0 {
            for line in r.stdout.split(separator: "\n").map({ String($0).trimmed })
            where !line.isEmpty && !line.hasPrefix("#") {
                section.add(AuditItem(id: "persist:cron:user:\(line)", group: "Cron jobs", title: line, value: NSUserName(),
                                      findings: [Finding(.notice, "Cron job", rationale: "Cron is a legacy scheduler often used for persistence.")]))
            }
        }
        let tabs = "/usr/lib/cron/tabs"
        if let privileged = context.privileged {
            section.note(file: tabs + " (as root)")
            do {
                for user in try await privileged.listDirectory(tabs) where user != NSUserName() {
                    let text = await section.readPrivileged(tabs + "/" + user, context: context)
                        .map { String(decoding: $0, as: UTF8.self) } ?? ""
                    // Other users' command lines can contain credentials: keep only schedule and program.
                    let jobs = text.split(separator: "\n").compactMap { Parsers.cronJobSummary(String($0)) }
                    section.add(AuditItem(id: "persist:cron:tab:\(user)", group: "Cron jobs", title: "crontab for \(user)",
                                          value: jobs.isEmpty ? "Present" : "\(jobs.count) job(s)",
                                          details: jobs.isEmpty ? [:] : ["Jobs": jobs.joined(separator: "\n")],
                                          findings: [Finding(.notice, "Cron table present",
                                              rationale: "Review scheduled commands for this user.")]))
                }
            } catch {
                section.coverage.degrade(to: .partial, "Could not list \(tabs) as root: \(error)")
            }
        } else {
            section.coverage.degrade(to: .partial, "Other users' crontabs: \(Privileges.rootHint).")
        }
        if FileManager.default.fileExists(atPath: "/etc/crontab") {
            section.add(AuditItem(id: "persist:cron:etc", group: "Cron jobs", title: "/etc/crontab", value: "Present",
                                  findings: [Finding(.notice, "System crontab present", rationale: "Not present by default on macOS.")]))
        }
    }

    private func collectLegacy(into section: inout SectionResult) {
        let checks: [(path: String, title: String)] = [
            ("/Library/StartupItems", "StartupItems"),
            ("/etc/launchd.conf", "launchd.conf"),
            ("/etc/emond.d/rules", "emond rules"),
            ("/etc/periodic", "periodic scripts"),
            ("/usr/local/etc/periodic", "periodic scripts (local)"),
        ]
        let fm = FileManager.default
        for c in checks where fm.fileExists(atPath: c.path) {
            let entries = fm.isDirectory(c.path) ? fm.contents(ofDirectory: c.path) : [c.path]
            guard !entries.isEmpty else { continue }
            section.note(file: c.path)
            section.add(AuditItem(id: "persist:legacy:\(c.path)", group: "Legacy mechanisms", title: c.title,
                                  value: "\(entries.count) item(s)", details: ["Path": c.path, "Entries": entries.joined(separator: "\n")],
                                  findings: [Finding(.notice, "Legacy persistence mechanism present",
                                      rationale: "Rarely used by legitimate modern software; review the contents.")]))
        }
    }

    private func collectShellFiles(into section: inout SectionResult, home: String) {
        let files = [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".profile"]
            .map { home + "/" + $0 } + ["/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/profile", "/etc/bashrc"]
        let fm = FileManager.default
        for path in files where fm.fileExists(atPath: path) {
            // Contents are not read; startup files commonly contain secrets.
            section.add(AuditItem(id: "persist:shell:\(path)", group: "Shell startup files",
                                  title: path.replacingOccurrences(of: home, with: "~"),
                                  value: fm.modificationDate(path).map { "Modified \($0.auditString)" } ?? "Present"))
        }
    }
}

extension Parsers {
    /// Splits `sfltool dumpbtm` output into one dictionary per item.
    static func btmDump(_ output: String) -> [[String: String]] {
        var items: [[String: String]] = []
        var current: [String: String]?
        for raw in output.split(separator: "\n") {
            let line = raw.trimmed
            if line.hasPrefix("#") && line.hasSuffix(":"), Int(line.dropFirst().dropLast()) != nil {
                if let c = current, !c.isEmpty { items.append(c) }
                current = [:]
            } else if line.hasPrefix("========") {
                if let c = current, !c.isEmpty { items.append(c) }
                current = nil
            } else if current != nil, let colon = line.firstIndex(of: ":") {
                let key = line[..<colon].trimmed
                let value = line[line.index(after: colon)...].trimmed
                if !key.isEmpty, current?[key] == nil { current?[key] = value }
            }
        }
        if let c = current, !c.isEmpty { items.append(c) }
        return items
    }
}

extension Parsers {
    /// "<schedule> <program>", with arguments replaced by "…". Comments, blank lines and
    /// environment assignments (which may hold secrets) yield nil.
    static func cronJobSummary(_ line: String) -> String? {
        let text = line.trimmed
        guard !text.isEmpty, !text.hasPrefix("#") else { return nil }
        let tokens = text.split(whereSeparator: \.isWhitespace).map(String.init)
        let scheduleLength = tokens[0].hasPrefix("@") ? 1 : 5
        if scheduleLength == 5, tokens[0].contains("=") { return nil }
        guard tokens.count > scheduleLength else { return nil }
        let schedule = tokens[..<scheduleLength].joined(separator: " ")
        let hasArguments = tokens.count > scheduleLength + 1
        return "\(schedule) \(tokens[scheduleLength])" + (hasArguments ? " …" : "")
    }
}
