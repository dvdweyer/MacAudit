import Foundation
import IOKit.kext

public struct ExtensionsCollector: Collector {
    public let id = "extensions"
    public let title = "Extensions & Plug-ins"
    public let symbol = "puzzlepiece.extension"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        await collectSystemExtensions(into: &section, context: context)
        collectKexts(into: &section)
        await collectAppExtensions(into: &section, context: context)
        BrowserExtensions.collect(into: &section, home: context.homeDirectory)
        await collectAuthorizationPlugins(into: &section, context: context)
        await collectPluginDirectories(into: &section, context: context)
    }

    private func collectSystemExtensions(into section: inout SectionResult, context: AuditContext) async {
        guard let r = await section.run(.systemExtensionsList, context: context) else { return }
        for ext in Parsers.systemExtensions(r.stdout) {
            var findings: [Finding] = []
            if ext.category.contains("endpoint_security") && ext.active {
                findings.append(Finding(.info, "Endpoint Security extension",
                    rationale: "Can observe and block process, file and network activity system-wide. Expected for security products."))
            }
            if ext.category.contains("network_extension") && ext.active {
                findings.append(Finding(.info, "Network extension",
                    rationale: "Can filter, proxy or tunnel network traffic."))
            }
            let shortCategory = ext.category.replacingOccurrences(of: "com.apple.system_extension.", with: "")
            section.add(AuditItem(
                id: "ext:sysext:\(ext.bundleID):\(ext.version)", group: "System extensions",
                title: ext.name, value: ext.state,
                details: ["Bundle ID": ext.bundleID, "Version": ext.version, "Team ID": ext.teamID,
                          "Category": shortCategory, "Enabled": ext.enabled ? "Yes" : "No",
                          "Active": ext.active ? "Yes" : "No"],
                findings: findings))
        }
    }

    private func collectKexts(into section: inout SectionResult) {
        section.note(api: "KextManagerCopyLoadedKextInfo")
        let loaded = KextManagerCopyLoadedKextInfo(nil, nil)?.takeRetainedValue() as? [String: [String: Any]] ?? [:]
        let thirdParty = loaded.filter { !$0.key.hasPrefix("com.apple.") && $0.key != "__kernel__" }
        section.add(AuditItem(id: "ext:kext:applecount", group: "Loaded kernel extensions", title: "Apple kernel extensions",
                              value: "\(loaded.keys.filter { $0.hasPrefix("com.apple.") }.count) loaded"))
        for (bundleID, info) in thirdParty.sorted(by: { $0.key < $1.key }) {
            section.add(AuditItem(
                id: "ext:kext:\(bundleID)", group: "Loaded kernel extensions", title: bundleID,
                value: info["CFBundleVersion"] as? String ?? "",
                details: ["Path": info["OSBundlePath"] as? String ?? ""],
                findings: [Finding(.notice, "Third-party kernel extension loaded",
                    rationale: "Kernel extensions run with full kernel privileges and reduce system security; Apple recommends system extensions instead.")]))
        }
        section.note(file: "/Library/Extensions")
        for name in FileManager.default.contents(ofDirectory: "/Library/Extensions") where name.hasSuffix(".kext") {
            section.add(AuditItem(id: "ext:kextdisk:\(name)", group: "Installed kernel extensions (/Library/Extensions)",
                                  title: name, value: "Installed"))
        }
    }

    private func collectAppExtensions(into section: inout SectionResult, context: AuditContext) async {
        guard let r = await section.run(.pluginkitList, context: context) else { return }
        let all = Parsers.pluginkit(r.stdout)
        let thirdParty = all.filter { !$0.identifier.hasPrefix("com.apple.") && !$0.path.hasPrefix("/System/") }
        section.add(AuditItem(id: "ext:appex:applecount", group: "App extensions", title: "Apple app extensions",
                              value: "\(all.count - thirdParty.count) registered"))
        for p in thirdParty {
            let category = Parsers.extensionPointName(p.sdk)
            var details: [String: String] = ["Identifier": p.identifier, "Version": p.version, "Path": p.path,
                                             "Extension point": p.sdk, "Election": p.electionDescription]
            if let parent = p.parentName { details["Parent app"] = parent }
            var findings: [Finding] = []
            if p.sdk.hasPrefix("com.apple.Safari") || p.sdk == "com.apple.FinderSync" {
                let signing = await context.signing.inspect(path: p.path)
                details.merge(signing.details) { a, _ in a }
                if signing.isUntrusted {
                    findings.append(Finding(.warning, "Untrusted \(category)", rationale: signing.summary))
                }
            }
            section.add(AuditItem(
                id: "ext:appex:\(p.identifier):\(p.path)", group: "App extensions: \(category)",
                title: p.displayName ?? p.identifier, value: p.electionDescription,
                details: details, findings: findings))
        }
    }

    private func collectAuthorizationPlugins(into section: inout SectionResult, context: AuditContext) async {
        let dir = "/Library/Security/SecurityAgentPlugins"
        section.note(file: dir)
        let bundles = FileManager.default.contents(ofDirectory: dir).filter { $0.hasSuffix(".bundle") }
        let names = Set(bundles.map { ($0 as NSString).deletingPathExtension })

        var activeMechanisms: [String] = []
        if let r = await section.run(.authorizationdbLoginConsole, context: context),
           let plist = try? PropertyListSerialization.propertyList(from: Data(r.stdout.utf8), format: nil) as? [String: Any] {
            activeMechanisms = (plist["mechanisms"] as? [String] ?? []).filter { mech in
                names.contains(String(mech.split(separator: ":").first ?? ""))
            }
        }
        for bundle in bundles {
            let name = (bundle as NSString).deletingPathExtension
            let path = dir + "/" + bundle
            let signing = await context.signing.inspect(path: path)
            let mechs = activeMechanisms.filter { $0.hasPrefix(name + ":") }
            var findings = [Finding(mechs.isEmpty ? .info : .notice, "Third-party authorization plug-in",
                rationale: "Authorization plug-ins run inside the login process and can see credentials.")]
            if signing.isUntrusted {
                findings.append(Finding(.warning, "Untrusted authorization plug-in", rationale: signing.summary))
            }
            section.add(AuditItem(
                id: "ext:authplugin:\(name)", group: "Authorization plug-ins", title: name,
                value: mechs.isEmpty ? "Installed (not in login mechanisms)" : "Active at login",
                details: ["Path": path, "Login mechanisms": mechs.joined(separator: "\n")].merging(signing.details) { a, _ in a },
                findings: findings))
        }
    }

    private func collectPluginDirectories(into section: inout SectionResult, context: AuditContext) async {
        let home = context.homeDirectory
        // An empty extension list means every entry counts (e.g. helper tools are plain executables).
        let dirs: [(group: String, paths: [String], extensions: Set<String>)] = [
            ("Audio (HAL) plug-ins", ["/Library/Audio/Plug-Ins/HAL"], ["driver", "plugin", "bundle"]),
            ("Input methods", ["/Library/Input Methods", home + "/Library/Input Methods"], ["app", "bundle", "inputplugin"]),
            ("Spotlight importers", ["/Library/Spotlight", home + "/Library/Spotlight"], ["mdimporter"]),
            ("QuickLook generators", ["/Library/QuickLook", home + "/Library/QuickLook"], ["qlgenerator"]),
            ("Directory Services plug-ins", ["/Library/DirectoryServices/PlugIns"], ["dsplug", "bundle"]),
            ("Internet plug-ins", ["/Library/Internet Plug-Ins", home + "/Library/Internet Plug-Ins"], ["plugin", "webplugin"]),
            ("Printer drivers & PPD filters", ["/Library/Printers/PPDs/Contents/Resources"], []),
            ("PrivilegedHelperTools", ["/Library/PrivilegedHelperTools"], []),
        ]
        for d in dirs {
            for dir in d.paths {
                let entries = FileManager.default.contents(ofDirectory: dir).filter {
                    d.extensions.isEmpty || d.extensions.contains(($0 as NSString).pathExtension.lowercased())
                }
                guard !entries.isEmpty else { continue }
                section.note(file: dir)
                if d.group.hasPrefix("Printer") {
                    section.add(AuditItem(id: "ext:dir:\(dir)", group: d.group, title: dir, value: "\(entries.count) items"))
                    continue
                }
                for name in entries {
                    let path = dir + "/" + name
                    let signing = await context.signing.inspect(path: path)
                    var findings: [Finding] = []
                    if signing.isUntrusted {
                        findings.append(Finding(.notice, "Unsigned or untrusted plug-in", rationale: signing.summary))
                    }
                    section.add(AuditItem(id: "ext:dir:\(path)", group: d.group, title: name, value: signing.summary,
                                          details: ["Path": path].merging(signing.details) { a, _ in a },
                                          findings: findings))
                }
            }
        }

        section.note(file: "/etc/pam.d")
        for file in FileManager.default.contents(ofDirectory: "/etc/pam.d") {
            guard let text = try? String(contentsOfFile: "/etc/pam.d/" + file, encoding: .utf8) else { continue }
            for module in Parsers.nonStandardPAMModules(text) {
                section.add(AuditItem(id: "ext:pam:\(file):\(module)", group: "PAM modules (non-default)",
                                      title: module, value: "/etc/pam.d/\(file)",
                                      findings: [Finding(.notice, "Non-default PAM module",
                                          rationale: "PAM modules participate in authentication (sudo, login, screensaver). Verify this is expected, e.g. Touch ID for sudo.")]))
            }
        }
    }
}

extension Parsers {
    struct SystemExtension: Equatable {
        var category: String
        var enabled: Bool
        var active: Bool
        var teamID: String
        var bundleID: String
        var version: String
        var name: String
        var state: String
    }

    static func systemExtensions(_ output: String) -> [SystemExtension] {
        var category = ""
        var result: [SystemExtension] = []
        let row = /^(\*?)\t(\*?)\t(\S+)\t(\S+) \(([^)]*)\)\t(.*)\t\[(.*)\]\s*$/
        for line in output.split(separator: "\n").map(String.init) {
            if line.hasPrefix("--- ") {
                category = String(line.dropFirst(4).split(separator: " ").first ?? "")
            } else if let m = line.firstMatch(of: row) {
                result.append(SystemExtension(category: category, enabled: m.1 == "*", active: m.2 == "*",
                                              teamID: String(m.3), bundleID: String(m.4), version: String(m.5),
                                              name: String(m.6).trimmed, state: String(m.7)))
            }
        }
        return result
    }

    struct PluginKitEntry: Equatable {
        var identifier: String
        var version: String
        var election: Character?
        var fields: [String: String] = [:]

        var path: String { fields["Path"] ?? "" }
        var sdk: String { fields["SDK"] ?? "" }
        var displayName: String? { fields["Display Name"] }
        var parentName: String? { fields["Parent Name"] }
        var electionDescription: String {
            switch election {
            case "+": "Enabled by user"
            case "-": "Disabled by user"
            case "=": "Superseded"
            case "!": "Debug"
            default: "Default"
            }
        }
    }

    static func pluginkit(_ output: String) -> [PluginKitEntry] {
        var entries: [PluginKitEntry] = []
        let header = /^\s*([+\-=!])?\s+(\S+)\(([^)]*)\)\s*$/
        for line in output.split(separator: "\n").map(String.init) {
            if let eq = line.range(of: " = "), !entries.isEmpty {
                let key = line[..<eq.lowerBound].trimmed
                entries[entries.count - 1].fields[key] = String(line[eq.upperBound...]).trimmed
            } else if let m = line.firstMatch(of: header) {
                entries.append(PluginKitEntry(identifier: String(m.2), version: String(m.3), election: m.1?.first))
            }
        }
        return entries
    }

    static func extensionPointName(_ sdk: String) -> String {
        let known: [String: String] = [
            "com.apple.Safari.web-extension": "Safari web extension",
            "com.apple.Safari.extension": "Safari app extension",
            "com.apple.Safari.content-blocker": "Safari content blocker",
            "com.apple.FinderSync": "Finder Sync",
            "com.apple.share-services": "Share",
            "com.apple.quicklook.preview": "Quick Look preview",
            "com.apple.quicklook.thumbnail": "Quick Look thumbnail",
            "com.apple.fileprovider-nonui": "File Provider",
            "com.apple.widgetkit-extension": "Widget",
            "com.apple.services": "Action",
            "com.apple.spotlight.import": "Spotlight importer",
            "com.apple.photo-editing": "Photo editing",
            "com.apple.networkextension.packet-tunnel": "Packet tunnel",
            "com.apple.networkextension.filter-data": "Content filter",
            "com.apple.authentication-services-credential-provider-ui": "Password AutoFill",
            "com.apple.appintents-extension": "App Intents",
            "com.apple.intents-service": "Siri intents",
            "com.apple.message-payload-provider": "Messages",
            "com.apple.mail-extension": "Mail",
            "com.apple.usernotifications.service": "Notification service",
            "com.apple.background-asset-downloader-extension": "Background assets",
        ]
        return known[sdk] ?? sdk.replacingOccurrences(of: "com.apple.", with: "")
    }

    static func nonStandardPAMModules(_ text: String) -> [String] {
        text.split(separator: "\n").compactMap { raw in
            let line = raw.trimmed
            guard !line.hasPrefix("#"), !line.isEmpty else { return nil }
            let parts = line.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 3, parts[1] != "include", parts[1] != "substack" else { return nil }
            let module = String(parts[2])
            let standard = !module.contains("/") && (module.hasPrefix("pam_") && [
                "pam_opendirectory.so", "pam_permit.so", "pam_deny.so", "pam_unix.so", "pam_krb5.so",
                "pam_ntlm.so", "pam_launchd.so", "pam_uwtmp.so", "pam_nologin.so", "pam_rootok.so",
                "pam_smartcard.so", "pam_aks.so", "pam_sacl.so", "pam_group.so", "pam_localauthentication.so",
                "pam_self.so", "pam_env.so", "pam_mount.so", "pam_tid.so",
            ].contains(module))
            // pam_tid (Touch ID for sudo) is Apple's but opt-in, so it is still reported.
            return standard && module != "pam_tid.so" ? nil : module
        }
    }
}
