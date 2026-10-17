import Foundation

/// Reads browser extension manifests straight from browser profile folders (no browser APIs exist for this).
enum BrowserExtensions {
    static let chromium: [(browser: String, root: String)] = [
        ("Chrome", "Library/Application Support/Google/Chrome"),
        ("Edge", "Library/Application Support/Microsoft Edge"),
        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Arc", "Library/Application Support/Arc/User Data"),
        ("Vivaldi", "Library/Application Support/Vivaldi"),
        ("Chromium", "Library/Application Support/Chromium"),
    ]

    static let broadHosts: Set<String> = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"]

    static func collect(into section: inout SectionResult, home: String) {
        let fm = FileManager.default
        for b in chromium {
            let root = home + "/" + b.root
            guard fm.isDirectory(root) else { continue }
            section.note(file: "~/" + b.root)
            for profile in fm.contents(ofDirectory: root) where profile == "Default" || profile.hasPrefix("Profile ") {
                let extDir = root + "/" + profile + "/Extensions"
                for extID in fm.contents(ofDirectory: extDir) {
                    guard let version = fm.contents(ofDirectory: extDir + "/" + extID).last else { continue }
                    let dir = extDir + "/" + extID + "/" + version
                    guard let data = fm.contents(atPath: dir + "/manifest.json"),
                          let manifest = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
                    let name = localizedName(manifest, dir: dir) ?? extID
                    var hosts = (manifest["host_permissions"] as? [String] ?? [])
                        + (manifest["permissions"] as? [String] ?? [])
                    for script in manifest["content_scripts"] as? [[String: Any]] ?? [] {
                        hosts += script["matches"] as? [String] ?? []
                    }
                    section.add(item(browser: b.browser, profile: profile, id: extID, name: name,
                                     version: manifest["version"] as? String ?? version,
                                     permissions: hosts, manifestPath: dir + "/manifest.json"))
                }
            }
        }
        collectFirefox(into: &section, home: home)
    }

    static func collectFirefox(into section: inout SectionResult, home: String) {
        let root = home + "/Library/Application Support/Firefox/Profiles"
        let fm = FileManager.default
        guard fm.isDirectory(root) else { return }
        section.note(file: "~/Library/Application Support/Firefox/Profiles/*/extensions.json")
        for profile in fm.contents(ofDirectory: root) {
            guard let data = fm.contents(atPath: root + "/" + profile + "/extensions.json"),
                  let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
            for addon in json["addons"] as? [[String: Any]] ?? [] {
                guard addon["type"] as? String == "extension",
                      let location = addon["location"] as? String,
                      !location.hasPrefix("app-") else { continue }
                let id = addon["id"] as? String ?? "?"
                let name = (addon["defaultLocale"] as? [String: Any])?["name"] as? String ?? id
                let perms = (addon["userPermissions"] as? [String: Any])?["origins"] as? [String] ?? []
                var it = item(browser: "Firefox", profile: profile, id: id, name: name,
                              version: addon["version"] as? String ?? "", permissions: perms, manifestPath: nil)
                it.value = (addon["active"] as? Bool ?? false) ? "Enabled" : "Disabled"
                section.add(it)
            }
        }
    }

    private static func item(browser: String, profile: String, id: String, name: String, version: String,
                             permissions: [String], manifestPath: String?) -> AuditItem {
        let broad = permissions.contains { broadHosts.contains($0) }
        let native = permissions.contains("nativeMessaging")
        var findings: [Finding] = []
        if broad {
            findings.append(Finding(.notice, "Access to all websites",
                rationale: "This extension can read and change data on every site you visit."))
        }
        if native {
            findings.append(Finding(.info, "Native messaging",
                rationale: "This extension can communicate with a program installed on the Mac."))
        }
        var details = ["Browser": browser, "Profile": profile, "ID": id, "Version": version,
                       "Permissions": Array(Set(permissions)).sorted().joined(separator: "\n")]
        if let manifestPath { details["Manifest"] = manifestPath }
        return AuditItem(id: "ext:browser:\(browser):\(profile):\(id)", group: "Browser extensions: \(browser)",
                         title: name, value: "Installed", details: details, findings: findings)
    }

    static func localizedName(_ manifest: [String: Any], dir: String) -> String? {
        guard let raw = manifest["name"] as? String else { return nil }
        guard raw.hasPrefix("__MSG_"), raw.hasSuffix("__") else { return raw }
        let key = String(raw.dropFirst(6).dropLast(2)).lowercased()
        let locales = [manifest["default_locale"] as? String, "en", "en_US"].compactMap { $0 }
        for locale in locales {
            guard let data = FileManager.default.contents(atPath: "\(dir)/_locales/\(locale)/messages.json"),
                  let messages = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { continue }
            if let entry = messages.first(where: { $0.key.lowercased() == key })?.value as? [String: Any],
               let message = entry["message"] as? String {
                return message
            }
        }
        return raw
    }
}
