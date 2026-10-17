import Foundation
import Darwin

public struct ApplicationsCollector: Collector {
    public let id = "applications"
    public let title = "Applications"
    public let symbol = "app.badge.checkmark"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let roots = ["/Applications", "/Applications/Utilities", context.homeDirectory + "/Applications"]
        var seen = Set<String>()
        for root in roots {
            section.note(file: root)
            for path in Self.appBundles(in: root) where seen.insert(path).inserted {
                section.add(await item(for: path, context: context))
            }
        }
    }

    /// .app bundles at the top level and one folder deep (e.g. /Applications/Vendor/App.app).
    static func appBundles(in root: String) -> [String] {
        let fm = FileManager.default
        var result: [String] = []
        for entry in fm.contents(ofDirectory: root) {
            let path = root + "/" + entry
            if entry.hasSuffix(".app") {
                result.append(path)
            } else if fm.isDirectory(path), entry != "Utilities" {
                result += fm.contents(ofDirectory: path).filter { $0.hasSuffix(".app") }.map { path + "/" + $0 }
            }
        }
        return result
    }

    private func item(for path: String, context: AuditContext) async -> AuditItem {
        let info = PlistReader.dictionary(at: path + "/Contents/Info.plist") ?? [:]
        let name = (path as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "")
        let version = info["CFBundleShortVersionString"] as? String ?? info["CFBundleVersion"] as? String ?? ""
        let bundleID = info["CFBundleIdentifier"] as? String ?? ""
        let signing = await context.signing.inspect(path: path)

        var details: [String: String] = ["Path": path, "Bundle ID": bundleID, "Version": version]
        details.merge(signing.details) { a, _ in a }
        if let archs = Bundle(path: path)?.executableArchitectures?.map({ $0.intValue }) {
            details["Architectures"] = archs.map {
                switch $0 {
                case NSBundleExecutableArchitectureARM64: "arm64"
                case NSBundleExecutableArchitectureX86_64: "x86_64"
                default: "other"
                }
            }.joined(separator: ", ")
        }
        if let quarantine = Self.xattr("com.apple.quarantine", path: path) {
            details["Quarantine"] = quarantine
        }
        if let minOS = info["LSMinimumSystemVersion"] as? String { details["Minimum macOS"] = minOS }

        var findings: [Finding] = []
        if bundleID.hasPrefix("com.apple.Safari.WebApp") {
            // Safari "Add to Dock" web apps are ad-hoc signed by Safari itself.
            return AuditItem(id: "app:\(path)", group: "Safari web apps", title: name, value: "Safari web app", details: details)
        }
        switch signing.status {
        case .unsigned:
            findings.append(Finding(.warning, "Unsigned application", rationale: "Its origin and integrity cannot be verified."))
        case .adhoc:
            findings.append(Finding(.notice, "Ad-hoc signed application",
                                    rationale: "Signed without a developer identity; common for locally built or open-source apps."))
        case .invalid:
            findings.append(Finding(.warning, "Invalid code signature",
                                    rationale: "The app was modified after signing or its signature is damaged. \(signing.error ?? "")"))
        case .valid where signing.isUntrusted:
            findings.append(Finding(.notice, "Not notarized", rationale: "Apple has not scanned this app for malware."))
        default:
            break
        }
        return AuditItem(id: "app:\(path)", group: path.hasPrefix(context.homeDirectory) ? "User applications" : "Applications",
                         title: name, value: [version, signing.summary].filter { !$0.isEmpty }.joined(separator: " · "),
                         details: details, findings: findings)
    }

    static func xattr(_ name: String, path: String) -> String? {
        let size = getxattr(path, name, nil, 0, 0, 0)
        guard size > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard getxattr(path, name, &buffer, size, 0, 0) == size else { return nil }
        return String(decoding: buffer, as: UTF8.self)
    }
}
