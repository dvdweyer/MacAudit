import Foundation

public enum JSONExporter {
    public static func encode(_ report: AuditReport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(report)
    }

    public static func decode(_ data: Data) throws -> AuditReport {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AuditReport.self, from: data)
    }
}

public struct ReportDiff: Sendable {
    public struct Change: Sendable, Identifiable {
        public enum Kind: String, Sendable { case added, removed, changed }
        public var id: String { kind.rawValue + ":" + itemID }
        public var kind: Kind
        public var section: String
        public var itemID: String
        public var title: String
        public var before: String?
        public var after: String?
        public var newFindings: [Finding]
    }

    public var old: AuditReport
    public var new: AuditReport
    public var changes: [Change]

    /// Details that legitimately change between runs and would otherwise drown real changes.
    static let volatileDetailKeys: Set<String> = ["PID", "Booted", "Last failed login", "Failed login count"]
    static let volatileItemIDs: Set<String> = ["system:uptime", "updates:lastcheck"]

    public init(old: AuditReport, new: AuditReport) {
        self.old = old
        self.new = new
        var changes: [Change] = []
        let oldSections = Dictionary(uniqueKeysWithValues: old.sections.map { ($0.id, $0) })
        for section in new.sections {
            let before = Dictionary(oldSections[section.id]?.items.map { ($0.id, $0) } ?? [], uniquingKeysWith: { a, _ in a })
            let after = Dictionary(section.items.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            for item in section.items {
                guard let prev = before[item.id] else {
                    changes.append(Change(kind: .added, section: section.title, itemID: item.id, title: item.title,
                                          before: nil, after: item.value, newFindings: item.findings))
                    continue
                }
                guard !Self.volatileItemIDs.contains(item.id) else { continue }
                let detailsChanged = Self.stable(prev.details) != Self.stable(item.details)
                if prev.value != item.value || detailsChanged || Set(prev.findings) != Set(item.findings) {
                    var description = item.value
                    if prev.value == item.value, detailsChanged {
                        let keys = Set(prev.details.keys).union(item.details.keys)
                            .filter { !Self.volatileDetailKeys.contains($0) && prev.details[$0] != item.details[$0] }
                        description += " (changed: \(keys.sorted().joined(separator: ", ")))"
                    }
                    changes.append(Change(kind: .changed, section: section.title, itemID: item.id, title: item.title,
                                          before: prev.value, after: description,
                                          newFindings: item.findings.filter { !prev.findings.contains($0) }))
                }
            }
            for item in oldSections[section.id]?.items ?? [] where after[item.id] == nil {
                changes.append(Change(kind: .removed, section: section.title, itemID: item.id, title: item.title,
                                      before: item.value, after: nil, newFindings: []))
            }
        }
        self.changes = changes
    }

    static func stable(_ details: [String: String]) -> [String: String] {
        details.filter { !volatileDetailKeys.contains($0.key) }
    }

    public var textSummary: String {
        var lines = ["Changes from \(old.generatedAt.auditString) to \(new.generatedAt.auditString): \(changes.count)"]
        for c in changes {
            let sign = switch c.kind { case .added: "+"; case .removed: "-"; case .changed: "~" }
            var line = "\(sign) [\(c.section)] \(c.title)"
            switch c.kind {
            case .added: line += ": \(c.after ?? "")"
            case .removed: line += " (was: \(c.before ?? ""))"
            case .changed: line += ": \(c.before ?? "") → \(c.after ?? "")"
            }
            lines.append(line)
            for f in c.newFindings { lines.append("    [\(f.severity.rawValue)] \(f.title)") }
        }
        return lines.joined(separator: "\n")
    }
}

public final class SnapshotStore: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MacAudit/Snapshots", isDirectory: true)
    }

    @discardableResult
    public func save(_ report: AuditReport) throws -> URL {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let name = report.generatedAt.formatted(.iso8601).replacingOccurrences(of: ":", with: "-")
        let url = directory.appendingPathComponent("audit-\(name).json")
        try JSONExporter.encode(report).write(to: url, options: .atomic)
        return url
    }

    public func list() -> [URL] {
        ((try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    public func load(_ url: URL) throws -> AuditReport {
        try JSONExporter.decode(Data(contentsOf: url))
    }
}

public enum TextRenderer {
    public static func render(_ report: AuditReport) -> String {
        var out = """
        MacAudit \(report.toolVersion) — \(report.host.hostname) — macOS \(report.host.osVersion) (\(report.host.osBuild))
        Generated \(report.generatedAt.auditString) as \(report.host.user)\(report.host.runningAsRoot ? " (root)" : "") · Full Disk Access: \(report.host.fullDiskAccess ? "yes" : "no")
        Findings: \(Severity.allCases.reversed().map { "\(report.findingCount($0)) \($0.rawValue)" }.joined(separator: ", "))

        """
        for section in report.sections {
            out += "\n== \(section.title) [\(section.coverage.status.rawValue)] ==\n"
            for note in section.coverage.notes { out += "  ! \(note)\n" }
            var group = ""
            for item in section.items {
                if item.group != group {
                    group = item.group
                    out += "  -- \(group)\n"
                }
                out += "    \(item.title): \(item.value)\n"
                for f in item.findings { out += "      [\(f.severity.rawValue.uppercased())] \(f.title)\n" }
            }
        }
        return out
    }
}
