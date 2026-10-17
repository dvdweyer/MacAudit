import Foundation

public enum Severity: String, Codable, Sendable, CaseIterable, Comparable {
    case info, notice, warning, critical

    private var rank: Int {
        switch self {
        case .info: 0
        case .notice: 1
        case .warning: 2
        case .critical: 3
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

public struct Finding: Codable, Sendable, Hashable {
    public var severity: Severity
    public var title: String
    public var rationale: String

    public init(_ severity: Severity, _ title: String, rationale: String) {
        self.severity = severity
        self.title = title
        self.rationale = rationale
    }
}

public enum DataSource: Codable, Sendable, Hashable {
    case api(String)
    case file(String)
    case command(String)

    public var label: String {
        switch self {
        case .api(let s): "API: \(s)"
        case .file(let s): "File: \(s)"
        case .command(let s): "Command: \(s)"
        }
    }
}

public enum CoverageStatus: String, Codable, Sendable {
    case complete, partial, unavailable
}

public struct Coverage: Codable, Sendable, Hashable {
    public var status: CoverageStatus
    public var notes: [String]

    public init(_ status: CoverageStatus = .complete, notes: [String] = []) {
        self.status = status
        self.notes = notes
    }

    public mutating func degrade(to status: CoverageStatus, _ note: String) {
        if status == .unavailable || self.status == .complete {
            self.status = status
        }
        notes.append(note)
    }
}

public struct AuditItem: Codable, Sendable, Identifiable, Hashable {
    /// Stable across runs so snapshots can be diffed.
    public var id: String
    public var group: String
    public var title: String
    public var value: String
    public var details: [String: String]
    public var findings: [Finding]

    public init(id: String, group: String, title: String, value: String,
                details: [String: String] = [:], findings: [Finding] = []) {
        self.id = id
        self.group = group
        self.title = title
        self.value = value
        self.details = details
        self.findings = findings
    }

    public var highestSeverity: Severity? { findings.map(\.severity).max() }
}

public struct SectionResult: Codable, Sendable, Identifiable {
    public var id: String
    public var title: String
    public var symbol: String
    public var items: [AuditItem]
    public var sources: [DataSource]
    public var coverage: Coverage
    public var duration: TimeInterval

    public init(id: String, title: String, symbol: String, items: [AuditItem] = [],
                sources: [DataSource] = [], coverage: Coverage = Coverage(), duration: TimeInterval = 0) {
        self.id = id
        self.title = title
        self.symbol = symbol
        self.items = items
        self.sources = sources
        self.coverage = coverage
        self.duration = duration
    }

    public var findings: [Finding] { items.flatMap(\.findings) }
    public var highestSeverity: Severity? { findings.map(\.severity).max() }
}

public struct HostInfo: Codable, Sendable {
    public var hostname: String
    public var osVersion: String
    public var osBuild: String
    public var user: String
    public var runningAsRoot: Bool
    public var fullDiskAccess: Bool
}

public struct AuditReport: Codable, Sendable {
    public static let schemaVersion = 1

    public var schemaVersion: Int
    public var generatedAt: Date
    public var toolVersion: String
    public var host: HostInfo
    public var sections: [SectionResult]

    public init(generatedAt: Date, toolVersion: String, host: HostInfo, sections: [SectionResult]) {
        self.schemaVersion = Self.schemaVersion
        self.generatedAt = generatedAt
        self.toolVersion = toolVersion
        self.host = host
        self.sections = sections
    }

    public var findings: [Finding] { sections.flatMap(\.findings) }

    public func findingCount(_ severity: Severity) -> Int {
        findings.filter { $0.severity == severity }.count
    }
}
