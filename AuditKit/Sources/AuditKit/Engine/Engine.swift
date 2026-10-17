import Foundation

public struct AuditContext: Sendable {
    public var runner: CommandRunner
    public var signing: CodeSignInspector
    public var homeDirectory: String
    public var isRoot: Bool
    public var hasFullDiskAccess: Bool

    public init(runner: CommandRunner = CommandRunner(), signing: CodeSignInspector = CodeSignInspector(),
                homeDirectory: String = NSHomeDirectory(), isRoot: Bool = Privileges.isRoot,
                hasFullDiskAccess: Bool = Privileges.hasFullDiskAccess) {
        self.runner = runner
        self.signing = signing
        self.homeDirectory = homeDirectory
        self.isRoot = isRoot
        self.hasFullDiskAccess = hasFullDiskAccess
    }
}

public protocol Collector: Sendable {
    var id: String { get }
    var title: String { get }
    /// SF Symbol name used by the app.
    var symbol: String { get }
    func collect(into section: inout SectionResult, context: AuditContext) async
}

extension SectionResult {
    /// Runs an allowlisted command and records it as a data source. Failures degrade coverage
    /// instead of aborting the section.
    @discardableResult
    mutating func run(_ command: AllowedCommand, context: AuditContext,
                      expectNonZeroExit: Bool = false) async -> CommandResult? {
        sources.append(.command(command.displayString))
        do {
            let result = try await context.runner.run(command)
            if result.timedOut {
                coverage.degrade(to: .partial, "\(command.displayString) timed out")
                return nil
            }
            if !result.succeeded && !expectNonZeroExit && result.combined.isEmpty {
                coverage.degrade(to: .partial, "\(command.displayString) exited with \(result.exitCode)")
            }
            return result
        } catch {
            coverage.degrade(to: .partial, "\(error)")
            return nil
        }
    }

    mutating func add(_ item: AuditItem) { items.append(item) }

    mutating func note(file path: String) { sources.append(.file(path)) }
    mutating func note(api name: String) { sources.append(.api(name)) }
}

public enum AuditProgress: Sendable {
    case started(id: String, title: String)
    case finished(SectionResult)
}

public struct AuditEngine: Sendable {
    public static let toolVersion = "0.0.2"

    public var collectors: [any Collector]

    public init(collectors: [any Collector] = AuditEngine.allCollectors) {
        self.collectors = collectors
    }

    public static var allCollectors: [any Collector] {
        [
            SystemOverviewCollector(),
            SecurityPostureCollector(),
            MalwareProtectionCollector(),
            SoftwareUpdateCollector(),
            PrivacyPermissionsCollector(),
            SharingCollector(),
            NetworkCollector(),
            ExtensionsCollector(),
            PersistenceCollector(),
            ProfilesCollector(),
            UsersCollector(),
            CertificatesCollector(),
            ApplicationsCollector(),
            BackupCollector(),
            DiagnosticsCollector(),
        ]
    }

    public func run(sections: Set<String>? = nil, context: AuditContext = AuditContext(),
                    progress: (@Sendable (AuditProgress) -> Void)? = nil) async -> AuditReport {
        let selected = collectors.filter { sections?.contains($0.id) ?? true }
        let order = Dictionary(uniqueKeysWithValues: selected.enumerated().map { ($1.id, $0) })

        let results = await withTaskGroup(of: SectionResult.self) { group in
            for collector in selected {
                group.addTask {
                    progress?(.started(id: collector.id, title: collector.title))
                    let start = Date()
                    var section = SectionResult(id: collector.id, title: collector.title, symbol: collector.symbol)
                    await collector.collect(into: &section, context: context)
                    section.duration = Date().timeIntervalSince(start)
                    progress?(.finished(section))
                    return section
                }
            }
            var all: [SectionResult] = []
            for await r in group { all.append(r) }
            return all
        }

        return AuditReport(
            generatedAt: Date(),
            toolVersion: Self.toolVersion,
            host: SystemInfo.hostInfo,
            sections: results.sorted { order[$0.id, default: 0] < order[$1.id, default: 0] }
        )
    }
}
