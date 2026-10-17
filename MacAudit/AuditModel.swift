import SwiftUI
import AuditKit
import UniformTypeIdentifiers

enum SidebarItem: Hashable {
    case overview
    case section(String)
    case compare
}

@MainActor @Observable
final class AuditModel {
    var report: AuditReport?
    var isRunning = false
    var runningSections: Set<String> = []
    var completedSections: [SectionResult] = []
    var selection: SidebarItem? = .overview
    var hasFullDiskAccess = Privileges.hasFullDiskAccess
    var snapshots: [URL] = []
    var diff: ReportDiff?
    var errorMessage: String?

    let store = SnapshotStore()
    let collectors = AuditEngine.allCollectors

    init() {
        snapshots = store.list()
    }

    func section(_ id: String) -> SectionResult? {
        report?.sections.first { $0.id == id } ?? completedSections.first { $0.id == id }
    }

    func runAudit() {
        guard !isRunning else { return }
        isRunning = true
        hasFullDiskAccess = Privileges.hasFullDiskAccess
        completedSections = []
        runningSections = Set(collectors.map(\.id))
        Task {
            let report = await AuditEngine().run { progress in
                if case .finished(let section) = progress {
                    Task { @MainActor in
                        self.runningSections.remove(section.id)
                        self.completedSections.append(section)
                    }
                }
            }
            self.report = report
            self.isRunning = false
            self.runningSections = []
            do {
                try store.save(report)
                snapshots = store.list()
            } catch {
                errorMessage = "Could not save snapshot: \(error.localizedDescription)"
            }
        }
    }

    func compare(with url: URL) {
        guard let report else { return }
        do {
            diff = ReportDiff(old: try store.load(url), new: report)
        } catch {
            errorMessage = "Could not load snapshot: \(error.localizedDescription)"
        }
    }

    func compareWithFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        compare(with: url)
    }

    func refreshFullDiskAccess() {
        hasFullDiskAccess = Privileges.hasFullDiskAccess
    }

    func openFullDiskAccessSettings() {
        NSWorkspace.shared.open(Privileges.fullDiskAccessSettingsURL)
    }

    // MARK: Export

    enum ExportFormat { case json, html, pdf }

    func export(_ format: ExportFormat) {
        guard let report else { return }
        let panel = NSSavePanel()
        let base = "MacAudit-\(report.host.hostname)-\(report.generatedAt.formatted(.iso8601.year().month().day()))"
        switch format {
        case .json:
            panel.allowedContentTypes = [.json]
            panel.nameFieldStringValue = base + ".json"
        case .html:
            panel.allowedContentTypes = [.html]
            panel.nameFieldStringValue = base + ".html"
        case .pdf:
            panel.allowedContentTypes = [.pdf]
            panel.nameFieldStringValue = base + ".pdf"
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            switch format {
            case .json: try JSONExporter.encode(report).write(to: url, options: .atomic)
            case .html: try Data(HTMLRenderer.render(report).utf8).write(to: url, options: .atomic)
            case .pdf: PDFExporter.shared.export(html: HTMLRenderer.render(report), to: url) { [weak self] error in
                if let error { self?.errorMessage = "PDF export failed: \(error.localizedDescription)" }
            }
            }
        } catch {
            errorMessage = "Export failed: \(error.localizedDescription)"
        }
    }
}
