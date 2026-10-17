import SwiftUI
import AuditKit
import UniformTypeIdentifiers
import ServiceManagement

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
    var helperStatus: SMAppService.Status = .notRegistered
    /// Set when the helper is enabled but could not be reached during the last audit.
    var helperProblem: String?

    let store = SnapshotStore()
    let collectors = AuditEngine.allCollectors
    private let helperService = SMAppService.daemon(plistName: PrivilegedHelper.plistName)

    init() {
        snapshots = store.list()
        refreshHelperStatus()
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
            let context = AuditContext(privileged: await connectHelper())
            let report = await AuditEngine().run(context: context) { progress in
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

    // MARK: Privileged helper

    func refreshHelperStatus() {
        helperStatus = helperService.status
    }

    func installHelper() {
        do {
            try helperService.register()
        } catch {
            refreshHelperStatus()
            // register() reports an error when the user still has to approve the daemon.
            if helperStatus != .requiresApproval {
                errorMessage = "Could not install the helper: \(error.localizedDescription)"
            }
        }
        refreshHelperStatus()
        if helperStatus == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    func removeHelper() {
        Task {
            do {
                try await helperService.unregister()
            } catch {
                errorMessage = "Could not remove the helper: \(error.localizedDescription)"
            }
            refreshHelperStatus()
        }
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private func connectHelper() async -> (any PrivilegedAccess)? {
        refreshHelperStatus()
        helperProblem = nil
        guard helperStatus == .enabled else { return nil }
        guard PrivilegedCaller(uid: getuid()).isAdministrator else {
            helperProblem = "Root access through the helper is only available to administrator accounts."
            return nil
        }
        let client = XPCPrivilegedAccess()
        do {
            _ = try await client.version()
            return client
        } catch {
            helperProblem = "The privileged helper is enabled but did not respond: \(error.localizedDescription)"
            return nil
        }
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
