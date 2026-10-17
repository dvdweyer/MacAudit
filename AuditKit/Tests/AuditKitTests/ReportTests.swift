import Testing
import Foundation
@testable import AuditKit

@Suite struct ReportTests {
    func report(_ items: [AuditItem], date: Date = Date()) -> AuditReport {
        AuditReport(generatedAt: date, toolVersion: "test",
                    host: HostInfo(hostname: "mac", osVersion: "27.0", osBuild: "26A1", user: "alice",
                                   runningAsRoot: false, fullDiskAccess: true),
                    sections: [SectionResult(id: "s", title: "Section", symbol: "x", items: items)])
    }

    @Test func jsonRoundTrip() throws {
        let original = report([AuditItem(id: "a", group: "g", title: "A", value: "1",
                                         findings: [Finding(.warning, "w", rationale: "r")])])
        let decoded = try JSONExporter.decode(JSONExporter.encode(original))
        #expect(decoded.sections[0].items[0].findings[0].severity == .warning)
        #expect(decoded.schemaVersion == AuditReport.schemaVersion)
        #expect(abs(decoded.generatedAt.timeIntervalSince(original.generatedAt)) < 1)
    }

    @Test func diffDetectsChanges() {
        let old = report([
            AuditItem(id: "keep", group: "g", title: "Keep", value: "same"),
            AuditItem(id: "change", group: "g", title: "Change", value: "Off"),
            AuditItem(id: "gone", group: "g", title: "Gone", value: "x"),
            AuditItem(id: "pid", group: "g", title: "Listener", value: "v", details: ["PID": "1"]),
        ])
        let new = report([
            AuditItem(id: "keep", group: "g", title: "Keep", value: "same"),
            AuditItem(id: "change", group: "g", title: "Change", value: "On",
                      findings: [Finding(.warning, "Now on", rationale: "")]),
            AuditItem(id: "new", group: "g", title: "New", value: "y"),
            AuditItem(id: "pid", group: "g", title: "Listener", value: "v", details: ["PID": "2"]),
        ])
        let diff = ReportDiff(old: old, new: new)
        let byKind = Dictionary(grouping: diff.changes, by: \.kind)
        #expect(byKind[.added]?.map(\.itemID) == ["new"])
        #expect(byKind[.removed]?.map(\.itemID) == ["gone"])
        #expect(byKind[.changed]?.map(\.itemID) == ["change"])
        #expect(byKind[.changed]?.first?.newFindings.count == 1)
    }

    @Test func htmlEscapes() {
        let html = HTMLRenderer.render(report([AuditItem(id: "x", group: "<g>", title: "<script>", value: "a&b")]))
        #expect(!html.contains("<script>"))
        #expect(html.contains("&lt;script&gt;"))
        #expect(html.contains("a&amp;b"))
    }

    @Test func snapshotStore() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("snap-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = SnapshotStore(directory: dir)
        let url = try store.save(report([AuditItem(id: "a", group: "g", title: "A", value: "1")]))
        #expect(store.list().map(\.lastPathComponent) == [url.lastPathComponent])
        #expect(try store.load(url).sections[0].items.count == 1)
    }
}
