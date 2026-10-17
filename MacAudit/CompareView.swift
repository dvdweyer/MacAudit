import SwiftUI
import AuditKit

struct CompareView: View {
    @Environment(AuditModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Menu("Compare current audit with…") {
                    ForEach(model.snapshots.filter { $0.lastPathComponent != currentSnapshotName }, id: \.self) { url in
                        Button(url.deletingPathExtension().lastPathComponent) { model.compare(with: url) }
                    }
                    Divider()
                    Button("Choose File…") { model.compareWithFile() }
                }
                .fixedSize()
                .disabled(model.report == nil)
                Spacer()
                Button("Show Snapshots in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([model.store.directory])
                }
            }
            .padding(12)
            Divider()

            if model.report == nil {
                ContentUnavailableView("Run an Audit First", systemImage: "arrow.left.arrow.right",
                                       description: Text("Each audit is saved as a snapshot. Compare the current audit with an earlier one to see what changed."))
            } else if let diff = model.diff {
                diffList(diff)
            } else {
                ContentUnavailableView("Choose a Snapshot", systemImage: "clock.arrow.circlepath",
                                       description: Text("\(model.snapshots.count) snapshot(s) available."))
            }
        }
        .navigationTitle("Compare Snapshots")
    }

    private var currentSnapshotName: String? {
        model.report.map { "audit-\($0.generatedAt.formatted(.iso8601).replacingOccurrences(of: ":", with: "-")).json" }
    }

    private func diffList(_ diff: ReportDiff) -> some View {
        let bySection = Dictionary(grouping: diff.changes, by: \.section)
        return List {
            Section {
                Text("\(diff.changes.count) change(s) since \(diff.old.generatedAt.formatted(date: .abbreviated, time: .shortened))")
                    .foregroundStyle(.secondary)
            }
            ForEach(bySection.keys.sorted(), id: \.self) { section in
                Section(section) {
                    ForEach(bySection[section] ?? []) { change in
                        ChangeRow(change: change)
                    }
                }
            }
        }
    }
}

struct ChangeRow: View {
    let change: ReportDiff.Change

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(change.title).fontWeight(.medium)
                Group {
                    switch change.kind {
                    case .added: Text(change.after ?? "")
                    case .removed: Text("was: \(change.before ?? "")")
                    case .changed: Text("\(change.before ?? "") → \(change.after ?? "")")
                    }
                }
                .font(.callout).foregroundStyle(.secondary)
                ForEach(change.newFindings, id: \.self) { f in
                    Label(f.title, systemImage: f.severity.symbol)
                        .font(.callout).foregroundStyle(f.severity.color)
                }
            }
        }
    }

    private var icon: String {
        switch change.kind {
        case .added: "plus.circle.fill"
        case .removed: "minus.circle.fill"
        case .changed: "pencil.circle.fill"
        }
    }

    private var color: Color {
        switch change.kind {
        case .added: .green
        case .removed: .red
        case .changed: .orange
        }
    }
}
