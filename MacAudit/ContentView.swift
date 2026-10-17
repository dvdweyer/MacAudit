import SwiftUI
import AuditKit

struct ContentView: View {
    @Environment(AuditModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                Label("Overview", systemImage: "gauge.with.dots.needle.33percent")
                    .tag(SidebarItem.overview)
                Section("Audit") {
                    ForEach(model.collectors, id: \.id) { collector in
                        SidebarRow(id: collector.id, title: collector.title, symbol: collector.symbol)
                            .tag(SidebarItem.section(collector.id))
                    }
                }
                Section("History") {
                    Label("Compare Snapshots", systemImage: "arrow.left.arrow.right")
                        .tag(SidebarItem.compare)
                }
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            VStack(spacing: 0) {
                if !model.hasFullDiskAccess {
                    FullDiskAccessBanner()
                }
                switch model.selection {
                case .section(let id):
                    SectionDetailView(sectionID: id)
                case .compare:
                    CompareView()
                default:
                    OverviewView()
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.runAudit()
                } label: {
                    Label("Run Audit", systemImage: "play.fill")
                }
                .disabled(model.isRunning)
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("JSON…") { model.export(.json) }
                    Button("HTML Report…") { model.export(.html) }
                    Button("PDF Report…") { model.export(.pdf) }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .disabled(model.report == nil)
            }
        }
        .alert("Error", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.refreshFullDiskAccess()
        }
    }
}

struct SidebarRow: View {
    @Environment(AuditModel.self) private var model
    let id: String
    let title: String
    let symbol: String

    var body: some View {
        HStack {
            Label(title, systemImage: symbol)
            Spacer()
            if model.runningSections.contains(id) {
                ProgressView().controlSize(.small)
            } else if let section = model.section(id) {
                if section.coverage.status != .complete {
                    Image(systemName: section.coverage.status == .unavailable ? "eye.slash" : "circle.lefthalf.filled")
                        .foregroundStyle(.secondary)
                        .help(section.coverage.notes.joined(separator: "\n"))
                }
                if let severity = section.highestSeverity, severity >= .notice {
                    let count = section.findings.filter { $0.severity >= .notice }.count
                    Text("\(count)")
                        .font(.caption.monospacedDigit().weight(.semibold))
                        .padding(.horizontal, 6)
                        .background(severity.color.opacity(0.18), in: Capsule())
                        .foregroundStyle(severity.color)
                }
            }
        }
    }
}

struct FullDiskAccessBanner: View {
    @Environment(AuditModel.self) private var model

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.trianglebadge.exclamationmark")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Full Disk Access not granted").font(.headline)
                Text("Privacy permissions (TCC) and some other data cannot be read. MacAudit only reads; it never changes settings.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open System Settings") { model.openFullDiskAccessSettings() }
        }
        .padding(12)
        .background(.orange.opacity(0.1))
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .info: .blue
        case .notice: .orange
        case .warning: .red
        case .critical: .purple
        }
    }

    var symbol: String {
        switch self {
        case .info: "info.circle.fill"
        case .notice: "exclamationmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .critical: "xmark.octagon.fill"
        }
    }

    var label: String { rawValue.capitalized }
}
