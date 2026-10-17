import SwiftUI
import AuditKit

struct OverviewView: View {
    @Environment(AuditModel.self) private var model

    var body: some View {
        if let report = model.report {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header(report)
                    counts(report)
                    keyFindings(report)
                    coverage(report)
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else if model.isRunning {
            VStack(spacing: 12) {
                ProgressView(value: Double(model.completedSections.count), total: Double(model.collectors.count))
                    .frame(width: 280)
                Text("Auditing… \(model.completedSections.count) of \(model.collectors.count) sections")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ContentUnavailableView {
                Label("No Audit Yet", systemImage: "checklist")
            } description: {
                Text("MacAudit reads this Mac's security configuration without changing anything.")
            } actions: {
                Button("Run Audit") { model.runAudit() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut("r")
            }
        }
    }

    private func header(_ report: AuditReport) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(report.host.hostname).font(.largeTitle.weight(.semibold))
            Text("macOS \(report.host.osVersion) (\(report.host.osBuild)) · audited \(report.generatedAt.formatted(date: .abbreviated, time: .shortened)) as \(report.host.user)")
                .foregroundStyle(.secondary)
        }
    }

    private func counts(_ report: AuditReport) -> some View {
        HStack(spacing: 12) {
            ForEach(Severity.allCases.reversed(), id: \.self) { severity in
                VStack(alignment: .leading, spacing: 4) {
                    Label(severity.label, systemImage: severity.symbol)
                        .font(.callout)
                        .foregroundStyle(severity.color)
                    Text("\(report.findingCount(severity))")
                        .font(.system(size: 30, weight: .semibold).monospacedDigit())
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    private func keyFindings(_ report: AuditReport) -> some View {
        let rows = report.sections.flatMap { section in
            section.items.flatMap { item in item.findings.map { (section: section, item: item, finding: $0) } }
        }
        .filter { $0.finding.severity >= .notice }
        .sorted { $0.finding.severity > $1.finding.severity }

        return VStack(alignment: .leading, spacing: 8) {
            Text("Key Findings").font(.title2.weight(.semibold))
            if rows.isEmpty {
                Text("No notable findings.").foregroundStyle(.secondary)
            }
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                Button {
                    model.selection = .section(row.section.id)
                } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: row.finding.severity.symbol)
                            .foregroundStyle(row.finding.severity.color)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.finding.title).fontWeight(.medium)
                            Text("\(row.section.title) › \(row.item.title)")
                                .font(.callout).foregroundStyle(.secondary)
                            Text(row.finding.rationale)
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                Divider()
            }
        }
    }

    private func coverage(_ report: AuditReport) -> some View {
        let incomplete = report.sections.filter { $0.coverage.status != .complete }
        return VStack(alignment: .leading, spacing: 8) {
            Text("Coverage").font(.title2.weight(.semibold))
            if incomplete.isEmpty {
                Text("All sections were fully audited.").foregroundStyle(.secondary)
            }
            ForEach(incomplete) { section in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(section.title) — \(section.coverage.status.rawValue)").fontWeight(.medium)
                    ForEach(section.coverage.notes, id: \.self) { note in
                        Text(note).font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            if !report.host.runningAsRoot {
                Text("Tip: `sudo macaudit run` from Terminal covers root-only data as well.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}
