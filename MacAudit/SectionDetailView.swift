import SwiftUI
import AuditKit

struct SectionDetailView: View {
    @Environment(AuditModel.self) private var model
    let sectionID: String

    @State private var search = ""
    @State private var onlyFindings = false
    @State private var selectedItemID: AuditItem.ID?
    @State private var showInspector = true

    var body: some View {
        Group {
            if let section = model.section(sectionID) {
                content(section)
            } else if model.runningSections.contains(sectionID) {
                ProgressView("Auditing…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ContentUnavailableView("Not Audited Yet", systemImage: "checklist",
                                       description: Text("Run an audit to see this section."))
            }
        }
        .onChange(of: sectionID) { selectedItemID = nil }
    }

    private func content(_ section: SectionResult) -> some View {
        let items = filtered(section.items)
        let groups = Dictionary(grouping: items, by: \.group)
        let order = section.items.map(\.group).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
            .filter { groups[$0] != nil }

        return List(selection: $selectedItemID) {
            if section.coverage.status != .complete {
                Section {
                    ForEach(section.coverage.notes, id: \.self) { note in
                        Label(note, systemImage: "circle.lefthalf.filled")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            ForEach(order, id: \.self) { group in
                Section("\(group) (\(groups[group]?.count ?? 0))") {
                    ForEach(groups[group] ?? []) { item in
                        ItemRow(item: item).tag(item.id)
                    }
                }
            }
        }
        .searchable(text: $search, placement: .toolbar)
        .navigationTitle(section.title)
        .navigationSubtitle("\(section.items.count) items · \(String(format: "%.1f", section.duration))s")
        .toolbar {
            ToolbarItem {
                Toggle(isOn: $onlyFindings) {
                    Label("Only Findings", systemImage: "line.3.horizontal.decrease.circle")
                }
                .help("Show only items with findings")
            }
            ToolbarItem {
                Toggle(isOn: $showInspector) {
                    Label("Inspector", systemImage: "sidebar.right")
                }
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if let id = selectedItemID, let item = section.items.first(where: { $0.id == id }) {
                    ItemInspector(item: item)
                } else {
                    SourcesInspector(section: section)
                }
            }
            .inspectorColumnWidth(min: 260, ideal: 340)
        }
    }

    private func filtered(_ items: [AuditItem]) -> [AuditItem] {
        items.filter { item in
            if onlyFindings && item.findings.isEmpty { return false }
            guard !search.isEmpty else { return true }
            let q = search.lowercased()
            return item.title.lowercased().contains(q) || item.value.lowercased().contains(q)
                || item.group.lowercased().contains(q)
                || item.details.values.contains { $0.lowercased().contains(q) }
        }
    }
}

struct ItemRow: View {
    let item: AuditItem

    var body: some View {
        HStack(spacing: 8) {
            if let severity = item.highestSeverity {
                Image(systemName: severity.symbol)
                    .foregroundStyle(severity.color)
                    .help(item.findings.map(\.title).joined(separator: "\n"))
            } else {
                Image(systemName: "circle.fill")
                    .font(.system(size: 5))
                    .foregroundStyle(.tertiary)
                    .frame(width: 16)
            }
            Text(item.title)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 12)
            Text(item.value)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            if let url = item.settingsURL {
                Button("Open") { NSWorkspace.shared.open(url) }
                    .controlSize(.small)
                    .help("Open this pane in System Settings")
            }
        }
    }
}

struct ItemInspector: View {
    let item: AuditItem

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.title).font(.title3.weight(.semibold)).textSelection(.enabled)
                    Text(item.value).foregroundStyle(.secondary).textSelection(.enabled)
                }
                ForEach(item.findings, id: \.self) { finding in
                    VStack(alignment: .leading, spacing: 4) {
                        Label(finding.title, systemImage: finding.severity.symbol)
                            .foregroundStyle(finding.severity.color)
                            .fontWeight(.medium)
                        Text(finding.rationale).font(.callout)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(finding.severity.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                }
                if !item.details.isEmpty {
                    Divider()
                    ForEach(item.details.keys.sorted(), id: \.self) { key in
                        if key == AuditItem.settingsLinkKey, let url = item.settingsURL {
                            Link("Open in System Settings", destination: url).font(.callout)
                        } else if let value = item.details[key], !value.isEmpty {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(key).font(.caption).foregroundStyle(.secondary)
                                Text(value).font(.callout).textSelection(.enabled)
                            }
                        }
                    }
                }
                Divider()
                VStack(alignment: .leading, spacing: 2) {
                    Text("Item ID").font(.caption).foregroundStyle(.secondary)
                    Text(item.id).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct SourcesInspector: View {
    let section: SectionResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Data Sources").font(.title3.weight(.semibold))
                Text("Select an item for details. This section was collected from:")
                    .font(.callout).foregroundStyle(.secondary)
                ForEach(Array(Set(section.sources.map(\.label))).sorted(), id: \.self) { source in
                    Text(source).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
