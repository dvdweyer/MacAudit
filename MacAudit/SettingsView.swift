import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @Environment(AuditModel.self) private var model

    var body: some View {
        Form {
            Section {
                LabeledContent("Status") {
                    HStack(spacing: 6) {
                        Image(systemName: statusSymbol).foregroundStyle(statusColor)
                        Text(statusText)
                    }
                }
                if let problem = model.helperProblem {
                    Text(problem).foregroundStyle(.red).font(.callout)
                }
                HStack {
                    switch model.helperStatus {
                    case .enabled:
                        Button("Remove Helper") { model.removeHelper() }
                    case .requiresApproval:
                        Button("Open Login Items Settings") { model.openLoginItemsSettings() }
                        Button("Remove Helper") { model.removeHelper() }
                    default:
                        Button("Install Helper…") { model.installHelper() }
                    }
                }
            } header: {
                Text("Root access")
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Some data is only readable by root: background items, Location Services clients, other users' crontabs, known Wi-Fi networks, sudoers, device profiles, listening ports of system daemons, and signatures of root-only programs.")
                    Text("The helper is a launch daemon that answers a fixed set of read requests from MacAudit only. It runs in a sandbox that denies all file writes outside temporary folders, including for the commands it runs. macOS asks you to allow it in System Settings › General › Login Items & Extensions.")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear { model.refreshHelperStatus() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.refreshHelperStatus()
        }
    }

    private var statusText: String {
        switch model.helperStatus {
        case .enabled: "Installed and allowed"
        case .requiresApproval: "Waiting for approval in System Settings"
        case .notFound: "Not found in the app bundle"
        default: "Not installed"
        }
    }

    private var statusSymbol: String {
        switch model.helperStatus {
        case .enabled: "checkmark.circle.fill"
        case .requiresApproval: "clock.fill"
        default: "minus.circle"
        }
    }

    private var statusColor: Color {
        switch model.helperStatus {
        case .enabled: .green
        case .requiresApproval: .orange
        default: .secondary
        }
    }
}
