import SwiftUI

@main
struct MacAuditApp: App {
    @State private var model = AuditModel()

    var body: some Scene {
        Window("MacAudit", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 900, minHeight: 560)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Audit") {
                Button("Run Audit") { model.runAudit() }
                    .keyboardShortcut("r")
                    .disabled(model.isRunning)
                Divider()
                Button("Export JSON…") { model.export(.json) }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(model.report == nil)
                Button("Export HTML…") { model.export(.html) }
                    .disabled(model.report == nil)
                Button("Export PDF…") { model.export(.pdf) }
                    .keyboardShortcut("p", modifiers: [.command, .shift])
                    .disabled(model.report == nil)
            }
        }
    }
}
