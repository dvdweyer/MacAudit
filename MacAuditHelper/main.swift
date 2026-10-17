import Foundation
import AuditKit

// Root helper for MacAudit, registered with SMAppService. It answers a fixed set of read-only
// requests (see PrivilegedRequest / PrivilegedPolicy) and nothing else.

@_silgen_name("sandbox_init")
private func sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64,
                          _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32

// Enforce read-only at the OS level before accepting any request; refuse to run without it.
var sandboxError: UnsafeMutablePointer<CChar>?
guard sandbox_init(PrivilegedHelper.sandboxProfile, 0, &sandboxError) == 0 else {
    let message = sandboxError.map { String(cString: $0) } ?? "unknown error"
    FileHandle.standardError.write(Data("MacAuditHelper: sandbox_init failed: \(message)\n".utf8))
    exit(1)
}

/// Exits shortly after the last client disconnects; launchd restarts the helper on demand, so an
/// updated app bundle never keeps talking to an old helper process.
final class IdleExit: Sendable {
    private let queue = DispatchQueue(label: "idle-exit")
    // Only accessed on `queue`.
    nonisolated(unsafe) private var connections = 0
    nonisolated(unsafe) private var generation = 0

    func opened() { queue.async { self.connections += 1; self.generation += 1 } }

    func closed() {
        queue.async {
            self.connections -= 1
            self.generation += 1
            guard self.connections == 0 else { return }
            let scheduled = self.generation
            self.queue.asyncAfter(deadline: .now() + 10) {
                if self.connections == 0 && self.generation == scheduled { exit(0) }
            }
        }
    }
}

final class HelperDelegate: NSObject, NSXPCListenerDelegate, PrivilegedHelperXPC, Sendable {
    let service = PrivilegedService()
    let idle = IdleExit()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: PrivilegedHelperXPC.self)
        connection.exportedObject = self
        let idle = self.idle
        connection.invalidationHandler = { idle.closed() }
        idle.opened()
        connection.resume()
        return true
    }

    func perform(_ request: Data, reply: @escaping @Sendable (Data?, String?) -> Void) {
        let service = self.service
        Task {
            do {
                let decoded = try JSONDecoder().decode(PrivilegedRequest.self, from: request)
                reply(try await service.handle(decoded), nil)
            } catch {
                reply(nil, "\(error)")
            }
        }
    }
}

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: PrivilegedHelper.machServiceName)
listener.setConnectionCodeSigningRequirement(PrivilegedHelper.clientRequirement)
listener.delegate = delegate
listener.resume()
dispatchMain()
