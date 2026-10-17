import Foundation
import AuditKit

// Root helper for MacAudit, registered with SMAppService. It answers a fixed set of read-only
// requests (see PrivilegedRequest / PrivilegedPolicy) from administrators, and nothing else.

@_silgen_name("sandbox_init")
private func sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64,
                          _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32

// Enforce read-only at the OS level before accepting any request; refuse to run without it.
let profile = PrivilegedHelper.sandboxProfile(
    writableDirectories: PrivilegedHelper.ownScratchDirectories(),
    executables: PrivilegedService.executables)
var sandboxError: UnsafeMutablePointer<CChar>?
guard sandbox_init(profile, 0, &sandboxError) == 0 else {
    let message = sandboxError.map { String(cString: $0) } ?? "unknown error"
    FileHandle.standardError.write(Data("MacAuditHelper: sandbox_init failed: \(message)\n".utf8))
    exit(1)
}

/// Exits 10 s after the last client disconnects (or after launch, if no client is accepted);
/// launchd restarts the helper on demand, so an updated app bundle never keeps talking to an old
/// helper process.
final class IdleExit: NSObject, Sendable {
    private let queue = DispatchQueue(label: "idle-exit")
    // Only accessed on `queue`.
    nonisolated(unsafe) private var connections = 0
    nonisolated(unsafe) private var generation = 0

    override init() {
        super.init()
        queue.async { self.exitWhenIdle() }
    }

    func opened() { queue.async { self.connections += 1; self.generation += 1 } }

    func closed() {
        queue.async {
            self.connections -= 1
            self.generation += 1
            self.exitWhenIdle()
        }
    }

    private func exitWhenIdle() {
        guard connections == 0 else { return }
        let scheduled = generation
        queue.asyncAfter(deadline: .now() + 10) {
            if self.connections == 0 && self.generation == scheduled { exit(0) }
        }
    }
}

/// Serves one client connection; requests are evaluated on behalf of that connection's user.
final class ConnectionHandler: NSObject, PrivilegedHelperXPC, Sendable {
    let service: PrivilegedService
    let caller: PrivilegedCaller

    init(service: PrivilegedService, caller: PrivilegedCaller) {
        self.service = service
        self.caller = caller
    }

    func perform(_ request: Data, reply: @escaping @Sendable (Data?, String?) -> Void) {
        let service = self.service
        let caller = self.caller
        Task {
            do {
                let decoded = try JSONDecoder().decode(PrivilegedRequest.self, from: request)
                reply(try await service.handle(decoded, caller: caller), nil)
            } catch {
                reply(nil, "\(error)")
            }
        }
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate, Sendable {
    let service = PrivilegedService()
    let idle = IdleExit()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // The code-signing requirement is checked by the listener; this adds who is asking.
        let caller = PrivilegedCaller(uid: connection.effectiveUserIdentifier)
        guard caller.isAdministrator else { return false }
        connection.exportedInterface = NSXPCInterface(with: PrivilegedHelperXPC.self)
        connection.exportedObject = ConnectionHandler(service: service, caller: caller)
        let idle = self.idle
        connection.invalidationHandler = { idle.closed() }
        idle.opened()
        connection.resume()
        return true
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: PrivilegedHelper.machServiceName)
#if DEBUG
listener.setConnectionCodeSigningRequirement(PrivilegedHelper.developmentClientRequirement)
#else
listener.setConnectionCodeSigningRequirement(PrivilegedHelper.clientRequirement)
#endif
listener.delegate = delegate
listener.resume()
dispatchMain()
