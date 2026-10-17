import Foundation

@objc public protocol PrivilegedHelperXPC {
    /// `request` is a JSON-encoded `PrivilegedRequest`; the reply carries the JSON response or an error message.
    func perform(_ request: Data, reply: @escaping @Sendable (Data?, String?) -> Void)
}

/// Constants shared by the app (client) and the helper daemon (server).
public enum PrivilegedHelper {
    public static let label = "org.afaik.MacAudit.helper"
    public static let machServiceName = label
    /// Name of the launchd plist in Contents/Library/LaunchDaemons, as passed to SMAppService.daemon.
    public static let plistName = label + ".plist"

    static let teamID = "R4J8ZNC9HF"
    /// The helper only accepts connections from MacAudit signed by this team.
    public static let clientRequirement =
        #"anchor apple generic and identifier "org.afaik.MacAudit" and certificate leaf[subject.OU] = "\#(teamID)""#
    /// The app only talks to a helper signed by the same team.
    public static let helperRequirement =
        #"anchor apple generic and identifier "\#(label)" and certificate leaf[subject.OU] = "\#(teamID)""#

    /// Applied by the helper to itself (and inherited by every command it runs): all file writes are
    /// denied except in temporary directories, so the helper cannot modify the system even if asked to.
    public static let sandboxProfile = """
        (version 1)
        (allow default)
        (deny file-write*)
        (allow file-write* (subpath "/private/var/folders") (subpath "/private/tmp") (literal "/dev/null"))
        """
}

/// Client side of the helper daemon.
public final class XPCPrivilegedAccess: PrivilegedAccess, @unchecked Sendable {
    // NSXPCConnection is thread-safe; it is configured once in init and never mutated afterwards.
    private let connection: NSXPCConnection

    public init() {
        connection = NSXPCConnection(machServiceName: PrivilegedHelper.machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: PrivilegedHelperXPC.self)
        connection.setCodeSigningRequirement(PrivilegedHelper.helperRequirement)
        connection.resume()
    }

    deinit { connection.invalidate() }

    public func perform(_ request: PrivilegedRequest) async throws -> Data {
        let payload = try JSONEncoder().encode(request)
        return try await withCheckedThrowingContinuation { continuation in
            // XPC calls exactly one of the error handler or the reply block per message.
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                continuation.resume(throwing: error)
            } as? PrivilegedHelperXPC
            guard let proxy else {
                continuation.resume(throwing: PrivilegedError.failed("Helper interface unavailable"))
                return
            }
            proxy.perform(payload) { data, error in
                if let data {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: PrivilegedError.failed(error ?? "Unknown helper error"))
                }
            }
        }
    }
}
