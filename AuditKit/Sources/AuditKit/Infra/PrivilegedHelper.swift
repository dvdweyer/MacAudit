import Foundation
import Darwin

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
    /// A release helper only accepts the Developer ID-signed app; Apple Development builds carry
    /// get-task-allow and could be taken over by a debugger.
    public static let clientRequirement =
        #"anchor apple generic and identifier "org.afaik.MacAudit" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "\#(teamID)""#
    /// Used only by Debug builds of the helper.
    public static let developmentClientRequirement =
        #"anchor apple generic and identifier "org.afaik.MacAudit" and certificate leaf[subject.OU] = "\#(teamID)""#
    /// The app only talks to a helper signed by the same team.
    public static let helperRequirement =
        #"anchor apple generic and identifier "\#(label)" and certificate leaf[subject.OU] = "\#(teamID)""#

    /// Applied by the helper to itself and inherited by every command it runs: file writes only in
    /// `writableDirectories`, no IP networking, and only `executables` may be launched.
    public static func sandboxProfile(writableDirectories: [String], executables: [String]) -> String {
        func quoted(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let writable = writableDirectories.map { "(subpath \(quoted($0)))" }.joined(separator: " ")
        let exec = executables.map { "(literal \(quoted($0)))" }.joined(separator: " ")
        return """
            (version 1)
            (allow default)
            (deny file-write*)
            (allow file-write* \(writable) (literal "/dev/null"))
            (deny network-outbound (remote ip))
            (deny network-inbound)
            (deny network-bind)
            (deny process-exec)
            \(exec.isEmpty ? "" : "(allow process-exec \(exec))")
            """
    }

    /// The helper's own per-user temporary and cache directories (created on demand by confstr).
    public static func ownScratchDirectories() -> [String] {
        [_CS_DARWIN_USER_TEMP_DIR, _CS_DARWIN_USER_CACHE_DIR].compactMap { name in
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
            guard confstr(name, &buffer, buffer.count) > 0 else { return nil }
            return PrivilegedPolicy.resolve(String(cString: buffer))
        }
    }
}

/// The user on whose behalf a privileged request is made.
public struct PrivilegedCaller: Sendable {
    public var uid: uid_t
    public var home: String?

    public static let root = PrivilegedCaller(uid: 0)

    public init(uid: uid_t) {
        self.uid = uid
        home = getpwuid(uid).map { String(cString: $0.pointee.pw_dir) }
    }

    public var isRoot: Bool { uid == 0 }

    /// Only administrators may use the helper: they could get the same data with sudo, so the
    /// helper grants them convenience, not new access.
    public var isAdministrator: Bool {
        var user = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var group = user
        guard mbr_uid_to_uuid(uid, &user) == 0, mbr_gid_to_uuid(80 /* admin */, &group) == 0 else { return false }
        var member: Int32 = 0
        return mbr_check_membership(&user, &group, &member) == 0 && member != 0
    }
}

// membership.h is not exported to Swift.
@_silgen_name("mbr_uid_to_uuid")
private func mbr_uid_to_uuid(_ uid: uid_t, _ uu: UnsafeMutablePointer<uuid_t>) -> Int32
@_silgen_name("mbr_gid_to_uuid")
private func mbr_gid_to_uuid(_ gid: gid_t, _ uu: UnsafeMutablePointer<uuid_t>) -> Int32
@_silgen_name("mbr_check_membership")
private func mbr_check_membership(_ user: UnsafePointer<uuid_t>, _ group: UnsafePointer<uuid_t>,
                                  _ isMember: UnsafeMutablePointer<Int32>) -> Int32

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
