import Foundation

/// The complete set of operations that may be performed with root privileges. Every case is a read;
/// `PrivilegedPolicy` further restricts which commands and paths are accepted.
public enum PrivilegedRequest: Codable, Sendable {
    case version
    case run(AllowedCommand)
    case readFile(String)
    case listDirectory(String)
    case signingInfo(String)
    case listeningSockets
}

/// Root access as seen by collectors: either this process is root, or requests go to the helper daemon.
public protocol PrivilegedAccess: Sendable {
    /// Returns the JSON-encoded response for the request.
    func perform(_ request: PrivilegedRequest) async throws -> Data
}

public enum PrivilegedError: Error, CustomStringConvertible {
    case notAllowed(String)
    case failed(String)

    public var description: String {
        switch self {
        case .notAllowed(let s): "Not allowed by the privileged policy: \(s)"
        case .failed(let s): s
        }
    }
}

enum PrivilegedPolicy {
    /// Allowlisted commands that only give complete results as root.
    static let commands: Set<AllowedCommand> = [.sfltoolDumpBTM, .profilesShowConfiguration]

    static let files: Set<String> = [
        "/etc/sudoers",
        "/var/db/locationd/clients.plist",
        "/Library/Preferences/com.apple.wifi.known-networks.plist",
    ]
    /// Directories whose listing, and whose direct children, may be read.
    static let directories: Set<String> = ["/etc/sudoers.d", "/usr/lib/cron/tabs"]

    static let maxFileSize = 64 * 1024 * 1024

    static func canRun(_ command: AllowedCommand) -> Bool { commands.contains(command) }

    static func canList(_ path: String) -> Bool {
        guard let resolved = resolve(path) else { return false }
        return directories.contains { resolve($0) == resolved }
    }

    static func canRead(_ path: String) -> Bool {
        guard let resolved = resolve(path) else { return false }
        if files.contains(where: { resolve($0) == resolved }) { return true }
        if isUserTCCDatabase(resolved) { return true }
        let parent = (resolved as NSString).deletingLastPathComponent
        return directories.contains { resolve($0) == parent }
    }

    /// `/private/var/containers/Data/ProtectedSystem/<UUID>/Data/Library/Application Support/com.apple.TCC/TCC.db[-wal|-shm]`
    static func isUserTCCDatabase(_ path: String) -> Bool {
        let prefix = "/private/var/containers/Data/ProtectedSystem/"
        guard path.hasPrefix(prefix) else { return false }
        let parts = path.dropFirst(prefix.count).split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        return parts.count == 6 && UUID(uuidString: parts[0]) != nil
            && parts[1...4] == ["Data", "Library", "Application Support", "com.apple.TCC"]
            && ["TCC.db", "TCC.db-wal", "TCC.db-shm"].contains(parts[5])
    }

    /// Absolute, free of `..`, with symlinks resolved, so allowlist checks cannot be sidestepped.
    /// realpath(3) rather than URL.resolvingSymlinksInPath, which strips `/private`.
    static func resolve(_ path: String) -> String? {
        guard path.hasPrefix("/"), !path.split(separator: "/").contains("..") else { return nil }
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

/// Executes privileged requests in the current process after checking `PrivilegedPolicy`.
/// Used by the helper daemon and by the CLI when it runs as root.
public struct PrivilegedService: Sendable {
    let runner: CommandRunner
    let signing: CodeSignInspector

    public init(runner: CommandRunner = CommandRunner(), signing: CodeSignInspector = CodeSignInspector()) {
        self.runner = runner
        self.signing = signing
    }

    public func handle(_ request: PrivilegedRequest) async throws -> Data {
        let encoder = JSONEncoder()
        switch request {
        case .version:
            return try encoder.encode(AuditEngine.toolVersion)
        case .run(let command):
            guard PrivilegedPolicy.canRun(command) else { throw PrivilegedError.notAllowed(command.displayString) }
            return try encoder.encode(try await runner.run(command))
        case .readFile(let path):
            guard PrivilegedPolicy.canRead(path) else { throw PrivilegedError.notAllowed(path) }
            let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
            defer { try? handle.close() }
            let data = try handle.read(upToCount: PrivilegedPolicy.maxFileSize) ?? Data()
            return try encoder.encode(data)
        case .listDirectory(let path):
            guard PrivilegedPolicy.canList(path) else { throw PrivilegedError.notAllowed(path) }
            return try encoder.encode(try FileManager.default.contentsOfDirectory(atPath: path).sorted())
        case .signingInfo(let path):
            guard path.hasPrefix("/") else { throw PrivilegedError.notAllowed(path) }
            return try encoder.encode(await signing.inspect(path: path))
        case .listeningSockets:
            return try encoder.encode(ProcSockets.listeningSockets())
        }
    }
}

/// Root access for a process that is itself root (`sudo macaudit`).
public struct LocalPrivilegedAccess: PrivilegedAccess {
    let service: PrivilegedService

    public init(service: PrivilegedService = PrivilegedService()) { self.service = service }

    public func perform(_ request: PrivilegedRequest) async throws -> Data {
        try await service.handle(request)
    }
}

extension PrivilegedAccess {
    private func decode<T: Decodable>(_ type: T.Type, _ request: PrivilegedRequest) async throws -> T {
        try JSONDecoder().decode(T.self, from: try await perform(request))
    }

    /// The helper's AuditKit version; also a cheap reachability check.
    public func version() async throws -> String { try await decode(String.self, .version) }
    func run(_ command: AllowedCommand) async throws -> CommandResult { try await decode(CommandResult.self, .run(command)) }
    func readFile(_ path: String) async throws -> Data { try await decode(Data.self, .readFile(path)) }
    func listDirectory(_ path: String) async throws -> [String] { try await decode([String].self, .listDirectory(path)) }
    func signingInfo(path: String) async throws -> SigningInfo { try await decode(SigningInfo.self, .signingInfo(path)) }
    func listeningSockets() async throws -> ProcSockets.Result { try await decode(ProcSockets.Result.self, .listeningSockets) }
}
