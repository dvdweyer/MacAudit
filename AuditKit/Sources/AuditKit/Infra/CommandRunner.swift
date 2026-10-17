import Foundation

/// The complete set of external programs the auditor may execute. Every case maps to a
/// SIP-protected Apple binary with fixed, read-only arguments; nothing is passed through a shell.
public enum AllowedCommand: Codable, Sendable, Hashable, CaseIterable {
    case csrutilStatus
    case spctlStatus
    case fdesetupStatus
    case firewallGlobalState
    case firewallStealthMode
    case firewallBlockAll
    case firewallAllowSigned
    case firewallListApps
    case devToolsSecurityStatus
    case xprotectVersion
    case launchctlPrintDisabledSystem
    case netstat
    case scutilNetworkConnections
    case systemExtensionsList
    case pluginkitList
    case profilesEnrollmentStatus
    case profilesShowConfiguration
    case secureTokenStatus(user: String)
    case tmutilDestinationInfo
    case tmutilLatestBackup
    case sfltoolDumpBTM
    case crontabList
    case nvramFindMyToken
    case sharingList
    case cupsSettings
    case screenLockStatus
    case authorizationdbLoginConsole
    case launchctlPrintDisabledUser(uid: UInt32)
    case bootPolicy
    case passwordPolicies

    public static var allCases: [AllowedCommand] {
        [.csrutilStatus, .spctlStatus, .fdesetupStatus, .firewallGlobalState, .firewallStealthMode,
         .firewallBlockAll, .firewallAllowSigned, .firewallListApps,
         .devToolsSecurityStatus, .xprotectVersion, .launchctlPrintDisabledSystem, .netstat,
         .scutilNetworkConnections, .systemExtensionsList, .pluginkitList,
         .profilesEnrollmentStatus, .profilesShowConfiguration, .secureTokenStatus(user: "nobody"),
         .tmutilDestinationInfo, .tmutilLatestBackup, .sfltoolDumpBTM, .crontabList,
         .nvramFindMyToken, .sharingList, .cupsSettings, .screenLockStatus,
         .authorizationdbLoginConsole, .launchctlPrintDisabledUser(uid: 501), .bootPolicy, .passwordPolicies]
    }

    private static let firewall = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    public var invocation: (path: String, arguments: [String]) {
        switch self {
        case .csrutilStatus: ("/usr/bin/csrutil", ["status"])
        case .spctlStatus: ("/usr/sbin/spctl", ["--status"])
        case .fdesetupStatus: ("/usr/bin/fdesetup", ["status"])
        case .firewallGlobalState: (Self.firewall, ["--getglobalstate"])
        case .firewallStealthMode: (Self.firewall, ["--getstealthmode"])
        case .firewallBlockAll: (Self.firewall, ["--getblockall"])
        case .firewallAllowSigned: (Self.firewall, ["--getallowsigned"])
        case .firewallListApps: (Self.firewall, ["--listapps"])
        case .devToolsSecurityStatus: ("/usr/sbin/DevToolsSecurity", ["-status"])
        case .xprotectVersion: ("/usr/bin/xprotect", ["version"])
        case .launchctlPrintDisabledSystem: ("/bin/launchctl", ["print-disabled", "system"])
        // Returns no Internet sockets when launched by a non-Apple process; NetworkCollector then uses libproc.
        case .netstat: ("/usr/sbin/netstat", ["-anv"])
        case .scutilNetworkConnections: ("/usr/sbin/scutil", ["--nc", "list"])
        case .systemExtensionsList: ("/usr/bin/systemextensionsctl", ["list"])
        case .pluginkitList: ("/usr/bin/pluginkit", ["-m", "-A", "-v", "-v", "-v"])
        case .profilesEnrollmentStatus: ("/usr/bin/profiles", ["status", "-type", "enrollment"])
        case .profilesShowConfiguration: ("/usr/bin/profiles", ["show", "-type", "configuration"])
        case .secureTokenStatus(let user): ("/usr/sbin/sysadminctl", ["-secureTokenStatus", user])
        case .tmutilDestinationInfo: ("/usr/bin/tmutil", ["destinationinfo"])
        case .tmutilLatestBackup: ("/usr/bin/tmutil", ["latestbackup"])
        case .sfltoolDumpBTM: ("/usr/bin/sfltool", ["dumpbtm"])
        case .crontabList: ("/usr/bin/crontab", ["-l"])
        case .nvramFindMyToken: ("/usr/sbin/nvram", ["fmm-mobileme-token-FMM"])
        case .sharingList: ("/usr/sbin/sharing", ["-l"])
        case .cupsSettings: ("/usr/sbin/cupsctl", [])
        case .screenLockStatus: ("/usr/sbin/sysadminctl", ["-screenLock", "status"])
        case .authorizationdbLoginConsole: ("/usr/bin/security", ["authorizationdb", "read", "system.login.console"])
        case .launchctlPrintDisabledUser(let uid): ("/bin/launchctl", ["print-disabled", "gui/\(uid)"])
        // Unlike `bputil -d`, this works without root.
        case .bootPolicy: ("/usr/sbin/system_profiler", ["-json", "SPiBridgeDataType"])
        case .passwordPolicies: ("/usr/bin/pwpolicy", ["-getaccountpolicies"])
        }
    }

    public var displayString: String {
        let inv = invocation
        return ([inv.path] + inv.arguments).joined(separator: " ")
    }

    /// Usernames come from OpenDirectory, but are still validated before reaching argv.
    static func isValidUserName(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 255, !name.hasPrefix("-") else { return false }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        return name.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}

public struct CommandResult: Codable, Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var timedOut: Bool

    public var succeeded: Bool { exitCode == 0 && !timedOut }
    /// Several Apple tools print their answer on stderr.
    public var combined: String { stdout.isEmpty ? stderr : stdout + (stderr.isEmpty ? "" : "\n" + stderr) }
}

public enum CommandError: Error, CustomStringConvertible {
    case invalidArgument(String)
    case launchFailed(String)

    public var description: String {
        switch self {
        case .invalidArgument(let s): "Rejected argument: \(s)"
        case .launchFailed(let s): "Could not launch: \(s)"
        }
    }
}

public struct CommandRunner: Sendable {
    public var timeout: TimeInterval
    public var maxOutputBytes: Int

    public init(timeout: TimeInterval = 20, maxOutputBytes: Int = 16 * 1024 * 1024) {
        self.timeout = timeout
        self.maxOutputBytes = maxOutputBytes
    }

    public func run(_ command: AllowedCommand) async throws -> CommandResult {
        if case .secureTokenStatus(let user) = command, !AllowedCommand.isValidUserName(user) {
            throw CommandError.invalidArgument(user)
        }
        let (path, arguments) = command.invocation
        let timeout = self.timeout
        let cap = maxOutputBytes
        return try await Task.detached(priority: .userInitiated) {
            try Self.execute(path: path, arguments: arguments, timeout: timeout, cap: cap)
        }.value
    }

    private static func execute(path: String, arguments: [String], timeout: TimeInterval, cap: Int) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"]
        process.standardInput = FileHandle.nullDevice
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        do {
            try process.run()
        } catch {
            throw CommandError.launchFailed("\(path): \(error.localizedDescription)")
        }

        let group = DispatchGroup()
        nonisolated(unsafe) var outData = Data()
        nonisolated(unsafe) var errData = Data()
        group.enter()
        DispatchQueue.global().async {
            outData = Self.drain(out.fileHandleForReading, cap: cap)
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errData = Self.drain(err.fileHandleForReading, cap: cap)
            group.leave()
        }

        var timedOut = false
        if group.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            process.terminate()
            group.wait()
        }
        process.waitUntilExit()

        return CommandResult(
            exitCode: process.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self),
            timedOut: timedOut
        )
    }

    private static func drain(_ handle: FileHandle, cap: Int) -> Data {
        var data = Data()
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            if data.count < cap { data.append(chunk.prefix(cap - data.count)) }
        }
        return data
    }
}
