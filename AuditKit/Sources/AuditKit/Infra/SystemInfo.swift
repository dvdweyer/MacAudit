import Foundation
import Darwin

public enum Privileges {
    public static var isRoot: Bool { geteuid() == 0 }

    /// TCC databases are only openable with Full Disk Access. Opening for read is side-effect free.
    /// The system one is probed first because the per-user database may not exist (it doesn't on some macOS 27 installs).
    public static var hasFullDiskAccess: Bool {
        let paths = ["/Library/Application Support/com.apple.TCC/TCC.db",
                     NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"]
        return paths.contains { path in
            guard let handle = FileHandle(forReadingAtPath: path) else { return false }
            try? handle.close()
            return true
        }
    }

    public static let fullDiskAccessSettingsURL =
        URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles")!
}

public enum SystemInfo {
    public static var systemVersion: [String: Any] {
        PlistReader.dictionary(at: "/System/Library/CoreServices/SystemVersion.plist") ?? [:]
    }

    public static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        return String(cBuffer: buffer)
    }

    public static func sysctlInt(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return size == 4 ? Int64(Int32(truncatingIfNeeded: value)) : value
    }

    public static var bootTime: Date? {
        var tv = timeval()
        var size = MemoryLayout<timeval>.size
        guard sysctlbyname("kern.boottime", &tv, &size, nil, 0) == 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
    }

    public static var hostInfo: HostInfo {
        let v = systemVersion
        return HostInfo(
            hostname: ProcessInfo.processInfo.hostName,
            osVersion: (v["ProductVersion"] as? String ?? "?") + ((v["ProductVersionExtra"] as? String).map { " \($0)" } ?? ""),
            osBuild: v["ProductBuildVersion"] as? String ?? "?",
            user: NSUserName(),
            runningAsRoot: Privileges.isRoot,
            fullDiskAccess: Privileges.hasFullDiskAccess
        )
    }
}

extension Date {
    var auditString: String {
        formatted(.iso8601.year().month().day().dateSeparator(.dash).time(includingFractionalSeconds: false).timeSeparator(.colon))
    }
}

extension FileManager {
    func contents(ofDirectory path: String) -> [String] {
        ((try? contentsOfDirectory(atPath: path)) ?? []).filter { !$0.hasPrefix(".") }.sorted()
    }

    func modificationDate(_ path: String) -> Date? {
        (try? attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}
