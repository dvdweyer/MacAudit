import Testing
import Foundation
import SQLite3
@testable import AuditKit

@Suite struct InfrastructureTests {
    /// Guards the read-only promise: every allowlisted command must be a SIP-protected Apple binary
    /// and must not carry a mutating verb.
    @Test func allowlistIsReadOnly() {
        let mutating = ["set", "add", "remove", "delete", "enable", "disable", "install", "uninstall", "load",
                        "unload", "kill", "bootout", "bootstrap", "write", "reset", "update", "create", "modify",
                        "erase", "clear", "start", "stop", "kickstart", "renew", "import", "trust", "block", "unblock"]
        let protectedPrefixes = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/"]
        for command in AllowedCommand.allCases {
            let (path, args) = command.invocation
            #expect(protectedPrefixes.contains { path.hasPrefix($0) }, "\(path) is outside SIP-protected locations")
            for arg in args {
                let word = arg.trimmingCharacters(in: CharacterSet(charactersIn: "-")).lowercased()
                for verb in mutating {
                    #expect(!word.hasPrefix(verb), "\(command.displayString) contains mutating argument \(arg)")
                }
            }
        }
    }

    @Test func userNameValidation() {
        #expect(AllowedCommand.isValidUserName("alice"))
        #expect(AllowedCommand.isValidUserName("first.last_2"))
        #expect(!AllowedCommand.isValidUserName("-resetPassword"))
        #expect(!AllowedCommand.isValidUserName("a b"))
        #expect(!AllowedCommand.isValidUserName("x;rm"))
        #expect(!AllowedCommand.isValidUserName(""))
    }

    @Test func sqliteSnapshotDoesNotTouchOriginal() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("tcc-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("TCC.db").path

        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        let sql = """
        CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, auth_reason INTEGER,
                             indirect_object_identifier TEXT, last_modified INTEGER, csreq BLOB);
        INSERT INTO access VALUES ('kTCCServiceSystemPolicyAllFiles', '/usr/local/bin/tool', 1, 2, 3, 'UNUSED', 1700000000, NULL);
        INSERT INTO access VALUES ('kTCCServiceCamera', 'com.example.app', 0, 0, 2, NULL, 1700000001, x'fade');
        """
        #expect(sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK)
        sqlite3_close(db)

        let before = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let rows = try SQLiteSnapshotReader.query(databaseAt: path, sql: "SELECT * FROM access ORDER BY service")
        let after = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        #expect(before == after)
        #expect(!FileManager.default.fileExists(atPath: path + "-wal"))
        #expect(rows.count == 2)

        let entries = rows.compactMap { TCCEntry(row: $0, scope: "User") }
        #expect(entries[0].serviceName == "Camera")
        #expect(entries[0].authValue == 0)
        #expect(entries[1].serviceName == "Full Disk Access")
        #expect(entries[1].isAllowed)
        #expect(entries[1].clientType == 1)
        #expect(TCCEntry.reasonName(entries[1].authReason) == "User set")
    }

    @Test func sqliteMissingFileThrows() {
        #expect(throws: SQLiteError.self) {
            try SQLiteSnapshotReader.query(databaseAt: "/nonexistent/TCC.db", sql: "SELECT 1")
        }
    }

    @Test func coverageDegrades() {
        var c = Coverage()
        c.degrade(to: .partial, "a")
        #expect(c.status == .partial)
        c.degrade(to: .unavailable, "b")
        #expect(c.status == .unavailable)
        c.degrade(to: .partial, "c")
        #expect(c.status == .unavailable)
        #expect(c.notes == ["a", "b", "c"])
    }

    @Test func privilegedPolicyOnlyAllowsRootOnlyReads() {
        #expect(PrivilegedPolicy.commands.allSatisfy { AllowedCommand.allCases.contains($0) })
        #expect(PrivilegedPolicy.canRun(.sfltoolDumpBTM))
        #expect(!PrivilegedPolicy.canRun(.netstat))

        #expect(PrivilegedPolicy.canRead("/etc/sudoers"))
        #expect(!PrivilegedPolicy.canRead("/etc/master.passwd"))
        #expect(!PrivilegedPolicy.canRead("/etc/sudoers.d/../master.passwd"))
        #expect(!PrivilegedPolicy.canRead("etc/sudoers"))
        #expect(PrivilegedPolicy.canList("/etc/sudoers.d"))
        #expect(!PrivilegedPolicy.canList("/etc"))

        let tcc = "/private/var/containers/Data/ProtectedSystem/B97B32AB-3D8F-46A2-A0A6-18C2E5C2B0CE/Data/Library/Application Support/com.apple.TCC/"
        #expect(PrivilegedPolicy.isUserTCCDatabase(tcc + "TCC.db"))
        #expect(PrivilegedPolicy.isUserTCCDatabase(tcc + "TCC.db-wal"))
        #expect(!PrivilegedPolicy.isUserTCCDatabase(tcc + "other.db"))
        #expect(!PrivilegedPolicy.isUserTCCDatabase(tcc.replacingOccurrences(of: "B97B32AB-3D8F-46A2-A0A6-18C2E5C2B0CE", with: "x/y") + "TCC.db"))
    }

    @Test func privilegedPolicyResolvesSymlinks() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("policy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent("sudoers")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/etc/master.passwd")
        #expect(!PrivilegedPolicy.canRead(link.path))
    }

    @Test func privilegedServiceRejectsRequestsOutsidePolicy() async {
        let service = PrivilegedService()
        await #expect(throws: PrivilegedError.self) { try await service.handle(.run(.netstat)) }
        await #expect(throws: PrivilegedError.self) { try await service.handle(.readFile("/etc/master.passwd")) }
        await #expect(throws: PrivilegedError.self) { try await service.handle(.listDirectory("/Users")) }
        let version = try? await LocalPrivilegedAccess(service: service).version()
        #expect(version == AuditEngine.toolVersion)
    }

    /// The helper's sandbox must block writes outside temporary directories, including for child processes.
    @Test func helperSandboxDeniesWrites() throws {
        func touch(_ path: String) throws -> Int32 {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            p.arguments = ["-p", PrivilegedHelper.sandboxProfile, "/usr/bin/touch", path]
            p.standardError = FileHandle.nullDevice
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        }
        let outside = NSHomeDirectory() + "/Library/Caches/macaudit-sandbox-test-\(UUID().uuidString)"
        #expect(try touch(outside) != 0)
        #expect(!FileManager.default.fileExists(atPath: outside))
        let inside = FileManager.default.temporaryDirectory.appendingPathComponent("sandbox-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: inside) }
        #expect(try touch(inside) == 0)
    }

    @Test func sqliteSnapshotFromData() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("snapdata-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("t.db").path
        var db: OpaquePointer?
        sqlite3_open(path, &db)
        sqlite3_exec(db, "CREATE TABLE access (service TEXT); INSERT INTO access VALUES ('kTCCServiceCamera');", nil, nil, nil)
        sqlite3_close(db)
        let rows = try SQLiteSnapshotReader.query(snapshot: ["": try Data(contentsOf: URL(fileURLWithPath: path))],
                                                  sql: "SELECT * FROM access")
        #expect(rows.first?["service"]?.string == "kTCCServiceCamera")
    }
}
