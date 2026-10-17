import Foundation
import SQLite3

public enum PlistReader {
    public static func dictionary(at path: String) -> [String: Any]? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
    }

    public static func array(at path: String) -> [Any]? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [Any]
    }

    /// Reads a preference through cfprefsd, which also resolves managed (MDM) values.
    public static func preference(_ key: String, domain: String, anyUser: Bool = false) -> Any? {
        if anyUser {
            return CFPreferencesCopyValue(key as CFString, domain as CFString,
                                          kCFPreferencesAnyUser, kCFPreferencesCurrentHost)
                ?? CFPreferencesCopyValue(key as CFString, domain as CFString,
                                          kCFPreferencesAnyUser, kCFPreferencesAnyHost)
        }
        return CFPreferencesCopyAppValue(key as CFString, domain as CFString)
    }

    public static func boolPreference(_ key: String, domain: String, anyUser: Bool = false) -> Bool? {
        switch preference(key, domain: domain, anyUser: anyUser) {
        case let b as Bool: b
        case let n as NSNumber: n.boolValue
        case let s as String: ["1", "true", "yes"].contains(s.lowercased())
        default: nil
        }
    }
}

public enum SQLValue: Sendable, Hashable {
    case null
    case integer(Int64)
    case real(Double)
    case text(String)
    case blob(Data)

    public var string: String? {
        switch self {
        case .text(let s): s
        case .integer(let i): String(i)
        case .real(let d): String(d)
        default: nil
        }
    }

    public var int: Int64? {
        switch self {
        case .integer(let i): i
        case .text(let s): Int64(s)
        default: nil
        }
    }

    public var data: Data? {
        if case .blob(let d) = self { return d }
        return nil
    }
}

public enum SQLiteError: Error, CustomStringConvertible {
    case notReadable(String)
    case sqlite(String)

    public var description: String {
        switch self {
        case .notReadable(let p): "Not readable: \(p)"
        case .sqlite(let m): "SQLite: \(m)"
        }
    }
}

/// Queries a SQLite database without touching the original: the database and its WAL/SHM
/// side files are copied into a private temporary directory and only the copy is opened.
public enum SQLiteSnapshotReader {
    public static func query(databaseAt path: String, sql: String) throws -> [[String: SQLValue]] {
        let fm = FileManager.default
        guard fm.isReadableFile(atPath: path) else { throw SQLiteError.notReadable(path) }

        let dir = fm.temporaryDirectory.appendingPathComponent("MacAudit-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: dir) }

        let copy = dir.appendingPathComponent("snapshot.db")
        do {
            try fm.copyItem(atPath: path, toPath: copy.path)
        } catch {
            throw SQLiteError.notReadable(path)
        }
        for suffix in ["-wal", "-shm"] where fm.fileExists(atPath: path + suffix) {
            try? fm.copyItem(atPath: path + suffix, toPath: copy.path + suffix)
        }

        var db: OpaquePointer?
        guard sqlite3_open_v2(copy.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else {
            throw SQLiteError.sqlite("open failed")
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            throw SQLiteError.sqlite(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        var rows: [[String: SQLValue]] = []
        let columns = sqlite3_column_count(stmt)
        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: SQLValue] = [:]
            for i in 0..<columns {
                let name = String(cString: sqlite3_column_name(stmt, i))
                switch sqlite3_column_type(stmt, i) {
                case SQLITE_INTEGER: row[name] = .integer(sqlite3_column_int64(stmt, i))
                case SQLITE_FLOAT: row[name] = .real(sqlite3_column_double(stmt, i))
                case SQLITE_TEXT: row[name] = .text(String(cString: sqlite3_column_text(stmt, i)))
                case SQLITE_BLOB:
                    let count = Int(sqlite3_column_bytes(stmt, i))
                    if let bytes = sqlite3_column_blob(stmt, i) {
                        row[name] = .blob(Data(bytes: bytes, count: count))
                    } else {
                        row[name] = .blob(Data())
                    }
                default: row[name] = .null
                }
            }
            rows.append(row)
        }
        return rows
    }
}
