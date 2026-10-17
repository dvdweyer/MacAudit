import Foundation
import Darwin

/// Login records from the wtmp database (what `last` shows). Readable without root.
enum LoginHistory {
    struct Login {
        var date: Date
        var line: String
    }

    static func latestLogins() -> [String: Login] {
        var latest: [String: Login] = [:]
        setutxent_wtmp(0)
        defer { endutxent_wtmp() }
        while let entry = getutxent_wtmp() {
            guard entry.pointee.ut_type == USER_PROCESS else { continue }
            let user = withUnsafeBytes(of: entry.pointee.ut_user) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            let line = withUnsafeBytes(of: entry.pointee.ut_line) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
            let date = Date(timeIntervalSince1970: TimeInterval(entry.pointee.ut_tv.tv_sec))
            if latest[user].map({ date > $0.date }) ?? true {
                latest[user] = Login(date: date, line: line)
            }
        }
        return latest
    }
}
