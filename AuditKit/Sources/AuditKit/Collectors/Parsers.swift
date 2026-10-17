import Foundation

/// Pure parsing functions for command output, kept separate from I/O so they can be fixture-tested.
enum Parsers {}

extension StringProtocol {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

extension String {
    /// Decodes a NUL-terminated C buffer.
    init(cBuffer: [CChar]) {
        self.init(decoding: cBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
