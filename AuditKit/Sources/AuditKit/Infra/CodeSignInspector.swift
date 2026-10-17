import Foundation
import Security

public struct SigningInfo: Codable, Sendable, Hashable {
    public enum Status: String, Codable, Sendable {
        case valid, invalid, unsigned, adhoc, missing, unreadable
    }

    public var status: Status
    public var identifier: String?
    public var teamID: String?
    public var authority: String?
    public var isApple: Bool
    public var isDeveloperID: Bool
    public var isNotarized: Bool
    public var isAppStore: Bool = false
    public var error: String?

    public var summary: String {
        switch status {
        case .missing: return "File not found"
        case .unreadable: return "Not readable without root"
        case .unsigned: return "Unsigned"
        case .adhoc: return "Ad-hoc signed"
        case .invalid: return "Invalid signature" + (error.map { " (\($0))" } ?? "")
        case .valid:
            if isApple { return "Apple" }
            if isAppStore { return "Mac App Store" + (teamID.map { ", team \($0)" } ?? "") }
            if isTestFlight { return "TestFlight" + (teamID.map { ", team \($0)" } ?? "") }
            var parts: [String] = []
            if isDeveloperID { parts.append("Developer ID") }
            else if let authority { parts.append(authority) }
            if let teamID { parts.append("team \(teamID)") }
            parts.append(isNotarized ? "notarized" : "not notarized")
            return parts.joined(separator: ", ")
        }
    }

    /// TestFlight builds are signed by Apple's distribution CA rather than notarized.
    public var isTestFlight: Bool { authority?.hasPrefix("TestFlight Beta Distribution") ?? false }

    public var details: [String: String] {
        var d: [String: String] = ["Signature": summary]
        if let identifier { d["Signing identifier"] = identifier }
        if let teamID { d["Team ID"] = teamID }
        if let authority { d["Authority"] = authority }
        return d
    }

    /// Unsigned, ad-hoc, broken, or (for third-party code) not notarized.
    public var isUntrusted: Bool {
        switch status {
        case .unsigned, .adhoc, .invalid: true
        case .valid: !isApple && !isAppStore && !isTestFlight && !isNotarized
        case .missing, .unreadable: false
        }
    }
}

/// Static code-signature inspection via Security.framework. Results are cached per path.
public actor CodeSignInspector {
    private var cache: [String: SigningInfo] = [:]
    /// Used for files this process cannot read (e.g. root-only daemons).
    private let privileged: (any PrivilegedAccess)?

    // SecRequirement is immutable once created.
    nonisolated(unsafe) private static let appleReq = requirement("anchor apple")
    // SecRequirement is immutable once created.
    nonisolated(unsafe) private static let notarizedReq = requirement("notarized")
    // SecRequirement is immutable once created.
    nonisolated(unsafe) private static let appStoreReq = requirement(
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists")
    // SecRequirement is immutable once created.
    nonisolated(unsafe) private static let developerIDReq = requirement(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists")

    public init(privileged: (any PrivilegedAccess)? = nil) {
        self.privileged = privileged
    }

    public func inspect(path: String) async -> SigningInfo {
        if let cached = cache[path] { return cached }
        var info = Self.evaluate(path: path)
        if info.status == .unreadable, let privileged, let remote = try? await privileged.signingInfo(path: path) {
            info = remote
        }
        cache[path] = info
        return info
    }

    private static func requirement(_ text: String) -> SecRequirement? {
        var req: SecRequirement?
        SecRequirementCreateWithString(text as CFString, [], &req)
        return req
    }

    private static func evaluate(path: String) -> SigningInfo {
        var info = SigningInfo(status: .valid, isApple: false, isDeveloperID: false, isNotarized: false)
        guard FileManager.default.fileExists(atPath: path) else {
            info.status = .missing
            return info
        }
        guard FileManager.default.isReadableFile(atPath: path) else {
            info.status = .unreadable
            return info
        }

        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            info.status = .unsigned
            return info
        }

        // Skipping resource validation keeps whole-/Applications scans fast; the code directory
        // and executable pages are still verified.
        let validity = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil)

        var rawInfo: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &rawInfo)
        let dict = (rawInfo as? [String: Any]) ?? [:]
        info.identifier = dict[kSecCodeInfoIdentifier as String] as? String
        info.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first {
            info.authority = SecCertificateCopySubjectSummary(leaf) as String?
        }
        let codeFlags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0

        switch validity {
        case errSecSuccess:
            break
        case errSecCSUnsigned:
            info.status = .unsigned
            return info
        default:
            info.status = .invalid
            info.error = SecCopyErrorMessageString(validity, nil) as String? ?? "OSStatus \(validity)"
            return info
        }

        if codeFlags & 0x2 != 0 { // kSecCodeSignatureAdhoc
            info.status = .adhoc
            return info
        }

        let check: (SecRequirement?) -> Bool = { req in
            guard let req else { return false }
            return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), req) == errSecSuccess
        }
        info.isApple = check(appleReq)
        if !info.isApple {
            info.isAppStore = check(appStoreReq)
            info.isDeveloperID = check(developerIDReq)
            info.isNotarized = check(notarizedReq)
        }
        return info
    }
}
