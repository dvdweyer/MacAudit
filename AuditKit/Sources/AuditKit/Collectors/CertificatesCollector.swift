import Foundation
import Security
import CryptoKit

public struct CertificatesCollector: Collector {
    public let id = "certificates"
    public let title = "Certificates & Trust"
    public let symbol = "checkmark.seal"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        section.note(api: "SecTrustSettingsCopyCertificates (user, admin domains)")
        for (domain, label) in [(SecTrustSettingsDomain.user, "User"), (.admin, "Admin (system-wide)")] {
            var raw: CFArray?
            let status = SecTrustSettingsCopyCertificates(domain, &raw)
            if status == errSecNoTrustSettings { continue }
            guard status == errSecSuccess, let certs = raw as? [SecCertificate] else {
                section.coverage.degrade(to: .partial, "\(label) trust settings: OSStatus \(status)")
                continue
            }
            for cert in certs {
                section.add(item(for: cert, domain: domain, label: label))
            }
        }
    }

    private func item(for cert: SecCertificate, domain: SecTrustSettingsDomain, label: String) -> AuditItem {
        let name = SecCertificateCopySubjectSummary(cert) as String? ?? "Certificate"
        let fingerprint = SHA256.hash(data: SecCertificateCopyData(cert) as Data)
            .map { String(format: "%02X", $0) }.joined()

        var settingsRaw: CFArray?
        SecTrustSettingsCopyTrustSettings(cert, domain, &settingsRaw)
        let settings = settingsRaw as? [[String: Any]] ?? []
        let trust = Self.describe(settings)

        var details: [String: String] = ["Domain": label, "SHA-256": fingerprint, "Trust": trust.description]
        if let notAfter = Self.notAfter(cert) {
            details["Expires"] = notAfter.auditString
        }
        if let policies = trust.policies, !policies.isEmpty {
            details["Policies"] = policies
        }

        var findings: [Finding] = []
        if trust.isTrustedRoot {
            findings.append(Finding(domain == .user ? .warning : .notice, "Custom trusted root certificate",
                rationale: "Any certificate issued by this root is trusted, which allows inspection of encrypted (TLS) traffic. Verify it is from your organisation or a known tool."))
        }
        return AuditItem(id: "cert:\(label):\(fingerprint)", group: "\(label) trust settings", title: name,
                         value: trust.description, details: details, findings: findings)
    }

    static func describe(_ settings: [[String: Any]]) -> (description: String, isTrustedRoot: Bool, policies: String?) {
        // An empty settings array means "always trust" for every policy.
        if settings.isEmpty { return ("Always trust", true, nil) }
        var results = Set<Int>()
        var policies: [String] = []
        for s in settings {
            let result = (s[kSecTrustSettingsResult as String] as? Int) ?? Int(SecTrustSettingsResult.trustRoot.rawValue)
            results.insert(result)
            if let policy = s[kSecTrustSettingsPolicy as String] {
                let policyRef = policy as! SecPolicy
                let props = SecPolicyCopyProperties(policyRef) as? [String: Any]
                policies.append(props?[kSecPolicyOid as String] as? String ?? "policy")
            }
        }
        let trusted = results.contains(Int(SecTrustSettingsResult.trustRoot.rawValue))
            || results.contains(Int(SecTrustSettingsResult.trustAsRoot.rawValue))
        let denied = results.contains(Int(SecTrustSettingsResult.deny.rawValue))
        let description = trusted ? "Trusted" : denied ? "Never trust" : "Use system defaults"
        return (description, trusted, policies.isEmpty ? nil : policies.joined(separator: "\n"))
    }

    static func notAfter(_ cert: SecCertificate) -> Date? {
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(cert, keys, nil) as? [String: Any],
              let entry = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
              let seconds = entry[kSecPropertyKeyValue as String] as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
    }
}
