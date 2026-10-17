import Foundation
import Darwin
import SystemConfiguration
import CFNetwork

public struct NetworkCollector: Collector {
    public let id = "network"
    public let title = "Network & Open Ports"
    public let symbol = "network"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        await collectListeners(into: &section, context: context)
        collectInterfaces(into: &section)
        collectDNSAndProxies(into: &section)
        await collectVPN(into: &section, context: context)
        collectHosts(into: &section)
        await collectAirDropAndWiFi(into: &section, context: context)
    }

    private func collectListeners(into section: inout SectionResult, context: AuditContext) async {
        var sockets: [Parsers.Socket] = []
        if let r = await section.run(.netstat, context: context) { sockets = Parsers.netstat(r.stdout) }
        if sockets.isEmpty {
            // macOS hides the system-wide socket table from non-Apple processes (and the tools they launch),
            // so fall back to per-process inspection.
            section.note(api: "libproc (proc_pidinfo, proc_pidfdinfo)")
            var result = ProcSockets.listeningSockets()
            if result.inaccessibleProcesses > 0, let privileged = context.privileged {
                do {
                    result = try await privileged.listeningSockets()
                    section.note(api: "libproc (as root)")
                } catch {
                    section.coverage.degrade(to: .partial, "Listening ports as root: \(error)")
                }
            }
            sockets = result.sockets
            if result.inaccessibleProcesses > 0 {
                section.coverage.degrade(to: .partial,
                    "Listening ports of \(result.inaccessibleProcesses) processes owned by other users (e.g. root daemons such as sshd) are not shown; this \(Privileges.rootHint).")
            }
        }
        section.note(api: "proc_pidpath")

        let listening = sockets.filter { $0.isListening && $0.port != 0 }
            .sorted { ($0.proto.hasPrefix("udp") ? 1 : 0, $0.port, $0.proto) < ($1.proto.hasPrefix("udp") ? 1 : 0, $1.port, $1.proto) }
        var seen = Set<String>()
        for s in listening {
            let key = "\(s.proto):\(s.localAddress):\(s.process)"
            guard seen.insert(key).inserted else { continue }

            var details: [String: String] = [
                "Protocol": s.proto, "Local address": s.localAddress, "Process": s.process,
                "PID": "\(s.pid)", "Exposure": s.isLoopback ? "Loopback only" : "Network",
            ]
            var findings: [Finding] = []
            if let path = Self.executablePath(pid: s.pid) {
                details["Executable"] = path
                let signing = await context.signing.inspect(path: path)
                details.merge(signing.details) { a, _ in a }
                if !s.isLoopback, signing.isUntrusted {
                    findings.append(Finding(.warning, "Network listener from untrusted code",
                        rationale: "\(signing.summary). This process accepts connections from other machines."))
                }
            } else if s.pid != 0 {
                details["Executable"] = "Not resolvable (process exited or insufficient privileges)"
            }
            if !s.isLoopback, Self.sensitivePorts[s.port] != nil, s.proto.hasPrefix("tcp") {
                findings.append(Finding(.notice, "\(Self.sensitivePorts[s.port]!) port open to the network",
                                        rationale: "Port \(s.port) is reachable from other machines unless filtered by the firewall."))
            }
            // PIDs are omitted from the id so snapshots remain comparable across reboots.
            section.add(AuditItem(
                id: "net:listen:\(s.proto):\(s.localAddress):\(s.process)",
                group: s.proto.hasPrefix("tcp") ? "Listening TCP ports" : "Bound UDP ports",
                title: "\(s.port)/\(s.proto) — \(s.process)",
                value: s.isLoopback ? "Loopback" : s.localHost == "*" ? "All interfaces" : s.localHost,
                details: details, findings: findings))
        }
    }

    static let sensitivePorts: [Int: String] = [
        21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 548: "AFP", 3283: "Remote Management",
        3389: "RDP", 5900: "VNC / Screen Sharing", 5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis",
        27017: "MongoDB", 9200: "Elasticsearch",
    ]

    static func executablePath(pid: Int32) -> String? {
        guard pid > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cBuffer: buffer)
    }

    private func collectInterfaces(into section: inout SectionResult) {
        section.note(api: "getifaddrs")
        var addresses: [String: [String]] = [:]
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return }
        defer { freeifaddrs(ifaddr) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            guard let addr = ifa.ifa_addr, (ifa.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }
            let family = addr.pointee.sa_family
            guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let name = String(cString: ifa.ifa_name)
            addresses[name, default: []].append(String(cBuffer: host))
        }
        for (name, addrs) in addresses.sorted(by: { $0.key < $1.key }) where name != "lo0" {
            section.add(AuditItem(id: "net:if:\(name)", group: "Active interfaces", title: name,
                                  value: addrs.first { !$0.contains(":") } ?? addrs.first ?? "",
                                  details: ["Addresses": addrs.joined(separator: "\n")]))
        }
    }

    private func collectDNSAndProxies(into section: inout SectionResult) {
        section.note(api: "SCDynamicStore, CFNetworkCopySystemProxySettings")
        if let dns = SCDynamicStoreCopyValue(nil, "State:/Network/Global/DNS" as CFString) as? [String: Any] {
            let servers = dns["ServerAddresses"] as? [String] ?? []
            section.add(AuditItem(id: "net:dns:servers", group: "DNS & proxies", title: "DNS servers",
                                  value: servers.joined(separator: ", ")))
            if let domains = dns["SearchDomains"] as? [String], !domains.isEmpty {
                section.add(AuditItem(id: "net:dns:search", group: "DNS & proxies", title: "Search domains",
                                      value: domains.joined(separator: ", ")))
            }
        }
        guard let proxies = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return }
        let kinds: [(key: String, title: String, host: String, port: String)] = [
            ("HTTPEnable", "HTTP proxy", "HTTPProxy", "HTTPPort"),
            ("HTTPSEnable", "HTTPS proxy", "HTTPSProxy", "HTTPSPort"),
            ("SOCKSEnable", "SOCKS proxy", "SOCKSProxy", "SOCKSPort"),
        ]
        for k in kinds {
            let on = (proxies[k.key] as? Int ?? 0) == 1
            let value = on ? "\(proxies[k.host] ?? "?"):\(proxies[k.port] ?? "?")" : "Off"
            section.add(AuditItem(id: "net:proxy:\(k.key)", group: "DNS & proxies", title: k.title, value: value,
                                  findings: on ? [Finding(.notice, "\(k.title) configured",
                                      rationale: "Traffic is routed through a proxy that can observe or modify it.")] : []))
        }
        let pac = (proxies["ProxyAutoConfigEnable"] as? Int ?? 0) == 1
        section.add(AuditItem(id: "net:proxy:pac", group: "DNS & proxies", title: "Automatic proxy configuration",
                              value: pac ? (proxies["ProxyAutoConfigURLString"] as? String ?? "On") : "Off",
                              findings: pac ? [Finding(.notice, "Proxy auto-configuration in use",
                                  rationale: "A PAC script decides which traffic goes through a proxy.")] : []))
    }

    private func collectVPN(into section: inout SectionResult, context: AuditContext) async {
        guard let r = await section.run(.scutilNetworkConnections, context: context) else { return }
        for vpn in Parsers.networkConnections(r.stdout) {
            section.add(AuditItem(id: "net:vpn:\(vpn.id)", group: "VPN & network services", title: vpn.name,
                                  value: vpn.status, details: ["Type": vpn.type, "Enabled": vpn.enabled ? "Yes" : "No"]))
        }
    }

    private func collectHosts(into section: inout SectionResult) {
        let path = "/etc/hosts"
        section.note(file: path)
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        for entry in Parsers.customHostEntries(text) {
            section.add(AuditItem(id: "net:hosts:\(entry)", group: "/etc/hosts entries", title: entry, value: "Custom",
                                  findings: [Finding(.notice, "Custom hosts entry",
                                      rationale: "Overrides DNS for these names; malware sometimes uses this to block or redirect sites.")]))
        }
    }

    private func collectAirDropAndWiFi(into section: inout SectionResult, context: AuditContext) async {
        let mode = PlistReader.preference("DiscoverableMode", domain: "com.apple.sharingd") as? String ?? "Contacts Only (default)"
        section.add(AuditItem(id: "net:airdrop", group: "Wireless", title: "AirDrop discoverability", value: mode,
                              findings: mode == "Everyone" ? [Finding(.notice, "AirDrop visible to everyone",
                                  rationale: "Anyone nearby can send AirDrop requests.")] : []))

        let known = "/Library/Preferences/com.apple.wifi.known-networks.plist"
        guard context.privileged != nil else {
            section.coverage.degrade(to: .partial, "Known Wi-Fi networks: \(Privileges.rootHint).")
            return
        }
        guard let data = await section.readPrivileged(known, context: context) else { return }
        for (key, raw) in (PlistReader.dictionary(from: data) ?? [:]).sorted(by: { $0.key < $1.key }) {
            let d = raw as? [String: Any] ?? [:]
            let security = d["SupportedSecurityTypes"] as? String ?? "Unknown"
            let ssid = key.replacingOccurrences(of: "wifi.network.ssid.", with: "")
            let open = security.lowercased().contains("open")
            section.add(AuditItem(id: "net:wifi:\(ssid)", group: "Known Wi-Fi networks", title: ssid, value: security,
                                  findings: open ? [Finding(.info, "Open Wi-Fi network remembered",
                                      rationale: "The Mac auto-joins this unencrypted network when in range.")] : []))
        }
    }
}

extension Parsers {
    struct Socket: Codable, Equatable {
        var proto: String
        var localAddress: String
        var foreignAddress: String
        var state: String
        var process: String
        var pid: Int32

        var localHost: String { Parsers.splitHostPort(localAddress).host }
        var port: Int { Int(Parsers.splitHostPort(localAddress).port) ?? 0 }
        var isListening: Bool {
            proto.hasPrefix("tcp") ? state == "LISTEN" : foreignAddress == "*.*"
        }
        var isLoopback: Bool {
            let h = localHost
            return h.hasPrefix("127.") || h == "::1" || h.hasSuffix("%lo0") || h == "localhost"
        }
    }

    static func splitHostPort(_ address: String) -> (host: String, port: String) {
        guard let dot = address.lastIndex(of: ".") else { return (address, "") }
        return (String(address[..<dot]), String(address[address.index(after: dot)...]))
    }

    /// Parses `netstat -anv`; the process column may contain spaces, so it is located relative
    /// to the fixed-width hex columns that follow it.
    static func netstat(_ output: String) -> [Socket] {
        let hex5 = /^[0-9a-fA-F]{5}$/
        let hex8 = /^[0-9a-fA-F]{8}$/
        var sockets: [Socket] = []
        for line in output.split(separator: "\n") {
            let t = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let proto = t.first, proto.hasPrefix("tcp") || proto.hasPrefix("udp"), t.count > 10 else { continue }
            let isTCP = proto.hasPrefix("tcp")
            let state = isTCP ? t[5] : ""
            let procStart = (isTCP ? 6 : 5) + 4
            guard procStart < t.count,
                  let end = (procStart..<(t.count - 1)).first(where: { t[$0].wholeMatch(of: hex5) != nil && t[$0 + 1].wholeMatch(of: hex8) != nil })
            else { continue }
            let procField = t[procStart..<end].joined(separator: " ")
            guard let colon = procField.lastIndex(of: ":") else { continue }
            sockets.append(Socket(proto: proto, localAddress: t[3], foreignAddress: t[4], state: state,
                                  process: String(procField[..<colon]),
                                  pid: Int32(procField[procField.index(after: colon)...]) ?? 0))
        }
        return sockets
    }

    struct NetworkConnection: Equatable {
        var id: String
        var name: String
        var type: String
        var status: String
        var enabled: Bool
    }

    static func networkConnections(_ output: String) -> [NetworkConnection] {
        let pattern = /^(\*?)\s*\(([^)]+)\)\s+([0-9A-F-]{36})\s+(.+?)\s+"([^"]*)"/
        return output.split(separator: "\n").compactMap { line in
            guard let m = String(line).firstMatch(of: pattern) else { return nil }
            return NetworkConnection(id: String(m.3), name: String(m.5), type: String(m.4).trimmed,
                                     status: String(m.2), enabled: m.1 == "*")
        }
    }

    static func customHostEntries(_ text: String) -> [String] {
        let defaults: Set<String> = ["127.0.0.1 localhost", "255.255.255.255 broadcasthost", "::1 localhost", "fe80::1%lo0 localhost"]
        return text.split(separator: "\n").compactMap { raw in
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init)?.trimmed ?? ""
            guard !line.isEmpty else { return nil }
            let normalized = line.split(whereSeparator: \.isWhitespace).joined(separator: " ")
            return defaults.contains(normalized) ? nil : normalized
        }
    }
}
