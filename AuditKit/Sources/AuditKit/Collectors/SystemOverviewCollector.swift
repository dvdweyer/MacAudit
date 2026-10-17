import Foundation
import IOKit
import SystemConfiguration

public struct SystemOverviewCollector: Collector {
    public let id = "system"
    public let title = "System Overview"
    public let symbol = "desktopcomputer"

    public init() {}

    public func collect(into section: inout SectionResult, context: AuditContext) async {
        let group = "System"
        let version = SystemInfo.systemVersion
        section.note(file: "/System/Library/CoreServices/SystemVersion.plist")
        section.note(api: "sysctl, IOKit, SystemConfiguration")

        func add(_ key: String, _ title: String, _ value: String?) {
            section.add(AuditItem(id: "system:\(key)", group: group, title: title, value: value ?? "Unknown"))
        }

        add("computerName", "Computer name", SCDynamicStoreCopyComputerName(nil, nil) as String?)
        add("localHostName", "Local hostname", SCDynamicStoreCopyLocalHostName(nil) as String?)
        add("model", "Model identifier", SystemInfo.sysctlString("hw.model"))
        add("chip", "Processor", SystemInfo.sysctlString("machdep.cpu.brand_string"))
        if let mem = SystemInfo.sysctlInt("hw.memsize") {
            add("memory", "Memory", ByteCountFormatter.string(fromByteCount: mem, countStyle: .memory))
        }
        add("serial", "Serial number", Self.platformSerial())
        add("osVersion", "macOS version", version["ProductVersion"] as? String)
        add("osBuild", "Build", version["ProductBuildVersion"] as? String)
        if let extra = version["ProductVersionExtra"] as? String {
            add("osExtra", "Background security improvement", extra)
        }
        add("kernel", "Kernel", SystemInfo.sysctlString("kern.version")?.components(separatedBy: ";").first)
        if let boot = SystemInfo.bootTime {
            let uptime = Date().timeIntervalSince(boot)
            var item = AuditItem(id: "system:uptime", group: group, title: "Uptime",
                                 value: Duration.seconds(uptime).formatted(.units(allowed: [.days, .hours, .minutes], width: .abbreviated)),
                                 details: ["Booted": boot.auditString])
            if uptime > 30 * 86_400 {
                item.findings.append(Finding(.notice, "Not restarted in over 30 days",
                                             rationale: "Some security updates (including XProtect and background security improvements) only take full effect after a restart."))
            }
            section.add(item)
        }
        let rosetta = FileManager.default.fileExists(atPath: "/Library/Apple/usr/share/rosetta/rosetta")
        add("rosetta", "Rosetta 2", rosetta ? "Installed" : "Not installed")
    }

    static func platformSerial() -> String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        return IORegistryEntryCreateCFProperty(service, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String
    }
}
