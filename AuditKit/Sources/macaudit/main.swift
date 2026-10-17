import Foundation
import AuditKit

let usage = """
usage: macaudit run [--format text|json|html] [--output PATH] [--sections id,id,...] [--save-snapshot]
       macaudit diff OLD.json NEW.json
       macaudit sections

Read-only audit of this Mac's security configuration. Grant Full Disk Access to your terminal
for complete privacy-permission data; run with sudo for root-only data (background items,
location clients, other users' crontabs, known Wi-Fi networks, sudoers).
"""

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(64)
}

func write(_ data: Data, to path: String?) {
    if let path {
        do { try data.write(to: URL(fileURLWithPath: path), options: .atomic) }
        catch { fail("Could not write \(path): \(error.localizedDescription)") }
    } else {
        FileHandle.standardOutput.write(data)
    }
}

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else { fail(usage) }
args.removeFirst()

switch command {
case "sections":
    for c in AuditEngine.allCollectors { print("\(c.id)\t\(c.title)") }

case "run":
    var format = "text"
    var output: String?
    var sections: Set<String>?
    var saveSnapshot = false
    var i = 0
    while i < args.count {
        let value: () -> String = {
            guard i + 1 < args.count else { fail("Missing value for \(args[i])") }
            i += 1
            return args[i]
        }
        switch args[i] {
        case "--format", "-f": format = value()
        case "--output", "-o": output = value()
        case "--sections", "-s": sections = Set(value().split(separator: ",").map(String.init))
        case "--save-snapshot": saveSnapshot = true
        case "-h", "--help": print(usage); exit(0)
        default: fail("Unknown option \(args[i])\n\n\(usage)")
        }
        i += 1
    }
    if let sections {
        let known = Set(AuditEngine.allCollectors.map(\.id))
        let unknown = sections.subtracting(known)
        if !unknown.isEmpty { fail("Unknown section(s): \(unknown.sorted().joined(separator: ", "))") }
    }
    let interactive = isatty(STDERR_FILENO) == 1
    let report = await AuditEngine().run(sections: sections) { progress in
        if interactive, case .finished(let s) = progress {
            FileHandle.standardError.write(Data("  ✓ \(s.title) (\(String(format: "%.1f", s.duration))s)\n".utf8))
        }
    }
    switch format {
    case "json":
        do { write(try JSONExporter.encode(report), to: output) } catch { fail("\(error)") }
    case "html":
        write(Data(HTMLRenderer.render(report).utf8), to: output)
    case "text":
        write(Data(TextRenderer.render(report).utf8), to: output)
    default:
        fail("Unknown format \(format)")
    }
    if saveSnapshot {
        do {
            let url = try SnapshotStore().save(report)
            FileHandle.standardError.write(Data("Snapshot saved to \(url.path)\n".utf8))
        } catch { fail("Could not save snapshot: \(error)") }
    }

case "diff":
    guard args.count == 2 else { fail(usage) }
    do {
        let old = try JSONExporter.decode(Data(contentsOf: URL(fileURLWithPath: args[0])))
        let new = try JSONExporter.decode(Data(contentsOf: URL(fileURLWithPath: args[1])))
        print(ReportDiff(old: old, new: new).textSummary)
    } catch {
        fail("Could not read reports: \(error)")
    }

case "-h", "--help", "help":
    print(usage)

default:
    fail(usage)
}
