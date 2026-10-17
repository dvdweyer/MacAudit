import Foundation

/// Renders a self-contained HTML report (no external resources), also used as the source for PDF export.
public enum HTMLRenderer {
    public static func render(_ report: AuditReport) -> String {
        var body = """
        <header>
          <h1>MacAudit report</h1>
          <p class="meta">\(esc(report.host.hostname)) · macOS \(esc(report.host.osVersion)) (\(esc(report.host.osBuild))) ·
          generated \(esc(report.generatedAt.auditString)) as \(esc(report.host.user))\(report.host.runningAsRoot ? " (root)" : "") ·
          Full Disk Access: \(report.host.fullDiskAccess ? "yes" : "no")</p>
          <div class="counts">
        """
        for s in Severity.allCases.reversed() {
            body += "<span class=\"pill \(s.rawValue)\">\(report.findingCount(s)) \(s.rawValue)</span>"
        }
        body += "</div></header>\n"

        let findings = report.sections.flatMap { section in
            section.items.flatMap { item in item.findings.map { (section, item, $0) } }
        }.filter { $0.2.severity >= .notice }.sorted { $0.2.severity > $1.2.severity }
        if !findings.isEmpty {
            body += "<section><h2>Key findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Item</th><th>Why it matters</th></tr>"
            for (section, item, f) in findings {
                body += "<tr><td><span class=\"pill \(f.severity.rawValue)\">\(f.severity.rawValue)</span></td><td>\(esc(f.title))</td><td>\(esc(section.title)) › \(esc(item.title))</td><td>\(esc(f.rationale))</td></tr>"
            }
            body += "</table></section>\n"
        }

        body += "<nav><h2>Contents</h2><ol>"
        for section in report.sections {
            body += "<li><a href=\"#\(esc(section.id))\">\(esc(section.title))</a> <span class=\"cov \(section.coverage.status.rawValue)\">\(section.coverage.status.rawValue)</span></li>"
        }
        body += "</ol></nav>\n"

        for section in report.sections {
            body += "<section id=\"\(esc(section.id))\"><h2>\(esc(section.title)) <span class=\"cov \(section.coverage.status.rawValue)\">\(section.coverage.status.rawValue)</span></h2>"
            for note in section.coverage.notes { body += "<p class=\"note\">\(esc(note))</p>" }
            var groups: [String: [AuditItem]] = [:]
            var order: [String] = []
            for item in section.items {
                if groups[item.group] == nil { order.append(item.group) }
                groups[item.group, default: []].append(item)
            }
            for group in order {
                body += "<h3>\(esc(group))</h3><table>"
                for item in groups[group] ?? [] {
                    let sev = item.highestSeverity.map { " class=\"row-\($0.rawValue)\"" } ?? ""
                    body += "<tr\(sev)><td class=\"t\">\(esc(item.title))</td><td>\(esc(item.value))"
                    for f in item.findings {
                        body += "<div class=\"finding\"><span class=\"pill \(f.severity.rawValue)\">\(f.severity.rawValue)</span> \(esc(f.title)) — <span class=\"why\">\(esc(f.rationale))</span></div>"
                    }
                    body += "</td></tr>"
                }
                body += "</table>"
            }
            let sources = Array(Set(section.sources.map(\.label))).sorted()
            body += "<details><summary>Data sources (\(sources.count))</summary><ul>"
            for s in sources { body += "<li><code>\(esc(s))</code></li>" }
            body += "</ul></details></section>\n"
        }

        return """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MacAudit — \(esc(report.host.hostname))</title>
        <style>\(css)</style></head>
        <body>\(body)</body></html>
        """
    }

    static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    static let css = """
    :root { --bg:#fff; --fg:#1d1d1f; --muted:#6e6e73; --line:#e5e5ea; --row:#fafafa;
      --info:#0a84ff; --notice:#b25000; --warning:#d70015; --critical:#fff; --criticalbg:#a1001c; }
    @media (prefers-color-scheme: dark) { :root { --bg:#1c1c1e; --fg:#f5f5f7; --muted:#a1a1a6; --line:#3a3a3c; --row:#242426;
      --info:#64d2ff; --notice:#ffb340; --warning:#ff6961; } }
    * { box-sizing: border-box; }
    body { font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; background: var(--bg); color: var(--fg);
      max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
    h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
    h3 { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin: 18px 0 6px; }
    .meta { color: var(--muted); margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    td, th { text-align: left; vertical-align: top; padding: 5px 8px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
    th { color: var(--muted); font-weight: 500; }
    td.t { width: 38%; font-weight: 500; }
    tr:nth-child(even) td { background: var(--row); }
    .pill { display: inline-block; border-radius: 10px; padding: 0 8px; font-size: 11px; font-weight: 600; border: 1px solid currentColor; margin-right: 4px; }
    .pill.info { color: var(--info); } .pill.notice { color: var(--notice); } .pill.warning { color: var(--warning); }
    .pill.critical { color: var(--critical); background: var(--criticalbg); border-color: var(--criticalbg); }
    .counts { display: flex; gap: 6px; flex-wrap: wrap; }
    .finding { margin-top: 3px; font-size: 12px; } .why { color: var(--muted); }
    .cov { font-size: 11px; font-weight: 500; color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; padding: 0 6px; }
    .cov.partial { color: var(--notice); } .cov.unavailable { color: var(--warning); }
    .note { color: var(--notice); font-size: 12px; margin: 4px 0; }
    details { margin-top: 8px; color: var(--muted); font-size: 12px; } code { font-size: 11px; }
    nav ol { columns: 2; } a { color: var(--info); }
    @media print { body { max-width: none; } section { break-inside: auto; } h2 { break-after: avoid; } details { display: none; } }
    """
}
