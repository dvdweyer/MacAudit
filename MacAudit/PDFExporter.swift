import AppKit
import WebKit

/// Paginated PDF export: the HTML report is laid out in an off-screen WKWebView and printed to a file.
@MainActor
final class PDFExporter: NSObject, WKNavigationDelegate {
    static let shared = PDFExporter()

    private var webView: WKWebView?
    private var window: NSWindow?
    private var pending: (url: URL, completion: (Error?) -> Void)?

    func export(html: String, to url: URL, completion: @escaping (Error?) -> Void) {
        let printInfo = NSPrintInfo.shared
        let frame = NSRect(x: 0, y: 0, width: printInfo.paperSize.width, height: printInfo.paperSize.height)
        let webView = WKWebView(frame: frame)
        webView.navigationDelegate = self
        // Print operations on WKWebView render blank pages unless the view is in a window.
        let window = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = webView
        self.webView = webView
        self.window = window
        pending = (url, completion)
        webView.loadHTMLString(html, baseURL: nil)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard let pending else { return }
        let info = (NSPrintInfo.shared.copy() as! NSPrintInfo)
        info.jobDisposition = .save
        info.dictionary()[NSPrintInfo.AttributeKey.jobSavingURL] = pending.url
        info.topMargin = 36
        info.bottomMargin = 36
        info.leftMargin = 36
        info.rightMargin = 36
        info.horizontalPagination = .fit
        info.verticalPagination = .automatic
        let op = webView.printOperation(with: info)
        op.showsPrintPanel = false
        op.showsProgressPanel = false
        op.view?.frame = webView.bounds
        let ok = op.run()
        pending.completion(ok ? nil : CocoaError(.fileWriteUnknown))
        cleanup()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        pending?.completion(error)
        cleanup()
    }

    private func cleanup() {
        pending = nil
        webView = nil
        window = nil
    }
}
