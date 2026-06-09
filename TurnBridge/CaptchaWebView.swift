import SwiftUI
import WebKit
import Combine

/// Sheet that loads the VK captcha page in a WKWebView, watches XHR / URL
/// activity for a `success_token`, and reports the result back via
/// CaptchaManager.
struct CaptchaWebView: View {
    let redirectUri: String
    @ObservedObject var manager: CaptchaManager = .shared
    @Environment(\.dismiss) private var dismiss

    @State private var status: String = "Solve the VK challenge below"
    @State private var didFinish = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                Text(status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity)
                    .background(Color(.secondarySystemBackground))

                CaptchaWKWebView(
                    url: URL(string: redirectUri),
                    onToken: { token in
                        guard !didFinish else { return }
                        didFinish = true
                        status = "Got token, finishing…"
                        Task {
                            await manager.submit(token: token)
                            dismiss()
                        }
                    },
                    onStatus: { s in status = s }
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .navigationTitle("Verify human")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        guard !didFinish else { return }
                        didFinish = true
                        Task {
                            await manager.cancel()
                            dismiss()
                        }
                    }
                }
            }
            .onAppear {
                SharedLogger.info("Captcha sheet appeared. redirect_uri=\(redirectUri)", source: .app)
            }
        }
        .navigationViewStyle(.stack)
    }
}

private struct CaptchaWKWebView: UIViewRepresentable {
    let url: URL?
    let onToken: (String) -> Void
    let onStatus: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onToken: onToken, onStatus: onStatus)
    }

    func makeUIView(context: Context) -> WKWebView {
        let userContent = WKUserContentController()
        userContent.add(context.coordinator, name: "captcha")

        // Inject the bot-tell scrubbers BEFORE any page JS runs.
        // - safariUAOverride: WKWebView's default JS-side
        //   navigator.userAgent lacks "Version/X.Y Safari/604.1" that
        //   real Mobile Safari emits; classifiers key on this exact
        //   diff. We mock navigator.userAgent + navigator.vendor on
        //   document-start so VK's bootstrap script sees the same UA
        //   string that the HTTP request carries (set via
        //   customUserAgent below).
        // - The original captcha helper script then runs and hooks
        //   fetch/XHR for success_token.
        userContent.addUserScript(WKUserScript(
            source: Self.safariUAOverride,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        ))
        userContent.addUserScript(WKUserScript(
            source: Self.injectedJS,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        ))

        let config = WKWebViewConfiguration()
        config.userContentController = userContent
        if #available(iOS 14.0, *) {
            config.defaultWebpagePreferences.allowsContentJavaScript = true
        }
        // Persistent data store: VK's classifier treats a captcha
        // session with zero prior vk.com cookies / localStorage as a
        // signal of a freshly-spun-up automation environment. Sharing
        // state across captcha sheets within the app gives real users
        // the same "I've been here before" signal that web Safari has.
        // We don't share with the system Safari (that requires
        // ASWebAuthenticationSession), but app-scoped persistence is
        // enough for the classifier.
        config.websiteDataStore = .default()

        let webView = WKWebView(frame: UIScreen.main.bounds, configuration: config)
        // Send the EXACT Mobile Safari UA. WKWebView's default UA is
        // missing the "Version/X.Y Safari/604.1" suffix — that gap is
        // one of the cheapest bot tells VK has. iOS 18 is the current
        // production version; if Apple ships 19 the suffix updates
        // organically but anything in the 17-18-19 range matches what
        // VK sees from real Safari iOS users.
        webView.customUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.backgroundColor = .systemBackground
        webView.scrollView.backgroundColor = .systemBackground
        webView.isOpaque = true

        if let url = url {
            SharedLogger.info("CaptchaWebView loading URL: \(url.absoluteString)", source: .app)
            onStatus("Loading…")
            webView.load(URLRequest(url: url))
        } else {
            SharedLogger.error("CaptchaWebView: URL is nil — won't load", source: .app)
            onStatus("Bad captcha URL")
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let onToken: (String) -> Void
        let onStatus: (String) -> Void

        init(onToken: @escaping (String) -> Void, onStatus: @escaping (String) -> Void) {
            self.onToken = onToken
            self.onStatus = onStatus
        }

        func userContentController(_ userContentController: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            guard message.name == "captcha",
                  let body = message.body as? [String: Any],
                  let type = body["type"] as? String else { return }
            switch type {
            case "success_token":
                if let token = body["token"] as? String, !token.isEmpty {
                    onToken(token)
                }
            case "status":
                if let s = body["text"] as? String {
                    onStatus(s)
                }
            default:
                break
            }
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            // Watch top-level navigations for `?success_token=...` or
            // `#success_token=...` — some flows put it in the URL.
            if let url = navigationAction.request.url {
                let token = tokenFromURL(url)
                if !token.isEmpty {
                    onToken(token)
                    decisionHandler(.cancel)
                    return
                }
            }
            decisionHandler(.allow)
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            onStatus("Loading captcha…")
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            SharedLogger.info("CaptchaWebView: page finished loading: \(webView.url?.absoluteString ?? "?")", source: .app)
            onStatus("Solve the VK challenge below")
        }

        func webView(_ webView: WKWebView,
                     didFail navigation: WKNavigation!,
                     withError error: Error) {
            SharedLogger.error("CaptchaWebView: navigation failed: \(error.localizedDescription)", source: .app)
            onStatus("Failed: \(error.localizedDescription)")
        }

        func webView(_ webView: WKWebView,
                     didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            SharedLogger.error("CaptchaWebView: provisional navigation failed: \(error.localizedDescription)", source: .app)
            onStatus("Failed: \(error.localizedDescription)")
        }

        private func tokenFromURL(_ url: URL) -> String {
            if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
               let item = comps.queryItems?.first(where: { $0.name == "success_token" }),
               let v = item.value {
                return v
            }
            if let fragment = url.fragment {
                for part in fragment.split(separator: "&") {
                    let kv = part.split(separator: "=", maxSplits: 1).map(String.init)
                    if kv.count == 2, kv[0] == "success_token" {
                        return kv[1].removingPercentEncoding ?? kv[1]
                    }
                }
            }
            return ""
        }
    }

    // Mock navigator.userAgent + companion fields BEFORE any page JS
    // runs so VK's classifier sees the Mobile Safari signature instead
    // of WKWebView's truncated default. customUserAgent on the WKWebView
    // handles the HTTP request side; this script handles the JS side
    // (window.navigator.userAgent + navigator.userAgentData + vendor).
    // Must run at document-start so vk's bootstrap doesn't capture the
    // un-patched values before us.
    //
    // Also strips `navigator.webdriver` (some WKWebView builds set it
    // to false but the property's mere presence is a tell), and forces
    // languages to match what an en-US Safari iOS reports.
    private static let safariUAOverride = """
    (function() {
        const ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        try {
            Object.defineProperty(navigator, 'userAgent', { get: () => ua, configurable: true });
        } catch (e) {}
        try {
            Object.defineProperty(navigator, 'appVersion', { get: () => ua.replace(/^Mozilla\\//, ''), configurable: true });
        } catch (e) {}
        try {
            Object.defineProperty(navigator, 'vendor', { get: () => 'Apple Computer, Inc.', configurable: true });
        } catch (e) {}
        try {
            Object.defineProperty(navigator, 'platform', { get: () => 'iPhone', configurable: true });
        } catch (e) {}
        try {
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'], configurable: true });
        } catch (e) {}
        // Real Safari iOS doesn't expose userAgentData (Client Hints).
        // WKWebView under some configurations does — strip it to match.
        try { delete navigator.userAgentData; } catch (e) {}
        // Drop the webdriver flag entirely. Real Safari has no such
        // property; WKWebView sets it (usually false). Presence ≠
        // absence to a fingerprinter.
        try { delete navigator.webdriver; } catch (e) {}
        try {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined, configurable: true });
        } catch (e) {}
    })();
    """

    // Injected as document-start so we patch fetch/XHR before VK's page code
    // gets a chance to fire. Looks for any response from `captchaNotRobot.*`
    // that carries `success_token`, and also polls the URL / page text as a
    // belt-and-braces fallback.
    private static let injectedJS = """
    (function() {
        function send(payload) {
            try { window.webkit.messageHandlers.captcha.postMessage(payload); } catch (e) {}
        }

        function maybeTokenFromText(text) {
            if (!text) return null;
            try {
                const json = JSON.parse(text);
                if (json && json.response && json.response.success_token) {
                    return json.response.success_token;
                }
            } catch (e) {}
            const m = String(text).match(/"success_token"\\s*:\\s*"([^"]+)"/);
            return m ? m[1] : null;
        }

        // fetch hook
        const origFetch = window.fetch;
        if (origFetch) {
            window.fetch = function(input, init) {
                const url = (typeof input === 'string') ? input : (input && input.url) || '';
                const p = origFetch.apply(this, arguments);
                if (url && url.indexOf('captchaNotRobot') !== -1) {
                    p.then(function(res) {
                        try {
                            res.clone().text().then(function(text) {
                                const t = maybeTokenFromText(text);
                                if (t) send({type:'success_token', token: t});
                            });
                        } catch (e) {}
                    }).catch(function() {});
                }
                return p;
            };
        }

        // XHR hook
        const origOpen = XMLHttpRequest.prototype.open;
        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function(method, url) {
            this.__cap_url = url;
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function() {
            const xhr = this;
            const prev = xhr.onreadystatechange;
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4 && xhr.__cap_url &&
                    String(xhr.__cap_url).indexOf('captchaNotRobot') !== -1) {
                    const t = maybeTokenFromText(xhr.responseText);
                    if (t) send({type:'success_token', token: t});
                }
                if (typeof prev === 'function') return prev.apply(this, arguments);
            };
            return origSend.apply(this, arguments);
        };

        // postMessage relay
        window.addEventListener('message', function(ev) {
            try {
                const data = ev.data;
                if (data && typeof data === 'object') {
                    if (data.success_token) send({type:'success_token', token: data.success_token});
                    if (data.type === 'captcha_success' && data.token) {
                        send({type:'success_token', token: data.token});
                    }
                } else if (typeof data === 'string') {
                    const t = maybeTokenFromText(data);
                    if (t) send({type:'success_token', token: t});
                }
            } catch (e) {}
        });

        // URL / location polling — sometimes VK reflects token in hash on success.
        let lastUrl = '';
        setInterval(function() {
            if (location.href !== lastUrl) {
                lastUrl = location.href;
                try {
                    const u = new URL(location.href);
                    let t = u.searchParams.get('success_token');
                    if (!t && u.hash) {
                        const params = new URLSearchParams(u.hash.replace(/^#/, ''));
                        t = params.get('success_token');
                    }
                    if (t) send({type:'success_token', token: t});
                } catch (e) {}
            }
        }, 250);

        send({type:'status', text:'Loaded captcha helper'});
    })();
    """
}
