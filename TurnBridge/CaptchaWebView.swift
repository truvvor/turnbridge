import SwiftUI
import WebKit
import Combine

/// Sheet that loads the VK captcha page in a WKWebView, watches XHR / URL
/// activity for a `success_token`, and reports the result back via
/// CaptchaManager.
struct CaptchaWebView: View {
    let redirectUri: String
    /// When non-nil, the injected JS will, after extracting
    /// success_token, replay this request inside the WebView's session
    /// (POST `retryBody` with literal "__TOKEN__" swapped for the
    /// actual token, to `retryUrl`). The full JSON response goes back
    /// via `onResponse`. nil = legacy token-only flow.
    let retryUrl: String?
    let retryBody: String?
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
                    retryUrl: retryUrl,
                    retryBody: retryBody,
                    onToken: { token in
                        guard !didFinish else { return }
                        didFinish = true
                        status = "Got token, finishing…"
                        Task {
                            await manager.submit(token: token)
                            dismiss()
                        }
                    },
                    onResponse: { responseJson in
                        guard !didFinish else { return }
                        didFinish = true
                        status = "Got response, finishing…"
                        Task {
                            await manager.submit(response: responseJson)
                            dismiss()
                        }
                    },
                    onTerminal: { reason in
                        // VK rendered a terminal failure page ("Attempt
                        // limit reached" etc). No way for the user to
                        // recover from inside the sheet — cancel and
                        // let Go bail to identity recycling.
                        guard !didFinish else { return }
                        didFinish = true
                        status = "VK refused: \(reason.prefix(80))"
                        SharedLogger.info("CaptchaWebView terminal page detected: \(reason)", source: .app)
                        Task {
                            await manager.cancel(reason: "vk terminal: \(reason.prefix(120))")
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
                        // Cancel ALWAYS works, even if didFinish is
                        // already true. This is the user's escape
                        // hatch when something downstream wedges —
                        // we'd rather double-cancel (idempotent on
                        // both Swift and Go sides) than trap the
                        // user staring at a frozen sheet.
                        didFinish = true
                        SharedLogger.info("CaptchaWebView: user pressed Cancel (state.didFinish was \(didFinish))", source: .app)
                        Task {
                            await manager.cancel()
                            dismiss()
                        }
                    }
                }
            }
            .onAppear {
                SharedLogger.info("Captcha sheet appeared. redirect_uri=\(redirectUri)", source: .app)
                // Watchdog: if nothing — solve, terminal, user cancel
                // — happens in 175 s, cancel ourselves. Go's
                // requestManualCaptcha times out at 180 s; firing 5 s
                // earlier on our side means the UI never lingers past
                // a backend already-gave-up state.
                Task {
                    try? await Task.sleep(nanoseconds: 175_000_000_000)
                    guard !didFinish else { return }
                    didFinish = true
                    status = "Timed out waiting for solve"
                    SharedLogger.warning("CaptchaWebView watchdog timeout (175 s) — auto-cancelling", source: .app)
                    await manager.cancel(reason: "ui watchdog timeout")
                    dismiss()
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}

private struct CaptchaWKWebView: UIViewRepresentable {
    let url: URL?
    let retryUrl: String?
    let retryBody: String?
    let onToken: (String) -> Void
    let onResponse: (String) -> Void
    let onTerminal: (String) -> Void
    let onStatus: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onToken: onToken,
                    onResponse: onResponse,
                    onTerminal: onTerminal,
                    onStatus: onStatus)
    }

    func makeUIView(context: Context) -> WKWebView {
        let userContent = WKUserContentController()
        userContent.add(context.coordinator, name: "captcha")

        // Inject the bot-tell scrubbers BEFORE any page JS runs.
        // - safariUAOverride: navigator.* spoofing so JS-visible UA
        //   matches the HTTP UA set via customUserAgent.
        // - retry config: small script that defines window.__capRetry
        //   with the URL + body template before the captcha helper
        //   reads it. JSON-stringified to handle the body's special
        //   chars safely.
        // - injectedJS: the helper that hooks fetch/XHR for
        //   success_token and either fires onResponse (if retry params
        //   are present and the in-WebView retry succeeded) or
        //   onToken (legacy).
        userContent.addUserScript(WKUserScript(
            source: Self.safariUAOverride,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        ))
        if let url = retryUrl, let body = retryBody, !url.isEmpty {
            let urlJSON = Self.jsString(url)
            let bodyJSON = Self.jsString(body)
            let retryScript = "window.__capRetry = {url: \(urlJSON), body: \(bodyJSON)};"
            userContent.addUserScript(WKUserScript(
                source: retryScript,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: false
            ))
        }
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
            context.coordinator.captchaURL = url
            // Cookie / state warm-up. VK's classifier reads a captcha
            // session with zero prior vk.com cookies + localStorage as a
            // freshly-spun-up automation environment — exactly the BOT
            // signal we're trying to avoid on the first hand-solved
            // sessions. So before navigating to the captcha, briefly
            // load m.vk.com so the persistent data store picks up the
            // organic "I've been here before" state a real Safari user
            // would have. The real captcha load is kicked off from the
            // warm-up's didFinish (or a 3 s hard cap, whichever first)
            // so a blocked / slow warm-up never strands the user.
            SharedLogger.info("CaptchaWebView warming up vk.com cookies before captcha load", source: .app)
            onStatus("Preparing…")
            if let warmURL = URL(string: "https://m.vk.com/") {
                webView.load(URLRequest(url: warmURL))
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { [weak webView] in
                    guard let webView = webView else { return }
                    context.coordinator.loadCaptchaIfNeeded(webView, reason: "warmup cap 3s")
                }
            } else {
                context.coordinator.loadCaptchaIfNeeded(webView, reason: "no warmup url")
            }
        } else {
            SharedLogger.error("CaptchaWebView: URL is nil — won't load", source: .app)
            onStatus("Bad captcha URL")
        }
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let onToken: (String) -> Void
        let onResponse: (String) -> Void
        let onStatus: (String) -> Void

        let onTerminal: (String) -> Void

        /// The real captcha URL, loaded only AFTER the cookie warm-up
        /// (or its 3 s cap) so VK sees an aged vk.com session rather
        /// than a cold one. Set in makeUIView.
        var captchaURL: URL?
        private var captchaLoadStarted = false

        init(onToken: @escaping (String) -> Void,
             onResponse: @escaping (String) -> Void,
             onTerminal: @escaping (String) -> Void,
             onStatus: @escaping (String) -> Void) {
            self.onToken = onToken
            self.onResponse = onResponse
            self.onTerminal = onTerminal
            self.onStatus = onStatus
        }

        /// Navigate to the real captcha page exactly once. Called from
        /// the warm-up's didFinish and from a 3 s fallback timer —
        /// whichever fires first wins; the flag makes the loser a no-op.
        func loadCaptchaIfNeeded(_ webView: WKWebView, reason: String) {
            guard !captchaLoadStarted, let url = captchaURL else { return }
            captchaLoadStarted = true
            SharedLogger.info("CaptchaWebView loading captcha after warmup (\(reason)): \(url.absoluteString)", source: .app)
            onStatus("Loading…")
            webView.load(URLRequest(url: url))
        }

        func userContentController(_ userContentController: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            guard message.name == "captcha",
                  let body = message.body as? [String: Any],
                  let type = body["type"] as? String else { return }
            switch type {
            case "final_response":
                // Preferred path: WebView did the VK API replay
                // inside the same browser session that solved the
                // captcha, and the response is the raw JSON the
                // extension would have gotten by doing the redemption
                // itself. No session switch.
                if let json = body["json"] as? String, !json.isEmpty {
                    onResponse(json)
                }
            case "success_token":
                // Legacy / fallback path: the in-WebView retry didn't
                // happen (no retry params, fetch threw, etc). Pass
                // the raw token; the extension does the retry from Go
                // and hopes VK accepts the session switch.
                if let token = body["token"] as? String, !token.isEmpty {
                    onToken(token)
                }
            case "status":
                if let s = body["text"] as? String {
                    // Mirror WebView-side status into the shared log so a
                    // device sysdiagnose shows whether the in-session
                    // replay actually produced a final_response or quietly
                    // fell back to the bot-prone raw-token path (CORS/CSP
                    // on the cross-origin api.vk.com fetch is the usual
                    // culprit). See injectedJS handleSuccessToken.
                    SharedLogger.debug("CaptchaWebView JS: \(s)", source: .app)
                    onStatus(s)
                }
            case "terminal":
                // Server-rendered failure page ("Attempt limit
                // reached" etc). The captcha isn't going anywhere,
                // and the user has no way to recover from inside
                // the sheet — close it. The Cancel path in the
                // CaptchaManager fires the cancel IPC so Go's
                // requestManualCaptcha unblocks immediately rather
                // than waiting for its 180s timeout.
                let reason = (body["reason"] as? String) ?? "terminal page"
                onTerminal(reason)
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
            // The first finished navigation is the cookie warm-up
            // (m.vk.com). Now that the data store has organic vk.com
            // state, navigate to the real captcha. Subsequent didFinish
            // calls (the captcha page itself) are no-ops via the flag.
            if captchaURL != nil {
                loadCaptchaIfNeeded(webView, reason: "warmup finished")
            }
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

    /// JSON-quote a Swift string for embedding into JS source code.
    /// Handles backslashes, quotes, newlines, etc.
    fileprivate static func jsString(_ s: String) -> String {
        let data = try? JSONSerialization.data(withJSONObject: [s], options: [])
        guard let data = data,
              let json = String(data: data, encoding: .utf8) else {
            return "\"\""
        }
        // Strip the surrounding [ ... ] so we get just the quoted string.
        let inner = json.dropFirst().dropLast()
        // Belt-and-braces: escape "</" so it can't terminate a <script>
        // tag if the source ever ends up embedded in HTML directly.
        return String(inner).replacingOccurrences(of: "</", with: "<\\/")
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
        // Touch surface: real Mobile Safari on iPhone reports
        // maxTouchPoints = 5. WKWebView sometimes reports 0/1, which is
        // an obvious "this isn't a phone browser" tell to a fingerprinter.
        try {
            Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 5, configurable: true });
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

        // Once true, no more sends — first solve wins.
        let solved = false;

        // When the captcha helper grabs success_token, this runs.
        // If window.__capRetry is set (retryUrl + retryBody from the
        // extension), do the follow-up VK API call inside this
        // browser session — same cookies, same TLS, same IP, no
        // session switch for VK to flag. Send the JSON response as
        // 'final_response'. Fall back to sending the raw token on any
        // hiccup so the legacy Go-side retry still gets a chance.
        function handleSuccessToken(token) {
            if (solved) return;
            solved = true;
            const cfg = window.__capRetry;
            if (!cfg || !cfg.url || !cfg.body) {
                send({type: 'success_token', token: token});
                return;
            }
            const body = cfg.body.replace(/__TOKEN__/g, encodeURIComponent(token));
            send({type: 'status', text: 'replay: redeeming token in-session (POST ' + cfg.url + ')'});
            fetch(cfg.url, {
                method: 'POST',
                credentials: 'include',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: body
            }).then(function(r) { return r.text(); })
              .then(function(text) {
                  if (text && text.length > 0) {
                      send({type: 'status', text: 'replay OK: final_response (' + text.length + ' bytes) — single coherent session'});
                      send({type: 'final_response', json: text});
                  } else {
                      // 2xx but empty body — treat as replay miss so the
                      // log makes the silent-degrade-to-raw-token explicit.
                      send({type: 'status', text: 'replay FALLBACK: empty response body → raw token (Go will redeem, session switch risk)'});
                      send({type: 'success_token', token: token});
                  }
              })
              .catch(function(e) {
                  // The common cause here is the cross-origin fetch to
                  // api.vk.com being blocked by the captcha page's CSP
                  // connect-src or by missing CORS — which silently
                  // demotes us to the bot-prone Go redemption path.
                  send({type: 'status', text: 'replay FALLBACK: fetch threw (' + e + ') → raw token (likely CORS/CSP; Go will redeem, session switch risk)'});
                  send({type: 'success_token', token: token});
              });
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

        // Diagnostic: surface VK's verdict on every captchaNotRobot.*
        // response, even when there's no success_token. status:BOT here
        // means the solve was rejected IN the WebView (fingerprint /
        // dirty IP) — a different failure from "token captured but
        // redemption fell back". Without this the sheet just hangs to
        // the watchdog and the device log says nothing. Deduped so the
        // 250 ms pollers don't spam identical lines.
        let verdictLogged = {};
        function logVerdict(url, text) {
            try {
                if (!url || String(url).indexOf('captchaNotRobot') === -1) return;
                const after = String(url).split('captchaNotRobot.')[1] || '';
                const tag = after.split('?')[0].split('&')[0].split('/')[0];
                let json = null; try { json = JSON.parse(text); } catch (e) {}
                const r = (json && (json.response || json)) || {};
                let status = r.status || '';
                if (!status && json && json.error) status = 'error:' + (json.error.error_code || '?');
                const showType = r.show_captcha_type || r.show_type || '';
                const key = tag + '|' + status + '|' + showType;
                if (verdictLogged[key]) return;
                verdictLogged[key] = true;
                send({type: 'status', text: 'verdict ' + tag + ': status=' + (status || '?') + (showType ? (' show_type=' + showType) : '')});
            } catch (e) {}
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
                                logVerdict(url, text);
                                const t = maybeTokenFromText(text);
                                if (t) handleSuccessToken(t);
                            });
                        } catch (e) {}
                    }).catch(function() {});
                }
                return p;
            };
        }

        // XHR hook. Two hooks because VK sites use both:
        //   - Override of xhr.onreadystatechange catches code that
        //     sets the handler via property assignment.
        //   - addEventListener('load', ...) catches code that
        //     subscribes via the event listener API. Without this
        //     second hook, sites that prefer addEventListener (which
        //     is increasingly the norm for SPA frameworks) fire their
        //     handlers without our knowledge — we miss the response
        //     and the captcha sheet looks stuck even though VK has
        //     already issued the success_token.
        const origOpen = XMLHttpRequest.prototype.open;
        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function(method, url) {
            this.__cap_url = url;
            return origOpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function() {
            const xhr = this;
            // load-event hook (independent of any onreadystatechange).
            try {
                xhr.addEventListener('load', function() {
                    try {
                        if (xhr.__cap_url &&
                            String(xhr.__cap_url).indexOf('captchaNotRobot') !== -1) {
                            logVerdict(xhr.__cap_url, xhr.responseText);
                            const t = maybeTokenFromText(xhr.responseText);
                            if (t) handleSuccessToken(t);
                        }
                    } catch (e) {}
                });
            } catch (e) {}
            // onreadystatechange wrap (catches direct property assignment).
            const prev = xhr.onreadystatechange;
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4 && xhr.__cap_url &&
                    String(xhr.__cap_url).indexOf('captchaNotRobot') !== -1) {
                    logVerdict(xhr.__cap_url, xhr.responseText);
                    const t = maybeTokenFromText(xhr.responseText);
                    if (t) handleSuccessToken(t);
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
                    if (data.success_token) handleSuccessToken(data.success_token);
                    if (data.type === 'captcha_success' && data.token) {
                        handleSuccessToken(data.token);
                    }
                } else if (typeof data === 'string') {
                    const t = maybeTokenFromText(data);
                    if (t) handleSuccessToken(t);
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
                    if (t) handleSuccessToken(t);
                } catch (e) {}
            }
        }, 250);

        // Terminal-state polling. VK renders some failure pages
        // server-side as plain HTML — no XHR for our fetch/XHR hooks
        // to catch — so the only way to detect them is to inspect
        // the rendered DOM text. When found, fire 'terminal' so
        // native dismisses the sheet instead of leaving the user
        // staring at a dead end (the most common: "Attempt limit
        // reached", which the user has to currently kill the whole
        // app to escape).
        const terminalPatterns = [
            /attempt[\\s_]?limit[\\s_]?reached/i,
            /превышен[оа]?\\s*колич/i,
            /попыток.*исчерпан/i,
            /please\\s*try\\s*again\\s*later/i,
            /повторите\\s*попытку\\s*позже/i,
        ];
        let terminalFired = false;
        setInterval(function() {
            if (solved || terminalFired || !document.body) return;
            const txt = document.body.innerText || '';
            for (let i = 0; i < terminalPatterns.length; i++) {
                if (terminalPatterns[i].test(txt)) {
                    terminalFired = true;
                    send({type:'terminal', reason: txt.slice(0, 200)});
                    return;
                }
            }
        }, 750);

        send({type:'status', text:'Loaded captcha helper'});
    })();
    """
}
