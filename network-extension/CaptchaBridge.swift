import Foundation
import WireGuardKitGo

/// Constants shared with the main app for the manual captcha IPC.
enum CaptchaIPC {
    static let appGroupID = "group.com.truvvor.turnbridge"
    static let requestUserDefaultsKey = "captcha.pendingRequest"
    static let requestDarwinNotification = "com.truvvor.turnbridge.captcha.request"
    static let cancelDarwinNotification  = "com.truvvor.turnbridge.captcha.cancel"

    /// JSON payload the app sends back via NETunnelProviderSession.sendProviderMessage.
    struct AppMessage: Codable {
        let type: String          // "captcha_answer" | "captcha_cancel"
        let requestId: String
        let successToken: String?
        let reason: String?
        /// New (1.3.24+): full JSON response when the WebView replayed
        /// the failing VK call inside its own session. See the
        /// matching field in TurnBridge/CaptchaIPC.swift.
        let responseJson: String?
        /// New (1.3.40+): VK cookies + Safari iOS UA harvested from the
        /// WebView's WKWebsiteDataStore. Forwarded to Go via
        /// TurnBridgeSetVKCookies and attached to subsequent /cred
        /// POSTs to the remote captcha-service.
        let cookiesJson: String?
        let userAgent: String?
    }

    /// Persistent payload the extension writes when it needs the app to solve a captcha.
    struct PendingRequest: Codable {
        let requestId: String
        let redirectUri: String
        let createdAt: TimeInterval
        /// New (1.3.24+): see TurnBridge/CaptchaIPC.swift.
        let retryUrl: String?
        let retryBody: String?
    }
}

/// Trampoline from cgo into Swift. Note: this runs on a Go goroutine /
/// arbitrary thread, so anything heavy must be dispatched off it.
private let manualCaptchaCCallback: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void = { reqIDPtr, uriPtr in
    guard let reqIDPtr = reqIDPtr, let uriPtr = uriPtr else { return }
    let reqID = String(cString: reqIDPtr)
    let uri   = String(cString: uriPtr)
    CaptchaBridge.publishRequest(requestId: reqID, redirectUri: uri)
}

enum CaptchaBridge {

    /// Registered once at tunnel start.
    static func install() {
        TurnBridgeSetManualCaptchaCallback(manualCaptchaCCallback)
    }

    /// Called from the cgo callback. Persists the request in the shared
    /// User Defaults so the app can pick it up, then fires a Darwin
    /// notification that wakes the app's observer.
    fileprivate static func publishRequest(requestId: String, redirectUri: String) {
        SharedLogger.info("Manual captcha requested (reqID=\(requestId))", source: .tunnel)

        // Pull the retry-request template from Go. When set, the
        // WebView will POST the body to this URL after extracting
        // success_token, INSIDE its own browser session — VK then
        // sees a single coherent session for both captcha solve and
        // the follow-up API call. Free the C string after parsing.
        var retryUrl: String?
        var retryBody: String?
        requestId.withCString { reqIDC in
            if let cStr = TurnBridgeGetManualCaptchaRetryRequest(reqIDC) {
                defer { free(UnsafeMutablePointer(mutating: cStr)) }
                let json = String(cString: cStr)
                if let data = json.data(using: .utf8),
                   let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
                    retryUrl = parsed["url"]
                    retryBody = parsed["body"]
                }
            }
        }

        if let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) {
            let payload = CaptchaIPC.PendingRequest(
                requestId: requestId,
                redirectUri: redirectUri,
                createdAt: Date().timeIntervalSince1970,
                retryUrl: retryUrl,
                retryBody: retryBody
            )
            if let data = try? JSONEncoder().encode(payload) {
                defaults.set(data, forKey: CaptchaIPC.requestUserDefaultsKey)
            }
        }

        let name = CFNotificationName(CaptchaIPC.requestDarwinNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name, nil, nil, true
        )
    }

    /// Called from NEPacketTunnelProvider.handleAppMessage when the app
    /// delivers a result (token or cancel) for an outstanding request.
    static func handleAppMessage(_ data: Data) -> Data? {
        guard let msg = try? JSONDecoder().decode(CaptchaIPC.AppMessage.self, from: data) else {
            SharedLogger.warning("CaptchaBridge: ignoring unparseable app message (\(data.count) bytes)", source: .tunnel)
            return nil
        }

        switch msg.type {
        case "captcha_answer":
            // Forward the harvested VK cookies + UA to Go BEFORE the
            // token/response is delivered. getCredsRemote pulls these
            // from atomic storage on every /cred POST, so wiring them
            // up first means the remote captcha-service has them
            // available the next time it solves. Empty cookies are
            // still set (resets any stale state from a previous solve
            // session).
            let cookiesJson = msg.cookiesJson ?? ""
            let userAgent = msg.userAgent ?? ""
            cookiesJson.withCString { cookiesC in
                userAgent.withCString { uaC in
                    TurnBridgeSetVKCookies(cookiesC, uaC)
                }
            }
            if !cookiesJson.isEmpty {
                SharedLogger.info("CaptchaBridge: forwarded VK cookies+UA to Go (\(cookiesJson.count) bytes JSON)", source: .tunnel)
            }
            // Prefer the full JSON response (the WebView did the retry
            // itself, so getCreds can skip its own redemption call).
            // Fall through to the legacy token-only path when the
            // WebView fell back to just extracting success_token
            // (network error during the in-WebView fetch, retryUrl
            // wasn't provided, etc).
            if let resp = msg.responseJson, !resp.isEmpty {
                msg.requestId.withCString { reqIDC in
                    resp.withCString { respC in
                        TurnBridgeSubmitManualCaptchaResponse(reqIDC, respC)
                    }
                }
                SharedLogger.info("CaptchaBridge: delivered full response (\(resp.count) bytes) for reqID=\(msg.requestId)", source: .tunnel)
            } else {
                let token = msg.successToken ?? ""
                msg.requestId.withCString { reqIDC in
                    token.withCString { tokenC in
                        TurnBridgeSubmitManualCaptchaToken(reqIDC, tokenC)
                    }
                }
                SharedLogger.info("CaptchaBridge: delivered success_token for reqID=\(msg.requestId)", source: .tunnel)
            }

        case "captcha_cancel":
            let reason = msg.reason ?? "user cancelled"
            msg.requestId.withCString { reqIDC in
                reason.withCString { reasonC in
                    TurnBridgeCancelManualCaptcha(reqIDC, reasonC)
                }
            }
            SharedLogger.info("CaptchaBridge: cancelled reqID=\(msg.requestId) (\(reason))", source: .tunnel)

        default:
            return nil
        }

        // Clear pending request from shared UserDefaults so the app doesn't
        // re-prompt on next launch.
        if let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) {
            defaults.removeObject(forKey: CaptchaIPC.requestUserDefaultsKey)
        }
        return Data("ok".utf8)
    }

    /// Called from stopTunnel: the Go side is going away, so any
    /// pending captcha prompt can never be answered. Clear the
    /// published request and tell the app to drop its sheet --
    /// otherwise the user keeps solving captchas into a dead session
    /// (1.3.27 field log: tunnel died with stop reason 9 four seconds
    /// after the first sheet appeared; the sheet stayed up for 20+
    /// minutes while the user kept solving into the void).
    static func teardown() {
        if let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) {
            defaults.removeObject(forKey: CaptchaIPC.requestUserDefaultsKey)
        }
        let name = CFNotificationName(CaptchaIPC.cancelDarwinNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name, nil, nil, true
        )
    }
}
