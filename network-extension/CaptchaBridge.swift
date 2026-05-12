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
    }

    /// Persistent payload the extension writes when it needs the app to solve a captcha.
    struct PendingRequest: Codable {
        let requestId: String
        let redirectUri: String
        let createdAt: TimeInterval
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

        if let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) {
            let payload = CaptchaIPC.PendingRequest(
                requestId: requestId,
                redirectUri: redirectUri,
                createdAt: Date().timeIntervalSince1970
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
            let token = msg.successToken ?? ""
            msg.requestId.withCString { reqIDC in
                token.withCString { tokenC in
                    TurnBridgeSubmitManualCaptchaToken(reqIDC, tokenC)
                }
            }
            SharedLogger.info("CaptchaBridge: delivered success_token for reqID=\(msg.requestId)", source: .tunnel)

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
}
