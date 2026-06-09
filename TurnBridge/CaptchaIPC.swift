import Foundation

/// IPC constants shared with the network extension's CaptchaBridge.swift.
/// Keep these strings in sync between the two targets.
enum CaptchaIPC {
    static let appGroupID = "group.com.truvvor.turnbridge"
    static let requestUserDefaultsKey = "captcha.pendingRequest"
    static let requestDarwinNotification = "com.truvvor.turnbridge.captcha.request"
    static let cancelDarwinNotification  = "com.truvvor.turnbridge.captcha.cancel"

    struct AppMessage: Codable {
        let type: String
        let requestId: String
        let successToken: String?
        let reason: String?
        /// New (1.3.24+): when the WebView replayed the failing VK API
        /// call inside its own browser session and got the full JSON
        /// response back, the app forwards that response here instead
        /// of a bare success_token. The extension routes it through
        /// TurnBridgeSubmitManualCaptchaResponse so getCreds skips its
        /// own retry — VK never sees a session switch between captcha
        /// solve and token redemption. Both fields are optional; the
        /// extension prefers responseJson when present.
        let responseJson: String?
    }

    struct PendingRequest: Codable {
        let requestId: String
        let redirectUri: String
        let createdAt: TimeInterval
        /// New (1.3.24+): if non-empty, the WebView should POST
        /// retryBody to retryUrl after extracting success_token, with
        /// the literal string "__TOKEN__" inside retryBody replaced by
        /// the actual token. The HTTP response is what the extension
        /// wants back via AppMessage.responseJson. Empty fields mean
        /// legacy "just send the token" path is fine.
        let retryUrl: String?
        let retryBody: String?
    }
}
