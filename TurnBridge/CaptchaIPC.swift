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
    }

    struct PendingRequest: Codable {
        let requestId: String
        let redirectUri: String
        let createdAt: TimeInterval
    }
}
