import Foundation

/// Persistent flag, shared with the network extension via the App Group,
/// that controls whether the VK captcha is solved by the auto solver or by
/// showing the challenge in a WKWebView for the user to solve.
enum ManualCaptchaSetting {
    static let key = "manualCaptcha"
    private static let suite = "group.com.truvvor.turnbridge"

    static var isEnabled: Bool {
        get { UserDefaults(suiteName: suite)?.bool(forKey: key) ?? false }
        set { UserDefaults(suiteName: suite)?.set(newValue, forKey: key) }
    }
}
