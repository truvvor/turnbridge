import Foundation

/// Settings, shared with the network extension via the App Group, that
/// point the in-tunnel captcha solver at an optional external server.
/// When both URL and API key are non-empty, the Go bridge will offload
/// getCreds to the server after the first few local solves succeed —
/// letting us pull additional VK captcha rate-limit budget from an IP
/// that isn't the user's mobile IP.
///
/// See captcha-service/ in the repo for the server, and
/// remote_creds.go for the client-side wiring.
enum RemoteCaptchaSetting {
    static let urlKey = "remoteCaptchaServiceURL"
    static let apiKeyKey = "remoteCaptchaServiceAPIKey"
    private static let suite = "group.com.truvvor.turnbridge"

    static var url: String {
        get { UserDefaults(suiteName: suite)?.string(forKey: urlKey) ?? "" }
        set { UserDefaults(suiteName: suite)?.set(newValue, forKey: urlKey) }
    }

    static var apiKey: String {
        get { UserDefaults(suiteName: suite)?.string(forKey: apiKeyKey) ?? "" }
        set { UserDefaults(suiteName: suite)?.set(newValue, forKey: apiKeyKey) }
    }

    static var isConfigured: Bool {
        !url.trimmingCharacters(in: .whitespaces).isEmpty &&
            !apiKey.trimmingCharacters(in: .whitespaces).isEmpty
    }
}
