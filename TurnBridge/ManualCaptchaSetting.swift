import Foundation

/// Persistent flag, shared with the network extension via the App Group,
/// that controls how the VK captcha pipeline behaves when an identity
/// challenge fires. Mirrors the Go-side `manualCaptchaMode*` constants in
/// captcha_manual.go — keep them in lockstep.
enum CaptchaMode: Int {
    /// Auto solver only. On auto-failure the proxy recycles a previously-
    /// acquired identity. Zero prompts to the user, occasional reused
    /// identities in the pool.
    case off = 0
    /// Every captcha is handed to the iOS UI immediately. Auto solver is
    /// never tried. Brutal UX at N=60 (one prompt per identity) but
    /// guarantees a fresh identity for every session.
    case forced = 1
    /// Auto solver runs first; cluster /cred runs second; only if BOTH
    /// fail does the UI prompt fire. Realistically ~15-20% of identities
    /// at N=60 will fall through to a prompt — bearable tradeoff for
    /// avoiding identity recycling entirely.
    case fallback = 2
}

enum ManualCaptchaSetting {
    static let key = "manualCaptchaMode"
    private static let legacyBoolKey = "manualCaptcha"
    private static let suite = "group.com.truvvor.turnbridge"

    static var mode: CaptchaMode {
        get {
            let d = UserDefaults(suiteName: suite)
            // New int-valued key takes precedence.
            if let raw = d?.object(forKey: key) as? Int, let m = CaptchaMode(rawValue: raw) {
                return m
            }
            // Backwards-compat: the old bool-valued key. True == forced.
            if d?.bool(forKey: legacyBoolKey) == true {
                return .forced
            }
            return .off
        }
        set {
            UserDefaults(suiteName: suite)?.set(newValue.rawValue, forKey: key)
            // Keep the legacy bool in sync so older NetworkExtension
            // builds (if any are still around) still see the
            // forced-vs-off distinction.
            UserDefaults(suiteName: suite)?.set(newValue == .forced, forKey: legacyBoolKey)
        }
    }

    /// Old API kept for callers that haven't moved to the enum yet.
    static var isEnabled: Bool {
        get { mode != .off }
        set { mode = newValue ? .forced : .off }
    }
}
