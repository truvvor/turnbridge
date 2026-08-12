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
    static let quotaKey = "manualCaptchaQuota"
    private static let legacyBoolKey = "manualCaptcha"
    private static let suite = "group.com.truvvor.turnbridge"

    /// Per-StartProxy cap on how many captcha sheets the user is willing
    /// to solve in the WebView before everything else gets handed to the
    /// remote captcha-service. 0 ⇒ never solve on the device (defer
    /// immediately); 1 ⇒ bootstrap solve only, then offload (default
    /// since 1.3.35 after the field report that VK refuses to mint a
    /// second token on the same IP for ~1 min). Reads default to 1 when
    /// unset so upgrades from older builds don't silently regress.
    /// Mirrored to Go via TurnBridgeSetManualCaptchaQuota at tunnel
    /// start; updates during a live tunnel don't take effect until the
    /// next reconnect.
    static let quotaDefault: Int = 1
    static let quotaRange: ClosedRange<Int> = 0...10

    static var quota: Int {
        get {
            let d = UserDefaults(suiteName: suite)
            // object(forKey:) so we can distinguish "unset" from "0".
            if let raw = d?.object(forKey: quotaKey) as? Int {
                return max(quotaRange.lowerBound, min(quotaRange.upperBound, raw))
            }
            return quotaDefault
        }
        set {
            let clamped = max(quotaRange.lowerBound, min(quotaRange.upperBound, newValue))
            UserDefaults(suiteName: suite)?.set(clamped, forKey: quotaKey)
        }
    }

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
            // Keep the legacy bool in sync. Semantics: "the user wants
            // the in-tunnel routing to leave room for a Safari captcha
            // sheet to load" — true for BOTH forced (always) and
            // fallback (occasionally), false only for the pure-auto
            // mode. Older NetworkExtension builds that read just this
            // bool (the routing-scope path in PacketTunnelProvider)
            // then continue to disable the kill switch correctly.
            UserDefaults(suiteName: suite)?.set(newValue != .off, forKey: legacyBoolKey)
        }
    }

    /// Old API kept for callers that haven't moved to the enum yet.
    static var isEnabled: Bool {
        get { mode != .off }
        set { mode = newValue ? .forced : .off }
    }
}
