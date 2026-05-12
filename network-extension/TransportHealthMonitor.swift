import Foundation

/// Watches the Go proxy log stream to maintain a "transport-alive" flag in
/// the App Group's UserDefaults. The main app reads this to surface a
/// "Connection unstable" banner when iOS still says NEVPNStatus=.connected
/// but the underlying DTLS/TURN tunnel hasn't seen any traffic in a while.
enum TransportHealthMonitor {
    static let lastAliveKey = "transport.lastAliveAt"
    static let lastDeadKey  = "transport.lastDeadAt"

    private static let appGroupID = "group.com.truvvor.turnbridge"

    private static let aliveSignals: [String] = [
        "Established DTLS connection",
        "Proxy started on",
        "Successfully registered User Identity"
    ]

    private static let deadSignals: [String] = [
        "Watchdog:",
        "Failed: ",
        "Closed DTLS connection",
        "DTLS connection timeout",
        "Proxy gracefully stopped",
        "RestartProxy:"
    ]

    /// Inspect a single log line emitted from the Go proxy.
    static func observe(_ message: String) {
        for s in aliveSignals where message.contains(s) {
            markAlive()
            return
        }
        for s in deadSignals where message.contains(s) {
            markDead()
            return
        }
    }

    static func markAlive() {
        UserDefaults(suiteName: appGroupID)?.set(Date(), forKey: lastAliveKey)
    }

    static func markDead() {
        UserDefaults(suiteName: appGroupID)?.set(Date(), forKey: lastDeadKey)
    }

    static func reset() {
        let defaults = UserDefaults(suiteName: appGroupID)
        defaults?.removeObject(forKey: lastAliveKey)
        defaults?.removeObject(forKey: lastDeadKey)
    }
}
