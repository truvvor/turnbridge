import SwiftUI
import Combine

/// Polls the App Group flags written by TransportHealthMonitor in the
/// extension. When the VPN status is `.connected` but the underlying
/// DTLS/TURN cycle has been silent / failed recently, surface a banner
/// so the user knows iOS lies about the connection being healthy.
@MainActor
final class TransportHealthState: ObservableObject {
    @Published private(set) var isStalled = false

    private var timer: AnyCancellable?

    func start() {
        guard timer == nil else { return }
        refresh()
        timer = Timer.publish(every: 5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.refresh() }
    }

    func stop() {
        timer?.cancel()
        timer = nil
        isStalled = false
    }

    private func refresh() {
        guard let defaults = UserDefaults(suiteName: "group.com.truvvor.turnbridge") else {
            isStalled = false
            return
        }
        let alive = defaults.object(forKey: "transport.lastAliveAt") as? Date
        let dead  = defaults.object(forKey: "transport.lastDeadAt")  as? Date
        guard let alive = alive else {
            // Never alive yet → still connecting, not stalled.
            isStalled = false
            return
        }
        let now = Date()

        // Every iOS sleep → wake cycle tears down the DTLS+TURN
        // sessions and immediately re-establishes new ones. That
        // teardown emits a burst of `Failed:` / `Closed DTLS
        // connection` log lines (which TransportHealthMonitor maps to
        // markDead()), and then ~1–3 seconds later the new session
        // emits `Established DTLS connection` → markAlive(). If we
        // flip the banner the moment dead > alive, the 5-second poller
        // catches that 1–3s window and shows the banner regularly
        // even though everything is fine.
        //
        // So allow a 10 s grace period after the most recent dead
        // event for a fresh alive to come in. Only after that grace
        // expires without a new alive do we call the transport
        // stalled.
        let aliveStale = now.timeIntervalSince(alive) > 30
        let deadAfterAlive: Bool = {
            guard let dead = dead, dead > alive else { return false }
            return now.timeIntervalSince(dead) > 10
        }()
        isStalled = aliveStale || deadAfterAlive
    }
}

struct TransportHealthBanner: View {
    let isStalled: Bool

    var body: some View {
        if isStalled {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                Text("Connection unstable — TURN tunnel reconnecting")
                    .font(.footnote)
                Spacer()
            }
            .foregroundColor(.white)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.orange)
            .cornerRadius(10)
            .padding(.horizontal, 16)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }
}
