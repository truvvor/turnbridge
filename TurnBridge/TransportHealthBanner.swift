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
            // Never alive yet → not necessarily stalled (still connecting).
            isStalled = false
            return
        }
        let now = Date()
        let lastDeadAfterAlive = (dead.map { $0 > alive } ?? false)
        let aliveStale = now.timeIntervalSince(alive) > 30
        isStalled = lastDeadAfterAlive || aliveStale
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
