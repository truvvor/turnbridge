import SwiftUI
import Combine

/// Polls captcha solve counters published by PacketTunnelProvider into
/// the App Group's shared UserDefaults. Surfaces two numbers in the UI:
///
///   "Direct"  — captchas solved from the user's mobile IP. Bounded
///               above by VK's per-IP rate-limit (~16 in practice).
///   "Tunnel"  — captchas solved from the WG server's egress IP, which
///               kicks in for sessions spawned AFTER WG handshake
///               completes through the bootstrap fleet. Independent
///               budget from direct, so e.g. N=30 can yield 16 direct
///               + 14 tunnel and all 30 sessions come up.
@MainActor
final class CaptchaStatsState: ObservableObject {
    @Published private(set) var direct: Int = 0
    @Published private(set) var tunnel: Int = 0
    @Published private(set) var remote: Int = 0
    @Published private(set) var directAttempts: Int = 0
    @Published private(set) var tunnelAttempts: Int = 0
    @Published private(set) var remoteAttempts: Int = 0
    @Published private(set) var directInFlight: Int = 0
    @Published private(set) var tunnelInFlight: Int = 0
    @Published private(set) var remoteInFlight: Int = 0
    @Published private(set) var sessionsReady: Int = 0
    @Published private(set) var sessionsTarget: Int = 0
    @Published private(set) var directSaturated: Bool = false
    @Published private(set) var tunnelSaturated: Bool = false

    private var timer: AnyCancellable?

    func start() {
        guard timer == nil else { return }
        refresh()
        timer = Timer.publish(every: 1, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.refresh() }
    }

    func stop() {
        timer?.cancel()
        timer = nil
        direct = 0
        tunnel = 0
        remote = 0
        directAttempts = 0
        tunnelAttempts = 0
        remoteAttempts = 0
        directInFlight = 0
        tunnelInFlight = 0
        remoteInFlight = 0
        sessionsReady = 0
        sessionsTarget = 0
        directSaturated = false
        tunnelSaturated = false
    }

    private func refresh() {
        guard let defaults = UserDefaults(suiteName: "group.com.truvvor.turnbridge") else {
            return
        }
        direct = defaults.integer(forKey: "captchaDirectCount")
        tunnel = defaults.integer(forKey: "captchaTunnelCount")
        remote = defaults.integer(forKey: "captchaRemoteCount")
        directAttempts = defaults.integer(forKey: "captchaDirectAttempts")
        tunnelAttempts = defaults.integer(forKey: "captchaTunnelAttempts")
        remoteAttempts = defaults.integer(forKey: "captchaRemoteAttempts")
        directInFlight = defaults.integer(forKey: "captchaDirectInFlight")
        tunnelInFlight = defaults.integer(forKey: "captchaTunnelInFlight")
        remoteInFlight = defaults.integer(forKey: "captchaRemoteInFlight")
        sessionsReady = defaults.integer(forKey: "sessionsReady")
        sessionsTarget = defaults.integer(forKey: "sessionsTarget")
        directSaturated = defaults.bool(forKey: "captchaDirectSaturated")
        tunnelSaturated = defaults.bool(forKey: "captchaTunnelSaturated")
    }
}

struct CaptchaStatsBadge: View {
    @ObservedObject var stats: CaptchaStatsState

    var body: some View {
        VStack(spacing: 6) {
            // Top row: Sessions ready/target — the single most useful
            // number while connecting (are we making progress?).
            HStack(spacing: 6) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                Text("\(stats.sessionsReady)/\(stats.sessionsTarget) sessions ready")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundColor(.primary)
            }

            Divider().padding(.horizontal, 4)

            // Bottom row: per-egress counters with in-flight indicators.
            // Three buckets — Direct (phone IP), Tunnel (WG egress
            // routed through utun), Server (captcha-service cluster).
            // The Server cell is the entire reason the total session
            // count exceeds Direct+Tunnel: server-side solves never
            // touch this phone's HTTP stack so they don't show up in
            // the other two buckets. With multi-link configured, the
            // Server cell is typically the largest of the three.
            HStack(spacing: 10) {
                cell(label: "Direct",
                     ok: stats.direct,
                     attempts: stats.directAttempts,
                     inFlight: stats.directInFlight,
                     saturated: stats.directSaturated,
                     accent: .blue)
                Divider().frame(height: 30)
                cell(label: "Tunnel",
                     ok: stats.tunnel,
                     attempts: stats.tunnelAttempts,
                     inFlight: stats.tunnelInFlight,
                     saturated: stats.tunnelSaturated,
                     accent: .green)
                Divider().frame(height: 30)
                cell(label: "Server",
                     ok: stats.remote,
                     attempts: stats.remoteAttempts,
                     inFlight: stats.remoteInFlight,
                     saturated: false,
                     accent: .purple)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
        )
    }

    private func cell(label: String, ok: Int, attempts: Int, inFlight: Int, saturated: Bool, accent: Color) -> some View {
        VStack(spacing: 1) {
            HStack(spacing: 4) {
                Text("\(ok)")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundColor(accent)
                Text("/\(attempts)")
                    .font(.system(size: 12, weight: .regular, design: .rounded))
                    .foregroundColor(.secondary)
                if inFlight > 0 {
                    Text("·\(inFlight)⟳")
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundColor(.orange)
                }
                if saturated {
                    Image(systemName: "exclamationmark.octagon.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.orange)
                }
            }
            Text(label)
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundColor(.secondary)
        }
    }
}
