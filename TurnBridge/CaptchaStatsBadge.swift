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
        directSaturated = false
        tunnelSaturated = false
    }

    private func refresh() {
        guard let defaults = UserDefaults(suiteName: "group.com.truvvor.turnbridge") else {
            return
        }
        direct = defaults.integer(forKey: "captchaDirectCount")
        tunnel = defaults.integer(forKey: "captchaTunnelCount")
        directSaturated = defaults.bool(forKey: "captchaDirectSaturated")
        tunnelSaturated = defaults.bool(forKey: "captchaTunnelSaturated")
    }
}

struct CaptchaStatsBadge: View {
    @ObservedObject var stats: CaptchaStatsState

    var body: some View {
        // Always visible during connecting/connected: zeros give the
        // user feedback that the counters exist and that they haven't
        // yet incremented this connect cycle (often the case when
        // pooled creds are reused without a fresh captcha solve).
        HStack(spacing: 14) {
            cell(label: "Direct",
                 value: stats.direct,
                 saturated: stats.directSaturated,
                 accent: .blue)
            Divider()
                .frame(height: 22)
            cell(label: "Tunnel",
                 value: stats.tunnel,
                 saturated: stats.tunnelSaturated,
                 accent: .green)
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

    private func cell(label: String, value: Int, saturated: Bool, accent: Color) -> some View {
        VStack(spacing: 1) {
            HStack(spacing: 4) {
                Text("\(value)")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundColor(accent)
                if saturated {
                    // Saturation = VK started returning ERROR_LIMIT for
                    // this egress, so the pool is effectively closed
                    // until VK's window resets.
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
