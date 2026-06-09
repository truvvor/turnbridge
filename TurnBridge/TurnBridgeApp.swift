//
//  Created by nullcstring.
//

import SwiftUI
import NetworkExtension

@main
struct TurnBridge: App {
    @StateObject private var captchaManager = CaptchaManager.shared

    var body: some Scene {
        WindowGroup {
            ContentView(app: self)
                .onAppear { captchaManager.start() }
                .sheet(item: Binding(
                    get: { captchaManager.pending.map(IdentifiedCaptcha.init) },
                    set: { newValue in
                        if newValue == nil {
                            Task { await captchaManager.cancel(reason: "sheet dismissed") }
                        }
                    }
                )) { identified in
                    CaptchaWebView(redirectUri: identified.request.redirectUri,
                                   retryUrl: identified.request.retryUrl,
                                   retryBody: identified.request.retryBody,
                                   manager: captchaManager)
                        .interactiveDismissDisabled()
                }
        }
    }

    private struct IdentifiedCaptcha: Identifiable {
        let request: CaptchaIPC.PendingRequest
        var id: String { request.requestId }
    }
    
    func turnOnTunnel(vkLink: String, peerAddr: String, listenAddr: String, nValue: Int, useUDP: Bool, streamAggregation: Bool, wrapKey: String, wgQuickConfig: String, completionHandler: @escaping (Bool) -> Void) {
        // Strip whitespace (including Unicode thin space U+2009 that
        // sneaks in from web copy-paste). Field log 1.3.14 showed the
        // proxy aborting at startup with `port "56010 " invalid`
        // — the trailing thin space lived inside the saved profile.
        let peerAddr = peerAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        let listenAddr = listenAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        SharedLogger.info("Connecting... peer=\(peerAddr), listen=\(listenAddr), n=\(nValue), udp=\(useUDP), streamAgg=\(streamAggregation)")

        NETunnelProviderManager.loadAllFromPreferences { tunnelManagersInSettings, error in
            if let error = error {
                NSLog("Error (loadAllFromPreferences): \(error)")
                SharedLogger.error("Failed to load tunnel preferences: \(error.localizedDescription)")
                completionHandler(false)
                return
            }

            let preExistingTunnelManager = tunnelManagersInSettings?.first
            let tunnelManager = preExistingTunnelManager ?? NETunnelProviderManager()
            SharedLogger.debug("Using \(preExistingTunnelManager != nil ? "existing" : "new") tunnel manager")

            let protocolConfiguration = NETunnelProviderProtocol()
            let currentAppBundleId = Bundle.main.bundleIdentifier ?? "com.truvvor.turnbridge"
            protocolConfiguration.providerBundleIdentifier = "\(currentAppBundleId).network-extension"

            let cleanIP = peerAddr.components(separatedBy: ":").first ?? peerAddr
            protocolConfiguration.serverAddress = cleanIP

            protocolConfiguration.providerConfiguration = [
                "wgQuickConfig": wgQuickConfig,
                "vkLink": vkLink,
                "peerAddr": peerAddr,
                "listenAddr": listenAddr,
                "nValue": nValue,
                "useUDP": useUDP,
                "streamAggregation": streamAggregation,
                "wrapKey": wrapKey
            ]

            let defaults = UserDefaults.standard
            let excludeAPNs = defaults.object(forKey: "excludeAPNs") as? Bool ?? false
            let excludeCellular = defaults.object(forKey: "excludeCellularServices") as? Bool ?? false
            let excludeLAN = defaults.object(forKey: "excludeLocalNetworks") as? Bool ?? true

            // includeAllNetworks acts as a kill-switch — it installs
            // the tunnel's default route BEFORE the tunnel is up, so
            // outbound traffic in the Connecting phase has nowhere
            // to go and the kernel returns "no route to host" for
            // EVERY destination (including 1.1.1.1 / hardcoded VK
            // IPs / DoH endpoints).
            //
            // That's fatal for both captcha modes:
            //   manual — the in-app WebView can't load id.vk.com
            //   auto   — the in-extension captcha solver can't reach
            //            login.vk.com / api.vk.com / 1.1.1.1
            //
            // So we turn the kill-switch off in both modes. The user
            // loses fail-closed behaviour during a mid-session
            // tunnel break, but in exchange the tunnel can actually
            // come up. Real kill-switch parity would require
            // changing includeAllNetworks DYNAMICALLY after WG
            // handshake — iOS doesn't support that, the flag is
            // saveToPreferences-time only.
            let manualCaptcha = ManualCaptchaSetting.isEnabled
            protocolConfiguration.includeAllNetworks = false
            protocolConfiguration.excludeAPNs = excludeAPNs
            protocolConfiguration.excludeCellularServices = excludeCellular
            protocolConfiguration.excludeLocalNetworks = excludeLAN

            SharedLogger.debug("Routing: includeAll=false (manualCaptcha=\(manualCaptcha)), LAN=\(excludeLAN), APNs=\(excludeAPNs), Cellular=\(excludeCellular)")

            tunnelManager.protocolConfiguration = protocolConfiguration
            tunnelManager.isEnabled = true
            tunnelManager.saveToPreferences { error in
                if let error = error {
                    NSLog("Error (saveToPreferences): \(error)")
                    SharedLogger.error("Failed to save tunnel preferences: \(error.localizedDescription)")
                    completionHandler(false)
                    return
                }
                tunnelManager.loadFromPreferences { error in
                    if let error = error {
                        NSLog("Error (loadFromPreferences): \(error)")
                        SharedLogger.error("Failed to reload tunnel preferences: \(error.localizedDescription)")
                        completionHandler(false)
                        return
                    }

                    guard let session = tunnelManager.connection as? NETunnelProviderSession else {
                        SharedLogger.error("tunnelManager.connection is not NETunnelProviderSession")
                        completionHandler(false)
                        return
                    }
                    do {
                        SharedLogger.info("Starting tunnel session...")
                        try session.startTunnel()
                        completionHandler(true)
                    } catch {
                        NSLog("Error (startTunnel): \(error)")
                        SharedLogger.error("Failed to start tunnel: \(error.localizedDescription)")
                        completionHandler(false)
                    }
                }
            }
        }
    }

    func turnOffTunnel() {
        SharedLogger.info("Disconnecting...")
        NETunnelProviderManager.loadAllFromPreferences { tunnelManagersInSettings, error in
            if let error = error {
                NSLog("Error (loadAllFromPreferences): \(error)")
                SharedLogger.error("Failed to load tunnel preferences: \(error.localizedDescription)")
                return
            }
            if let tunnelManager = tunnelManagersInSettings?.first {
                guard let session = tunnelManager.connection as? NETunnelProviderSession else {
                    SharedLogger.error("tunnelManager.connection is not NETunnelProviderSession")
                    return
                }
                switch session.status {
                case .connected, .connecting, .reasserting:
                    SharedLogger.info("Stopping tunnel session...")
                    session.stopTunnel()
                default:
                    SharedLogger.warning("Tunnel not in active state, nothing to stop")
                }
            } else {
                SharedLogger.warning("No tunnel manager found")
            }
        }
    }
}
