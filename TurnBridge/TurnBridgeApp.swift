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
                                   manager: captchaManager)
                        .interactiveDismissDisabled()
                }
        }
    }

    private struct IdentifiedCaptcha: Identifiable {
        let request: CaptchaIPC.PendingRequest
        var id: String { request.requestId }
    }
    
    func turnOnTunnel(vkLink: String, peerAddr: String, listenAddr: String, nValue: Int, wgQuickConfig: String, completionHandler: @escaping (Bool) -> Void) {
        SharedLogger.info("Connecting... peer=\(peerAddr), listen=\(listenAddr), n=\(nValue)")

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
                "nValue": nValue
            ]

            let defaults = UserDefaults.standard
            let excludeAPNs = defaults.object(forKey: "excludeAPNs") as? Bool ?? false
            let excludeCellular = defaults.object(forKey: "excludeCellularServices") as? Bool ?? false
            let excludeLAN = defaults.object(forKey: "excludeLocalNetworks") as? Bool ?? true

            // Manual captcha mode needs the captcha web view in the main app
            // to actually reach the internet *while the tunnel is still
            // coming up*. iOS enforces includeAllNetworks strictly during the
            // Connecting phase too, so leaving it on means the WebView can
            // never load id.vk.ru to ask the user. Trade kill-switch for
            // captcha solvability when this mode is on.
            let manualCaptcha = ManualCaptchaSetting.isEnabled
            protocolConfiguration.includeAllNetworks = !manualCaptcha
            protocolConfiguration.excludeAPNs = excludeAPNs
            protocolConfiguration.excludeCellularServices = excludeCellular
            protocolConfiguration.excludeLocalNetworks = excludeLAN

            SharedLogger.debug("Routing: includeAll=\(!manualCaptcha) (manualCaptcha=\(manualCaptcha)), LAN=\(excludeLAN), APNs=\(excludeAPNs), Cellular=\(excludeCellular)")

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
