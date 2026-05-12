//
//  Created by nullcstring.
//

import NetworkExtension
import Network
import WireGuardKit
import WireGuardKitGo
import os

let sharedLogger = Logger(subsystem: "com.truvvor.turnbridge.network-extension", category: "wgtunnel")

enum PacketTunnelProviderError: String, Error {
    case invalidProtocolConfiguration
    case cantParseWgQuickConfig
}

private let goProxyCLoggerCallback: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?) -> Void = { context, level, messageCStr in
    guard let cStr = messageCStr else { return }
    let message = String(cString: cStr).trimmingCharacters(in: .newlines)

    TransportHealthMonitor.observe(message)

    if level == 1 {
        sharedLogger.error("[TP]: \(message, privacy: .public)")
        SharedLogger.error(message, source: .tunnel)
    } else {
        sharedLogger.log("[TP]: \(message, privacy: .public)")
        SharedLogger.info(message, source: .tunnel)
    }
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    private lazy var adapter: WireGuardAdapter = {
        return WireGuardAdapter(with: self) { [weak self] _, message in
            sharedLogger.log("[WG]: \(message, privacy: .public)")
            SharedLogger.info(message, source: .wireguard)
        }
    }()

    private var pathMonitor: NWPathMonitor?
    private var lastPathStatus: NWPath.Status?
    private var lastPathInterfaceLabel: String?
    private var lastTransportRestartAt = Date.distantPast

    /// Tear down the current TURN/DTLS cycle and let the proxy spin up
    /// fresh inner connections, reusing cached credentials when possible
    /// (so no captcha re-prompt). Debounced to 5s to avoid stampedes when
    /// several signals fire at once (wake + network change).
    private func restartTransport(reason: String) {
        if Date().timeIntervalSince(lastTransportRestartAt) < 5 {
            return
        }
        lastTransportRestartAt = Date()
        SharedLogger.info("Transport restart: \(reason)", source: .tunnel)
        RestartProxy()
    }

    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        sharedLogger.log("=== Starting tunnel ===")
        SharedLogger.info("Starting tunnel", source: .tunnel)

        guard let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration else {
            sharedLogger.error("Invalid provider configuration")
            SharedLogger.error("Invalid provider configuration", source: .tunnel)
            completionHandler(PacketTunnelProviderError.invalidProtocolConfiguration)
            return
        }

        guard let wgQuickConfig = providerConfiguration["wgQuickConfig"] as? String else {
            sharedLogger.error("wgQuickConfig missing from provider configuration")
            SharedLogger.error("WireGuard config missing from provider configuration", source: .wireguard)
            completionHandler(PacketTunnelProviderError.cantParseWgQuickConfig)
            return
        }

        let tunnelConfiguration: TunnelConfiguration
        do {
            tunnelConfiguration = try TunnelConfiguration(fromWgQuickConfig: wgQuickConfig)
        } catch {
            sharedLogger.error("wg-quick config parse error: \(error.localizedDescription)")
            SharedLogger.error("Failed to parse WireGuard config: \(error.localizedDescription)", source: .wireguard)
            completionHandler(PacketTunnelProviderError.cantParseWgQuickConfig)
            return
        }

        guard let vkLink = providerConfiguration["vkLink"] as? String,
              let peerAddr = providerConfiguration["peerAddr"] as? String,
              let listenAddr = providerConfiguration["listenAddr"] as? String,
              let nValueInt = providerConfiguration["nValue"] as? Int else {
            sharedLogger.error("Missing proxy parameters in configuration")
            SharedLogger.error("Missing proxy parameters in configuration", source: .tunnel)
            completionHandler(PacketTunnelProviderError.invalidProtocolConfiguration)
            return
        }
        let nValue = Int32(nValueInt)

        SharedLogger.info("Peer: \(peerAddr), Listen: \(listenAddr), N: \(nValue)", source: .tunnel)
        SharedLogger.info("Starting TURN proxy...", source: .tunnel)

        ProxySetLogger(nil, goProxyCLoggerCallback)
        CaptchaBridge.install()

        let manualCaptchaEnabled = UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .bool(forKey: "manualCaptcha") ?? false
        TurnBridgeSetManualCaptchaMode(manualCaptchaEnabled ? 1 : 0)
        SharedLogger.info("Captcha mode: \(manualCaptchaEnabled ? "manual (browser sheet)" : "auto (in-tunnel solver)")", source: .tunnel)

        // Manual captcha is human-driven, so give the user time to actually
        // solve the challenge before declaring DTLS dead. Auto mode keeps
        // the original 12s budget — if the solver can't bash through in
        // that window something else is wrong and we want fast failure.
        let dtlsReadyTimeoutMs: Int32 = manualCaptchaEnabled ? 300_000 : 12_000

        DispatchQueue.global(qos: .userInteractive).async {
            StartProxy(vkLink, peerAddr, listenAddr, nValue)
        }

        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            let ready = ProxyWaitReady(dtlsReadyTimeoutMs)
            guard let self = self else { return }

            if ready == 0 {
                sharedLogger.error("DTLS connection timeout!")
                SharedLogger.error("DTLS connection timeout (\(dtlsReadyTimeoutMs / 1000)s)", source: .tunnel)
                completionHandler(PacketTunnelProviderError.invalidProtocolConfiguration)
                return
            }

            SharedLogger.info("DTLS ready, starting WireGuard adapter...", source: .tunnel)
            self.adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
                guard let self = self else { return }
                if let adapterError = adapterError {
                    sharedLogger.error("WireGuard adapter error: \(adapterError.localizedDescription)")
                    SharedLogger.error("WireGuard adapter failed: \(adapterError.localizedDescription)", source: .wireguard)
                } else {
                    let interfaceName = self.adapter.interfaceName ?? "unknown"
                    sharedLogger.log("Tunnel interface is \(interfaceName)")
                    SharedLogger.info("Tunnel up on interface \(interfaceName)", source: .wireguard)
                    self.startNetworkMonitoring()
                }
                completionHandler(adapterError)
            }
        }
    }

    private func describe(_ status: NWPath.Status) -> String {
        switch status {
        case .satisfied:          return "satisfied"
        case .unsatisfied:        return "unsatisfied"
        case .requiresConnection: return "requiresConnection"
        @unknown default:         return "unknown"
        }
    }

    private func startNetworkMonitoring() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let descriptors: [String] = [
                path.usesInterfaceType(.wifi) ? "wifi" : nil,
                path.usesInterfaceType(.cellular) ? "cellular" : nil,
                path.usesInterfaceType(.wiredEthernet) ? "ethernet" : nil
            ].compactMap { $0 }
            let label = descriptors.isEmpty ? "unknown" : descriptors.joined(separator: "+")
            let prevStatus = self.lastPathStatus
            let prevLabel = self.lastPathInterfaceLabel ?? "?"
            self.lastPathStatus = path.status
            self.lastPathInterfaceLabel = label

            let curStatusStr = self.describe(path.status)

            // Cellular flaps the path on PDP-context refreshes / tower
            // handovers — same interface kind, status stays .satisfied, but
            // an event fires every ~20s. Restarting on each one tears down
            // a working DTLS for no reason. We only restart when something
            // observable actually changed: interface kind flipped (wifi
            // <-> cellular), or the path was previously unavailable and is
            // now satisfied. Pure-noise events are dropped silently; the
            // watchdog still catches real DTLS death.
            guard let prevStatus = prevStatus else {
                SharedLogger.info("NWPath initial: status=\(curStatusStr), via=\(label)", source: .tunnel)
                return
            }
            let prevStatusStr = self.describe(prevStatus)
            let interfaceFlipped = prevLabel != label
            let recovered = prevStatus != NWPath.Status.satisfied && path.status == NWPath.Status.satisfied
            if !interfaceFlipped && !recovered {
                return
            }
            SharedLogger.info("NWPath change: \(prevLabel)/\(prevStatusStr) -> \(label)/\(curStatusStr)", source: .tunnel)
            if path.status == NWPath.Status.satisfied {
                let reason = interfaceFlipped
                    ? "interface flip \(prevLabel) -> \(label)"
                    : "path recovered to \(label)"
                self.restartTransport(reason: reason)
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = monitor
        SharedLogger.debug("NWPathMonitor started", source: .tunnel)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        sharedLogger.log("Stopping tunnel")
        SharedLogger.info("Stopping tunnel (reason: \(reason.rawValue))", source: .tunnel)

        pathMonitor?.cancel()
        pathMonitor = nil
        lastPathStatus = nil
        lastPathInterfaceLabel = nil

        StopProxy()
        SharedLogger.info("TURN proxy stopped", source: .tunnel)
        TransportHealthMonitor.reset()

        adapter.stop { [weak self] error in
            guard self != nil else { return }
            if let error = error {
                sharedLogger.error("Failed to stop WireGuard adapter: \(error.localizedDescription)")
                SharedLogger.error("WireGuard adapter stop failed: \(error.localizedDescription)", source: .wireguard)
            } else {
                SharedLogger.info("WireGuard adapter stopped", source: .wireguard)
            }
            SharedLogger.info("Tunnel stopped", source: .tunnel)
            completionHandler()

            #if os(macOS)
            // HACK: We have to kill the tunnel process ourselves because of a macOS bug
            exit(0)
            #endif
        }
    }
    

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let response = CaptchaBridge.handleAppMessage(messageData) ?? messageData
        completionHandler?(response)
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        SharedLogger.debug("Tunnel sleep requested", source: .tunnel)
        completionHandler()
    }

    override func wake() {
        SharedLogger.info("Tunnel wake — restarting transport", source: .tunnel)
        restartTransport(reason: "device wake")
    }
}
