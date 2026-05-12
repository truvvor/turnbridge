//
//  Created by nullcstring.
//

import NetworkExtension
import WireGuardKit
import WireGuardKitGo
import os

let sharedLogger = Logger(subsystem: "com.netlab.TurnBridge.network-extension", category: "wgtunnel")

enum PacketTunnelProviderError: String, Error {
    case invalidProtocolConfiguration
    case cantParseWgQuickConfig
}

private let goProxyCLoggerCallback: @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafePointer<CChar>?) -> Void = { context, level, messageCStr in
    guard let cStr = messageCStr else { return }
    let message = String(cString: cStr).trimmingCharacters(in: .newlines)

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
        // Default true for backward-compat with profiles saved before this field existed.
        let useUDP = (providerConfiguration["useUDP"] as? Bool) ?? true
        let udpFlag: Int32 = useUDP ? 1 : 0

        SharedLogger.info("Peer: \(peerAddr), Listen: \(listenAddr), N: \(nValue), UDP: \(useUDP)", source: .tunnel)
        SharedLogger.info("Starting TURN proxy...", source: .tunnel)

        ProxySetLogger(nil, goProxyCLoggerCallback)

        DispatchQueue.global(qos: .userInteractive).async {
            StartProxy(vkLink, peerAddr, listenAddr, nValue, udpFlag)
        }

        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            let ready = ProxyWaitReady(12000)
            guard let self = self else { return }

            if ready == 0 {
                sharedLogger.error("DTLS connection timeout!")
                SharedLogger.error("DTLS connection timeout (12s)", source: .tunnel)
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
                }
                completionHandler(adapterError)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        sharedLogger.log("Stopping tunnel")
        SharedLogger.info("Stopping tunnel (reason: \(reason.rawValue))", source: .tunnel)

        StopProxy()
        SharedLogger.info("TURN proxy stopped", source: .tunnel)

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
        if let handler = completionHandler {
            handler(messageData)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // iOS is about to suspend us. Don't tear anything down (iOS will
        // resume us via wake()), but record the moment so wake() can decide
        // whether the gap was long enough to need a fresh TURN allocation.
        sharedLogger.log("System sleep — flagging proxy for reconnect on wake")
        SharedLogger.info("System sleep — flagging proxy for reconnect on wake", source: .tunnel)
        Self.lastSleepAt = Date()
        completionHandler()
    }

    override func wake() {
        // After a sleep iOS thaws our Go runtime, but the TURN allocation
        // and DTLS session held by the embedded vk-turn-proxy client are
        // almost certainly stale — VK TURN drops idle channels, NAT
        // mappings on the cellular side have expired, and pion/dtls
        // sequence numbers can be outside the replay window. Force a
        // clean reconnect before WireGuard starts pumping packets through
        // zombie sockets.
        let gap = Self.lastSleepAt.map { Date().timeIntervalSince($0) } ?? 0
        sharedLogger.log("System wake — gap=\(String(format: "%.1f", gap))s, forcing TURN/DTLS reconnect")
        SharedLogger.info("System wake — gap=\(String(format: "%.1f", gap))s, forcing TURN/DTLS reconnect", source: .tunnel)
        ProxyForceReconnect()
        Self.lastSleepAt = nil
    }

    // Records when iOS told us to sleep so wake() can log the suspension gap.
    // Static because PacketTunnelProvider instances are owned by the system
    // and we want to survive whatever lifecycle iOS chooses.
    private static var lastSleepAt: Date?
}
