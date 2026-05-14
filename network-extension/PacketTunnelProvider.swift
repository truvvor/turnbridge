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
    private var lastPathStatus: Network.NWPath.Status?
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
        // Default true for backward-compat with profiles saved before this field existed.
        let useUDP = (providerConfiguration["useUDP"] as? Bool) ?? true
        let udpFlag: Int32 = useUDP ? 1 : 0
        let streamAggregation = (providerConfiguration["streamAggregation"] as? Bool) ?? false

        SharedLogger.info("Peer: \(peerAddr), Listen: \(listenAddr), N: \(nValue), UDP: \(useUDP), streamAgg: \(streamAggregation)", source: .tunnel)
        SharedLogger.info("Starting TURN proxy...", source: .tunnel)

        ProxySetLogger(nil, goProxyCLoggerCallback)
        CaptchaBridge.install()

        // Toggle the Stream-Aggregation handshake on the Go side
        // BEFORE StartProxy. The Go global is read once when each
        // DTLS session completes its handshake, so setting it later
        // would race the per-session goroutines.
        TurnBridgeSetStreamAggregation(streamAggregation ? 1 : 0)

        // Captcha trap: every slider captcha buffers its raw VK
        // response + decoded image in memory and only flushes to disk
        // when the solve ultimately fails. The artefacts land inside
        // the App Group container so they show up in the Files app
        // and survive across extension restarts. Passing the path
        // before StartProxy ensures the very first solve is covered.
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: CaptchaIPC.appGroupID) {
            let trapDir = container.appendingPathComponent("captcha_trap", isDirectory: true)
            try? FileManager.default.createDirectory(at: trapDir, withIntermediateDirectories: true)
            trapDir.path.withCString { TurnBridgeSetCaptchaTrapDir($0) }
            SharedLogger.info("Captcha trap dir: \(trapDir.path)", source: .tunnel)
        }

        let manualCaptchaEnabled = UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .bool(forKey: "manualCaptcha") ?? false
        TurnBridgeSetManualCaptchaMode(manualCaptchaEnabled ? 1 : 0)
        SharedLogger.info("Captcha mode: \(manualCaptchaEnabled ? "manual (browser sheet)" : "auto (in-tunnel solver)")", source: .tunnel)

        // Scale the readiness budget by N: StartProxy on the Go side
        // now waits for ALL N TURN allocations to come up before it
        // signals proxyReady (otherwise the WG adapter starts after
        // session 1 is up, iOS installs AllowedIPs=0.0.0.0/0 into
        // utun, and the captcha load for sessions 2..N gets routed
        // through the half-built tunnel and never completes — see
        // turn_proxy.go's StartProxy comment).
        //
        // Per-session budget:
        //   manual: the user is in the loop solving each captcha by
        //   hand, so plan for ~30 s/session plus a generous floor.
        //   auto:   the in-tunnel solver finishes in ~3–6 s on a
        //   warm path but burns longer on a slider+retry sequence,
        //   so budget ~15 s/session.
        //
        // The old 12 s / 300 s constants assumed N=1 and were the
        // direct cause of "DTLS connection timeout (12s)" landing
        // mid-Step-2/4 when nValue>1.
        let perSessionMs: Int32 = manualCaptchaEnabled ? 30_000 : 15_000
        let floorMs:      Int32 = manualCaptchaEnabled ? 60_000 : 20_000
        let dtlsReadyTimeoutMs: Int32 = max(floorMs, perSessionMs * nValue)
        SharedLogger.info("DTLS ready budget: \(dtlsReadyTimeoutMs / 1000)s for N=\(nValue) (\(manualCaptchaEnabled ? "manual" : "auto"))", source: .tunnel)

        DispatchQueue.global(qos: .userInteractive).async {
            StartProxy(vkLink, peerAddr, listenAddr, nValue, udpFlag)
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
                    self.logRouteScope()
                    self.startNetworkMonitoring()
                }
                completionHandler(adapterError)
            }
        }
    }

    /// Dump what is actually going into the tunnel. The previous version
    /// of this method read `routeLAN`/`manualCaptcha` from
    /// `providerConfiguration`, but the app never puts those keys
    /// there — it bakes the routing decision into the WG peer's
    /// `AllowedIPs` and reads `manualCaptcha` from the App Group's
    /// shared UserDefaults. The result: this log was reporting false
    /// for everything regardless of the actual UI state. Fixed to read
    /// the same sources the rest of the extension uses.
    private func logRouteScope() {
        // Manual-captcha flag is the app-group setting that the rest of
        // PacketTunnelProvider already reads (see startTunnel:104).
        let manualCap = UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .bool(forKey: "manualCaptcha") ?? false

        // The peer's AllowedIPs is the source of truth for what the OS
        // routes into utun. With AllowedIPs=0.0.0.0/0, ::/0 everything
        // goes through; with a narrow LAN list, the user's browser
        // traffic exits via the underlying interface and only LAN/peer
        // traffic uses the tunnel.
        var allowedIPs: [String] = []
        if let settings = self.protocolConfiguration as? NETunnelProviderProtocol,
           let cfg = settings.providerConfiguration,
           let wgQuick = cfg["wgQuickConfig"] as? String {
            for raw in wgQuick.split(separator: "\n") {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.lowercased().hasPrefix("allowedips") {
                    if let eq = line.firstIndex(of: "=") {
                        let value = line[line.index(after: eq)...]
                            .trimmingCharacters(in: .whitespaces)
                        allowedIPs = value.split(separator: ",")
                            .map { $0.trimmingCharacters(in: .whitespaces) }
                    }
                }
            }
        }

        let isFullTunnel = allowedIPs.contains { $0 == "0.0.0.0/0" || $0 == "::/0" }
        SharedLogger.info(
            "Tunnel routing scope: AllowedIPs=\(allowedIPs.isEmpty ? "?" : allowedIPs.joined(separator: ",")) fullTunnel=\(isFullTunnel) manualCaptcha=\(manualCap)",
            source: .tunnel
        )
        if !isFullTunnel {
            SharedLogger.info(
                "Split tunnel: only AllowedIPs subnets go via utun, the user's browser traffic exits via the underlying network",
                source: .tunnel
            )
        }
    }

    private func describe(_ status: Network.NWPath.Status) -> String {
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
            let recovered = prevStatus != Network.NWPath.Status.satisfied && path.status == Network.NWPath.Status.satisfied
            if !interfaceFlipped && !recovered {
                return
            }
            SharedLogger.info("NWPath change: \(prevLabel)/\(prevStatusStr) -> \(label)/\(curStatusStr)", source: .tunnel)
            if path.status == Network.NWPath.Status.satisfied {
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
