//
//  Created by nullcstring.
//

import Darwin
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
    private var captchaStatsTimer: DispatchSourceTimer?


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
        let wrapKey = (providerConfiguration["wrapKey"] as? String) ?? ""

        SharedLogger.info("Peer: \(peerAddr), Listen: \(listenAddr), N: \(nValue), UDP: \(useUDP), streamAgg: \(streamAggregation), wrap: \(wrapKey.isEmpty ? "off" : "on")", source: .tunnel)
        SharedLogger.info("Starting TURN proxy...", source: .tunnel)

        ProxySetLogger(nil, goProxyCLoggerCallback)
        CaptchaBridge.install()

        // Toggle the Stream-Aggregation handshake on the Go side
        // BEFORE StartProxy. The Go global is read once when each
        // DTLS session completes its handshake, so setting it later
        // would race the per-session goroutines.
        TurnBridgeSetStreamAggregation(streamAggregation ? 1 : 0)

        // SRTP/Opus wrap key. Empty string disables wrap and falls
        // back to the legacy direct DTLS-over-TURN path. Set BEFORE
        // StartProxy — currentWrapKey() is sampled once per session
        // start in oneTurnConnection.
        wrapKey.withCString { TurnBridgeSetWrapKey($0) }

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

        // Captcha solve mode: 0=off (auto only), 1=forced (always manual),
        // 2=fallback (auto first, manual on failure). Backwards-compat:
        // if the new int key isn't set, fall back to the legacy bool
        // (true → 1 forced, false → 0 off).
        let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID)
        let captchaModeRaw: Int = {
            if let raw = defaults?.object(forKey: "manualCaptchaMode") as? Int {
                return raw
            }
            return (defaults?.bool(forKey: "manualCaptcha") ?? false) ? 1 : 0
        }()
        TurnBridgeSetManualCaptchaMode(Int32(captchaModeRaw))
        let captchaModeLabel: String
        switch captchaModeRaw {
        case 1: captchaModeLabel = "manual (forced — always browser sheet)"
        case 2: captchaModeLabel = "manual fallback (browser sheet only when auto fails)"
        default: captchaModeLabel = "auto (in-tunnel solver only)"
        }
        SharedLogger.info("Captcha mode: \(captchaModeLabel)", source: .tunnel)

        // Remote captcha service: if the user configured a backend
        // URL + API key in Settings, the Go side will offload
        // getCreds to it after the first few local solves succeed —
        // letting us pull a second per-IP rate-limit budget from a
        // machine that isn't on the user's mobile IP. Empty values
        // disable the feature (server's getCreds falls back to local
        // every time).
        let remoteURL = UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .string(forKey: "remoteCaptchaServiceURL") ?? ""
        let remoteKey = UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .string(forKey: "remoteCaptchaServiceAPIKey") ?? ""
        remoteURL.withCString { urlPtr in
            remoteKey.withCString { keyPtr in
                ProxySetRemoteCaptchaService(urlPtr, keyPtr)
            }
        }
        if !remoteURL.isEmpty && !remoteKey.isEmpty {
            SharedLogger.info("Remote captcha service configured (\(remoteURL))", source: .tunnel)
        }

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
        // Bump the per-session DTLS budget whenever a user prompt is
        // POSSIBLE — forced (every session prompts) or fallback (auto
        // first, prompt only on failure). Even in fallback mode we
        // need to account for the wall-clock the user can take to
        // tap "solve" on the small minority that does prompt.
        let userPromptPossible = captchaModeRaw == 1 || captchaModeRaw == 2
        let perSessionMs: Int32 = userPromptPossible ? 30_000 : 15_000
        let floorMs:      Int32 = userPromptPossible ? 60_000 : 20_000
        let dtlsReadyTimeoutMs: Int32 = max(floorMs, perSessionMs * nValue)
        SharedLogger.info("DTLS ready budget: \(dtlsReadyTimeoutMs / 1000)s for N=\(nValue) (\(captchaModeLabel))", source: .tunnel)

        DispatchQueue.global(qos: .userInteractive).async {
            StartProxy(vkLink, peerAddr, listenAddr, nValue, udpFlag)
        }

        startCaptchaStatsPublisher()
        Self.startMemoryLogger()

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

        // Tear down any in-flight manual captcha prompt FIRST: after
        // StopProxy the Go waiter is gone and the sheet can never
        // resolve. The app observes the cancel Darwin notification and
        // dismisses the sheet.
        CaptchaBridge.teardown()

        pathMonitor?.cancel()
        pathMonitor = nil
        lastPathStatus = nil
        lastPathInterfaceLabel = nil

        stopCaptchaStatsPublisher()
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

    /// Periodically copy the Go-side captcha counters into the App
    /// Group's shared UserDefaults so the main app's UI can render
    /// "Direct: X · Tunnel: Y" without an IPC round-trip every tick.
    /// Reset to 0/0 happens on disconnect so the previous run's
    /// numbers don't ghost into the next connection.
    private func startCaptchaStatsPublisher() {
        stopCaptchaStatsPublisher()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .seconds(1))
        timer.setEventHandler {
            let direct = Int(TurnBridgeGetCaptchaDirectCount())
            let tunnel = Int(TurnBridgeGetCaptchaTunnelCount())
            let remote = Int(TurnBridgeGetCaptchaRemoteCount())
            let directAttempts = Int(TurnBridgeGetCaptchaDirectAttempts())
            let tunnelAttempts = Int(TurnBridgeGetCaptchaTunnelAttempts())
            let remoteAttempts = Int(TurnBridgeGetCaptchaRemoteAttempts())
            let directInFlight = Int(TurnBridgeGetCaptchaDirectInFlight())
            let tunnelInFlight = Int(TurnBridgeGetCaptchaTunnelInFlight())
            let remoteInFlight = Int(TurnBridgeGetCaptchaRemoteInFlight())
            let sessionsReady = Int(TurnBridgeGetSessionsReady())
            let sessionsTarget = Int(TurnBridgeGetSessionsTarget())
            let directSat = TurnBridgeIsCaptchaDirectSaturated() != 0
            let tunnelSat = TurnBridgeIsCaptchaTunnelSaturated() != 0
            guard let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) else { return }
            defaults.set(direct, forKey: "captchaDirectCount")
            defaults.set(tunnel, forKey: "captchaTunnelCount")
            defaults.set(remote, forKey: "captchaRemoteCount")
            defaults.set(directAttempts, forKey: "captchaDirectAttempts")
            defaults.set(tunnelAttempts, forKey: "captchaTunnelAttempts")
            defaults.set(remoteAttempts, forKey: "captchaRemoteAttempts")
            defaults.set(directInFlight, forKey: "captchaDirectInFlight")
            defaults.set(tunnelInFlight, forKey: "captchaTunnelInFlight")
            defaults.set(remoteInFlight, forKey: "captchaRemoteInFlight")
            defaults.set(sessionsReady, forKey: "sessionsReady")
            defaults.set(sessionsTarget, forKey: "sessionsTarget")
            defaults.set(directSat, forKey: "captchaDirectSaturated")
            defaults.set(tunnelSat, forKey: "captchaTunnelSaturated")
        }
        timer.resume()
        captchaStatsTimer = timer
    }

    private func stopCaptchaStatsPublisher() {
        captchaStatsTimer?.cancel()
        captchaStatsTimer = nil
        if let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID) {
            defaults.set(0, forKey: "captchaDirectCount")
            defaults.set(0, forKey: "captchaTunnelCount")
            defaults.set(0, forKey: "captchaRemoteCount")
            defaults.set(0, forKey: "captchaDirectAttempts")
            defaults.set(0, forKey: "captchaTunnelAttempts")
            defaults.set(0, forKey: "captchaRemoteAttempts")
            defaults.set(0, forKey: "captchaDirectInFlight")
            defaults.set(0, forKey: "captchaTunnelInFlight")
            defaults.set(0, forKey: "captchaRemoteInFlight")
            defaults.set(0, forKey: "sessionsReady")
            defaults.set(0, forKey: "sessionsTarget")
            defaults.set(false, forKey: "captchaDirectSaturated")
            defaults.set(false, forKey: "captchaTunnelSaturated")
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
        // After a sleep iOS thaws our Go runtime. The TURN allocation
        // and DTLS session held by the embedded vk-turn-proxy client
        // MAY be stale (VK TURN drops idle channels after ~50 s, NAT
        // mappings on the cellular side expire, pion/dtls sequence
        // numbers can drift out of the replay window), but only after
        // a long enough suspension. Short sleeps — screen-off blink,
        // brief task switch, lock-unlock cycle — leave every socket
        // intact and we just lose a few hundred ms of keepalive RTT.
        //
        // ProxyForceReconnect cancels ALL live TURN+DTLS sessions
        // (test logs showed 96–100 cancellations per wake on N=50,
        // and the recovery storm immediately trips VK's per-IP
        // ERROR_LIMIT). For short gaps we'd rather keep the work the
        // captcha pipeline already invested in. wakeReconnectThreshold
        // is set below VK's allocation rotation window so anything
        // shorter is presumed survivable.
        let gap = Self.lastSleepAt.map { Date().timeIntervalSince($0) } ?? 0
        let wakeReconnectThreshold: TimeInterval = 30
        if gap < wakeReconnectThreshold {
            sharedLogger.log("System wake — short gap=\(String(format: "%.1f", gap))s, keeping live sessions")
            SharedLogger.info("System wake — short gap=\(String(format: "%.1f", gap))s, keeping live sessions", source: .tunnel)
        } else {
            sharedLogger.log("System wake — gap=\(String(format: "%.1f", gap))s ≥ \(Int(wakeReconnectThreshold))s, forcing TURN/DTLS reconnect")
            SharedLogger.info("System wake — gap=\(String(format: "%.1f", gap))s ≥ \(Int(wakeReconnectThreshold))s, forcing TURN/DTLS reconnect", source: .tunnel)
            ProxyForceReconnect()
        }
        Self.lastSleepAt = nil
    }

    // Records when iOS told us to sleep so wake() can log the suspension gap.
    // Static because PacketTunnelProvider instances are owned by the system
    // and we want to survive whatever lifecycle iOS chooses.
    private static var lastSleepAt: Date?

    // Memory logger — runs every 5 s while the extension is alive.
    // Reports (a) the iOS-given remaining memory budget for this
    // extension via os_proc_available_memory() — this is the number
    // that, once it hits zero, makes iOS terminate us. (b) resident
    // set size via mach_task_basic_info, so we can see WHAT our
    // memory actually is in OS terms (not just Go heap, which the
    // Go-side memstats logger reports separately). The pair tells
    // us how much headroom we have for raising N, where N=50
    // currently sits on the memory budget, and whether spikes
    // come from Go (captcha pipeline) or non-Go (libdtls, mach
    // ports, etc).
    private static var memoryTimer: DispatchSourceTimer?

    static func startMemoryLogger() {
        // Re-arm on every StartProxy so it survives Stop/Start cycles
        // without leaking the previous timer.
        memoryTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now(), repeating: .seconds(5))
        timer.setEventHandler {
            let avail = os_proc_available_memory()
            let rss = currentResidentMemoryBytes()
            // Numbers in MB for human-readable logs.
            let availMB = Double(avail) / 1024.0 / 1024.0
            let rssMB = Double(rss) / 1024.0 / 1024.0
            let msg = String(
                format: "memory: rss=%.1fMB available=%.1fMB",
                rssMB, availMB
            )
            sharedLogger.log("\(msg, privacy: .public)")
            SharedLogger.info(msg, source: .tunnel)
        }
        timer.resume()
        memoryTimer = timer
    }

    private static func currentResidentMemoryBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { ptr -> kern_return_t in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        if kr != KERN_SUCCESS {
            return 0
        }
        return info.resident_size
    }
}
