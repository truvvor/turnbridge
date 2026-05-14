import Foundation

struct VPNProfile: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var vkLink: String
    var peerAddr: String
    var listenAddr: String
    var nValue: Int
    /// Transport from client to TURN server.
    /// true  = UDP (faster, default; what upstream turnbridge has hardcoded)
    /// false = TCP (more reliable over flaky cellular; survives short blips)
    var useUDP: Bool
    /// Enables the kiper292/vk-turn-proxy 17-byte Session-ID handshake
    /// on every DTLS stream so the server-side aggregator can fuse the
    /// N parallel TURN allocations into a single stable endpoint for
    /// WireGuard. Must ONLY be enabled when the WG server is running a
    /// compatible aggregator; otherwise the 17 bytes corrupt the very
    /// first WG handshake and the tunnel never comes up.
    var streamAggregation: Bool
    var wgQuickConfig: String

    init(id: UUID = UUID(), name: String = "", vkLink: String = "", peerAddr: String = "", listenAddr: String = "127.0.0.1:9000", nValue: Int = 1, useUDP: Bool = true, streamAggregation: Bool = false, wgQuickConfig: String = "") {
        self.id = id
        self.name = name
        self.vkLink = vkLink
        self.peerAddr = peerAddr
        self.listenAddr = listenAddr
        self.nValue = nValue
        self.useUDP = useUDP
        self.streamAggregation = streamAggregation
        self.wgQuickConfig = wgQuickConfig
    }

    // Backwards compatibility: older saved profiles in UserDefaults won't have useUDP / streamAggregation.
    enum CodingKeys: String, CodingKey {
        case id, name, vkLink, peerAddr, listenAddr, nValue, useUDP, streamAggregation, wgQuickConfig
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        vkLink = try c.decode(String.self, forKey: .vkLink)
        peerAddr = try c.decode(String.self, forKey: .peerAddr)
        listenAddr = try c.decode(String.self, forKey: .listenAddr)
        nValue = try c.decode(Int.self, forKey: .nValue)
        useUDP = (try? c.decode(Bool.self, forKey: .useUDP)) ?? true
        streamAggregation = (try? c.decode(Bool.self, forKey: .streamAggregation)) ?? false
        wgQuickConfig = try c.decode(String.self, forKey: .wgQuickConfig)
    }
}
