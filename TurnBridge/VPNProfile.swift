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
    var wgQuickConfig: String

    init(id: UUID = UUID(), name: String = "", vkLink: String = "", peerAddr: String = "", listenAddr: String = "127.0.0.1:9000", nValue: Int = 1, useUDP: Bool = true, wgQuickConfig: String = "") {
        self.id = id
        self.name = name
        self.vkLink = vkLink
        self.peerAddr = peerAddr
        self.listenAddr = listenAddr
        self.nValue = nValue
        self.useUDP = useUDP
        self.wgQuickConfig = wgQuickConfig
    }

    // Backwards compatibility: older saved profiles in UserDefaults won't have useUDP.
    enum CodingKeys: String, CodingKey {
        case id, name, vkLink, peerAddr, listenAddr, nValue, useUDP, wgQuickConfig
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
        wgQuickConfig = try c.decode(String.self, forKey: .wgQuickConfig)
    }
}
