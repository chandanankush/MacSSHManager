import Foundation

public enum SSHNetworkScope: String, Codable, Equatable, Sendable {
    case lan
    case tailscale
    case lanAndTailscale

    public var includesLAN: Bool { self == .lan || self == .lanAndTailscale }
    public var includesTailscale: Bool { self == .tailscale || self == .lanAndTailscale }

    public static func from(lan: Bool, tailscale: Bool) throws -> Self {
        switch (lan, tailscale) {
        case (true, true): .lanAndTailscale
        case (true, false): .lan
        case (false, true): .tailscale
        case (false, false): throw ControlErrorCode.invalidNetworkScope
        }
    }
}
