import Darwin
import Foundation
import SharedProtocol

public struct TailscaleSnapshot: Codable, Equatable, Sendable {
    public let interfaceName: String
    public let addressCIDR: String

    public init(interfaceName: String, addressCIDR: String) {
        self.interfaceName = interfaceName
        self.addressCIDR = addressCIDR
    }
}

public protocol TailscaleResolving: Sendable {
    func resolve() throws -> TailscaleSnapshot
}

/// Identifies the current, freshly-validated Tailscale interface without ever
/// hardcoding a `utunN` number. A single candidate must independently satisfy
/// three narrow signals at once: a `utun`-prefixed name, a point-to-point host
/// route (`/32`), and an address inside Tailscale's documented, stable CGNAT
/// allocation (100.64.0.0/10). Zero or more than one candidate fails closed.
public struct TailscaleRouteResolver: TailscaleResolving, Sendable {
    private let source: any NetworkConfigurationSourcing
    private let debug: any DebugLogging

    public init(
        source: any NetworkConfigurationSourcing = SystemNetworkConfigurationSource(),
        debug: any DebugLogging = NoopDebugLog()
    ) {
        self.source = source
        self.debug = debug
    }

    public func resolve() throws -> TailscaleSnapshot {
        let allAddresses = try source.interfaceAddresses()
        let candidates = allAddresses.filter { record in
            Self.isTailscaleInterfaceName(record.name) &&
                Self.isUsable(flags: record.flags) &&
                Self.isValidatedTailscaleAddress(record.address, netmask: record.netmask)
        }
        guard candidates.count == 1, let candidate = candidates.first else {
            debug.log("""
                resolve(): \(candidates.count) candidate(s) matched (need exactly 1); \
                all interfaces=\(allAddresses.map { "\($0.name)=\($0.address)/\($0.netmask) flags=\($0.flags)" })
                """)
            throw ControlErrorCode.tailscaleUnavailable
        }
        debug.log("resolve(): selected \(candidate.name)=\(candidate.address)")
        return TailscaleSnapshot(interfaceName: candidate.name, addressCIDR: "\(candidate.address)/32")
    }

    static func isTailscaleInterfaceName(_ name: String) -> Bool {
        PhysicalLANResolver.isSafeInterfaceName(name) && name.lowercased().hasPrefix("utun")
    }

    private static func isValidatedTailscaleAddress(_ address: String, netmask: String) -> Bool {
        guard let network = IPv4Network(address: address, netmask: netmask) else { return false }
        return network.prefixLength == 32 && network.isTailscaleRange
    }

    private static func isUsable(flags: UInt32) -> Bool {
        let required = UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
        let prohibited = UInt32(IFF_LOOPBACK)
        return flags & required == required && flags & prohibited == 0
    }
}
