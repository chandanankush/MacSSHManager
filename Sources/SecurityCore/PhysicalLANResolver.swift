import Darwin
import Foundation
import SharedProtocol
import SystemConfiguration

public struct LANSnapshot: Codable, Equatable, Sendable {
    public let interfaceName: String
    public let sourceCIDR: String
    public let isPrivate: Bool

    public init(interfaceName: String, sourceCIDR: String, isPrivate: Bool) {
        self.interfaceName = interfaceName
        self.sourceCIDR = sourceCIDR
        self.isPrivate = isPrivate
    }
}

public enum NetworkHardwareKind: Equatable, Sendable {
    case ethernet
    case wifi
    case virtual

    var isPhysicalLAN: Bool { self == .ethernet || self == .wifi }
}

public struct NetworkHardwareInterface: Equatable, Sendable {
    public let name: String
    public let kind: NetworkHardwareKind

    public init(name: String, kind: NetworkHardwareKind) {
        self.name = name
        self.kind = kind
    }
}

public struct NetworkAddressRecord: Equatable, Sendable {
    public let name: String
    public let address: String
    public let netmask: String
    public let flags: UInt32

    public init(name: String, address: String, netmask: String, flags: UInt32) {
        self.name = name
        self.address = address
        self.netmask = netmask
        self.flags = flags
    }

    public static func ipv4(
        name: String,
        address: String,
        netmask: String,
        flags: UInt32 = UInt32(IFF_UP | IFF_RUNNING)
    ) -> Self {
        Self(name: name, address: address, netmask: netmask, flags: flags)
    }
}

public protocol NetworkConfigurationSourcing: Sendable {
    func primaryIPv4InterfaceName() throws -> String?
    func hardwareInterfaces() throws -> [NetworkHardwareInterface]
    func interfaceAddresses() throws -> [NetworkAddressRecord]
}

public protocol LANResolving: Sendable {
    func resolve() throws -> LANSnapshot
}

public struct PhysicalLANResolver: LANResolving, Sendable {
    private let source: any NetworkConfigurationSourcing

    public init(source: any NetworkConfigurationSourcing = SystemNetworkConfigurationSource()) {
        self.source = source
    }

    public func resolve() throws -> LANSnapshot {
        guard let primary = try source.primaryIPv4InterfaceName(),
              Self.isSafeInterfaceName(primary),
              let hardware = try source.hardwareInterfaces().first(where: { $0.name == primary }),
              hardware.kind.isPhysicalLAN,
              !Self.isKnownVirtualName(primary),
              let address = try source.interfaceAddresses().first(where: { record in
                  record.name == primary && Self.isUsable(flags: record.flags)
              }),
              let network = IPv4Network(address: address.address, netmask: address.netmask),
              !network.isLoopback
        else {
            throw ControlErrorCode.networkUnavailable
        }

        return LANSnapshot(
            interfaceName: primary,
            sourceCIDR: network.cidr,
            isPrivate: network.isPrivate
        )
    }

    static func isSafeInterfaceName(_ name: String) -> Bool {
        guard (1...15).contains(name.utf8.count) else { return false }
        return name.utf8.allSatisfy { byte in
            (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
        }
    }

    static func isKnownVirtualName(_ name: String) -> Bool {
        ["utun", "tun", "tap", "bridge", "vboxnet", "vmnet", "docker", "colima", "tailscale"]
            .contains { name.lowercased().hasPrefix($0) }
    }

    private static func isUsable(flags: UInt32) -> Bool {
        let required = UInt32(IFF_UP | IFF_RUNNING)
        let prohibited = UInt32(IFF_LOOPBACK | IFF_POINTOPOINT)
        return flags & required == required && flags & prohibited == 0
    }
}

public struct SystemNetworkConfigurationSource: NetworkConfigurationSourcing, Sendable {
    public init() {}

    public func primaryIPv4InterfaceName() throws -> String? {
        guard let value = SCDynamicStoreCopyValue(nil, "State:/Network/Global/IPv4" as CFString),
              let dictionary = value as? [String: Any]
        else {
            return nil
        }
        return dictionary[kSCDynamicStorePropNetPrimaryInterface as String] as? String
    }

    public func hardwareInterfaces() throws -> [NetworkHardwareInterface] {
        guard let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [] }
        return interfaces.compactMap { interface -> NetworkHardwareInterface? in
            guard let name = SCNetworkInterfaceGetBSDName(interface) as String? else { return nil }
            let type = SCNetworkInterfaceGetInterfaceType(interface) as String?
            let kind: NetworkHardwareKind
            if type == (kSCNetworkInterfaceTypeEthernet as String) {
                kind = .ethernet
            } else if type == (kSCNetworkInterfaceTypeIEEE80211 as String) {
                kind = .wifi
            } else {
                kind = .virtual
            }
            return NetworkHardwareInterface(name: name, kind: kind)
        }
    }

    public func interfaceAddresses() throws -> [NetworkAddressRecord] {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else {
            throw ControlErrorCode.networkUnavailable
        }
        defer { freeifaddrs(first) }

        var records: [NetworkAddressRecord] = []
        var current = first
        while let interface = current?.pointee {
            defer { current = interface.ifa_next }
            guard interface.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
                  let address = numericIPv4(interface.ifa_addr),
                  let netmask = numericIPv4(interface.ifa_netmask)
            else {
                continue
            }
            records.append(
                NetworkAddressRecord(
                    name: String(cString: interface.ifa_name),
                    address: address,
                    netmask: netmask,
                    flags: interface.ifa_flags
                )
            )
        }
        return records
    }

    private func numericIPv4(_ address: UnsafeMutablePointer<sockaddr>?) -> String? {
        guard let address else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = getnameinfo(
            address,
            socklen_t(address.pointee.sa_len),
            &buffer,
            socklen_t(buffer.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard result == 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

struct IPv4Network: Equatable, Sendable {
    let address: UInt32
    let network: UInt32
    let prefixLength: Int

    init?(address: String, netmask: String) {
        guard let addressValue = Self.parse(address),
              let maskValue = Self.parse(netmask),
              let prefix = Self.prefixLength(of: maskValue),
              prefix > 0
        else {
            return nil
        }
        self.address = addressValue
        network = addressValue & maskValue
        prefixLength = prefix
    }

    init?(cidr: String) {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = Self.parse(String(parts[0])),
              let prefix = Int(parts[1]),
              (1...32).contains(prefix)
        else {
            return nil
        }
        let mask = prefix == 32 ? UInt32.max : UInt32.max << UInt32(32 - prefix)
        guard address & mask == address else { return nil }
        self.address = address
        network = address
        prefixLength = prefix
    }

    var cidr: String { "\(Self.render(network))/\(prefixLength)" }
    var isLoopback: Bool { address & 0xFF00_0000 == 0x7F00_0000 }
    var isPrivate: Bool {
        address & 0xFF00_0000 == 0x0A00_0000 ||
            address & 0xFFF0_0000 == 0xAC10_0000 ||
            address & 0xFFFF_0000 == 0xC0A8_0000
    }
    /// Tailscale's documented, stable CGNAT allocation range (100.64.0.0/10).
    var isTailscaleRange: Bool { address & 0xFFC0_0000 == 0x6440_0000 }

    private static func parse(_ value: String) -> UInt32? {
        var parsed = in_addr()
        guard inet_pton(AF_INET, value, &parsed) == 1 else { return nil }
        return UInt32(bigEndian: parsed.s_addr)
    }

    private static func render(_ value: UInt32) -> String {
        var address = in_addr(s_addr: value.bigEndian)
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count))
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func prefixLength(of mask: UInt32) -> Int? {
        let inverted = ~mask
        guard inverted & (inverted &+ 1) == 0 else { return nil }
        return mask.nonzeroBitCount
    }
}
