import Darwin
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class PhysicalLANResolverTests: XCTestCase {
    func testResolverSelectsDefaultPhysicalIPv4Interface() throws {
        let source = FakeNetworkConfigurationSource(
            primary: "en0",
            hardware: [
                .init(name: "en0", kind: .ethernet),
                .init(name: "utun4", kind: .virtual)
            ],
            addresses: [
                .ipv4(name: "en0", address: "192.168.50.12", netmask: "255.255.255.0"),
                .ipv4(name: "utun4", address: "100.64.1.2", netmask: "255.255.255.255")
            ]
        )

        XCTAssertEqual(
            try PhysicalLANResolver(source: source).resolve(),
            LANSnapshot(interfaceName: "en0", sourceCIDR: "192.168.50.0/24", isPrivate: true)
        )
    }

    func testResolverAllowsPublicPhysicalLANButMarksWarningFlag() throws {
        let source = FakeNetworkConfigurationSource(
            primary: "en7",
            hardware: [.init(name: "en7", kind: .wifi)],
            addresses: [.ipv4(name: "en7", address: "203.0.113.42", netmask: "255.255.255.0")]
        )

        XCTAssertEqual(
            try PhysicalLANResolver(source: source).resolve(),
            LANSnapshot(interfaceName: "en7", sourceCIDR: "203.0.113.0/24", isPrivate: false)
        )
    }

    func testResolverRejectsVirtualPrimaryInterface() {
        let source = FakeNetworkConfigurationSource(
            primary: "utun4",
            hardware: [.init(name: "utun4", kind: .virtual)],
            addresses: [.ipv4(name: "utun4", address: "100.64.1.2", netmask: "255.255.255.255")]
        )

        XCTAssertThrowsError(try PhysicalLANResolver(source: source).resolve()) { error in
            XCTAssertEqual(error as? ControlErrorCode, .networkUnavailable)
        }
    }

    func testResolverRejectsNoncontiguousNetmask() {
        let source = FakeNetworkConfigurationSource(
            primary: "en0",
            hardware: [.init(name: "en0", kind: .ethernet)],
            addresses: [.ipv4(name: "en0", address: "192.168.1.2", netmask: "255.0.255.0")]
        )

        XCTAssertThrowsError(try PhysicalLANResolver(source: source).resolve())
    }
}

private struct FakeNetworkConfigurationSource: NetworkConfigurationSourcing {
    let primary: String?
    let hardware: [NetworkHardwareInterface]
    let addresses: [NetworkAddressRecord]

    func primaryIPv4InterfaceName() throws -> String? { primary }
    func hardwareInterfaces() throws -> [NetworkHardwareInterface] { hardware }
    func interfaceAddresses() throws -> [NetworkAddressRecord] { addresses }
}
