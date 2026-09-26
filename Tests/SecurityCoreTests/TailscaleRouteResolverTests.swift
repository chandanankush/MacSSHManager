import Darwin
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class TailscaleRouteResolverTests: XCTestCase {
    func testResolvesSingleValidatedCandidate() throws {
        let source = FakeNetworkConfigurationSource(addresses: [
            .tailscale(name: "utun6", address: "100.101.102.103")
        ])

        XCTAssertEqual(
            try TailscaleRouteResolver(source: source).resolve(),
            TailscaleSnapshot(interfaceName: "utun6", addressCIDR: "100.101.102.103/32")
        )
    }

    func testResolvesRegardlessOfSpecificUtunNumber() throws {
        let source = FakeNetworkConfigurationSource(addresses: [
            .tailscale(name: "utun17", address: "100.77.174.83")
        ])

        XCTAssertEqual(
            try TailscaleRouteResolver(source: source).resolve(),
            TailscaleSnapshot(interfaceName: "utun17", addressCIDR: "100.77.174.83/32")
        )
    }

    func testFailsClosedWhenNoCandidateExists() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .ipv4(name: "en0", address: "192.168.50.12", netmask: "255.255.255.0")
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve()) { error in
            XCTAssertEqual(error as? ControlErrorCode, .tailscaleUnavailable)
        }
    }

    func testFailsClosedWhenMultipleCandidatesAreAmbiguous() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .tailscale(name: "utun6", address: "100.101.102.103"),
            .tailscale(name: "utun9", address: "100.101.102.200")
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve()) { error in
            XCTAssertEqual(error as? ControlErrorCode, .tailscaleUnavailable)
        }
    }

    func testRejectsNonUtunInterfaceEvenWithinTailscaleRange() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "en5",
                address: "100.101.102.103",
                netmask: "255.255.255.255",
                flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }

    func testRejectsUtunInterfaceOutsideTailscaleRange() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "utun8",
                address: "10.8.0.2",
                netmask: "255.255.255.255",
                flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }

    func testRejectsNonPointToPointNetmask() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "utun6",
                address: "100.101.102.103",
                netmask: "255.255.255.0",
                flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }

    func testRejectsLoopbackFlaggedInterface() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "utun6",
                address: "100.101.102.103",
                netmask: "255.255.255.255",
                flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_LOOPBACK)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }

    func testRejectsDownOrNotRunningInterface() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "utun6",
                address: "100.101.102.103",
                netmask: "255.255.255.255",
                flags: UInt32(IFF_POINTOPOINT)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }

    func testRejectsInjectedInterfaceName() {
        let source = FakeNetworkConfigurationSource(addresses: [
            .init(
                name: "utun6\npass",
                address: "100.101.102.103",
                netmask: "255.255.255.255",
                flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
            )
        ])

        XCTAssertThrowsError(try TailscaleRouteResolver(source: source).resolve())
    }
}

private extension NetworkAddressRecord {
    static func tailscale(name: String, address: String) -> Self {
        .init(
            name: name,
            address: address,
            netmask: "255.255.255.255",
            flags: UInt32(IFF_UP | IFF_RUNNING | IFF_POINTOPOINT)
        )
    }
}

private struct FakeNetworkConfigurationSource: NetworkConfigurationSourcing {
    let addresses: [NetworkAddressRecord]
    func primaryIPv4InterfaceName() throws -> String? { nil }
    func hardwareInterfaces() throws -> [NetworkHardwareInterface] { [] }
    func interfaceAddresses() throws -> [NetworkAddressRecord] { addresses }
}
