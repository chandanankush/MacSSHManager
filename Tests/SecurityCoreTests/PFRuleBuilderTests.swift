import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class PFRuleBuilderTests: XCTestCase {
    func testLANOnlyEmitsSingleLANPassRuleThenBlock() throws {
        let rules = try PFRuleBuilder().openRules(.lanOnly)

        XCTAssertEqual(
            rules,
            "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
                "block drop in quick proto tcp from any to any port 22\n"
        )
    }

    func testTailscaleOnlyEmitsSingleTailscalePassRuleThenBlock() throws {
        let rules = try PFRuleBuilder().openRules(.tailscaleOnly)

        XCTAssertEqual(
            rules,
            "pass in quick on utun6 inet proto tcp from 100.64.0.0/10 to 100.101.102.103/32 " +
                "port 22 flags S/SA keep state\n" +
                "block drop in quick proto tcp from any to any port 22\n"
        )
    }

    func testLANAndTailscaleEmitsLANRuleBeforeTailscaleRuleThenBlock() throws {
        let rules = try PFRuleBuilder().openRules(.lanAndTailscale)

        XCTAssertEqual(
            rules,
            "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
                "pass in quick on utun6 inet proto tcp from 100.64.0.0/10 to 100.101.102.103/32 " +
                "port 22 flags S/SA keep state\n" +
                "block drop in quick proto tcp from any to any port 22\n"
        )
    }

    func testClosedRulesBlockAllInboundIPv4AndIPv6SSH() {
        XCTAssertEqual(
            PFRuleBuilder().closedRules(),
            "block drop in quick proto tcp from any to any port 22\n"
        )
    }

    func testRuleBuilderRejectsInjectedLANInterfaceAndCIDR() throws {
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .lan,
                lan: LANSnapshot(interfaceName: "en0\npass", sourceCIDR: "192.168.1.0/24", isPrivate: true),
                tailscale: nil
            ))
        )
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .lan,
                lan: LANSnapshot(interfaceName: "en0", sourceCIDR: "any", isPrivate: true),
                tailscale: nil
            ))
        )
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .lan,
                lan: LANSnapshot(interfaceName: "utun4", sourceCIDR: "100.64.1.2/32", isPrivate: false),
                tailscale: nil
            ))
        )
    }

    func testRuleBuilderRejectsInjectedTailscaleInterfaceAndAddress() throws {
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .tailscale,
                lan: nil,
                tailscale: TailscaleSnapshot(interfaceName: "utun6\npass", addressCIDR: "100.101.102.103/32")
            ))
        )
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .tailscale,
                lan: nil,
                tailscale: TailscaleSnapshot(interfaceName: "en0", addressCIDR: "100.101.102.103/32")
            ))
        )
        XCTAssertThrowsError(
            try PFRuleBuilder().openRules(.init(
                scope: .tailscale,
                lan: nil,
                tailscale: TailscaleSnapshot(interfaceName: "utun6", addressCIDR: "any")
            ))
        )
    }
}

extension SSHAccessNetworkSnapshot {
    static let lanOnly = try! SSHAccessNetworkSnapshot(
        scope: .lan,
        lan: LANSnapshot(interfaceName: "en0", sourceCIDR: "192.168.50.0/24", isPrivate: true),
        tailscale: nil
    )
    static let tailscaleOnly = try! SSHAccessNetworkSnapshot(
        scope: .tailscale,
        lan: nil,
        tailscale: TailscaleSnapshot(interfaceName: "utun6", addressCIDR: "100.101.102.103/32")
    )
    static let lanAndTailscale = try! SSHAccessNetworkSnapshot(
        scope: .lanAndTailscale,
        lan: LANSnapshot(interfaceName: "en0", sourceCIDR: "192.168.50.0/24", isPrivate: true),
        tailscale: TailscaleSnapshot(interfaceName: "utun6", addressCIDR: "100.101.102.103/32")
    )
}
