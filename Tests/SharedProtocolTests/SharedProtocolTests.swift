import XCTest
@testable import SharedProtocol

final class SharedProtocolTests: XCTestCase {
    func testDurationsAreFixedAndDefaultIsThirtyMinutes() {
        XCTAssertEqual(
            AccessDuration.allCases.map(\.seconds),
            [900, 1_800, 3_600, 10_800, 21_600]
        )
        XCTAssertEqual(AccessDuration.default, .minutes30)
    }

    func testLeaseRejectsUnknownSchema() throws {
        let lease = Lease(
            schemaVersion: 99,
            requestID: UUID(),
            duration: .minutes30,
            deadlineUptime: 1_800,
            openedAt: Date(timeIntervalSince1970: 1_000),
            expiresAt: Date(timeIntervalSince1970: 2_800),
            bootSessionID: "boot-a",
            scope: .lan,
            lanInterfaceName: "en0",
            lanSourceCIDR: "192.168.1.0/24",
            tailscaleInterfaceName: nil,
            tailscaleAddressCIDR: nil,
            localConsoleOnly: false
        )

        XCTAssertThrowsError(try lease.validate()) { error in
            XCTAssertEqual(error as? ControlErrorCode, .invalidLease)
        }
    }

    func testLeaseRejectsScopeSnapshotMismatch() {
        let missingLAN = Lease(
            requestID: UUID(), duration: .minutes30, deadlineUptime: 1_800,
            openedAt: Date(timeIntervalSince1970: 1_000), expiresAt: Date(timeIntervalSince1970: 2_800),
            bootSessionID: "boot-a", scope: .lan,
            lanInterfaceName: nil, lanSourceCIDR: nil,
            tailscaleInterfaceName: nil, tailscaleAddressCIDR: nil,
            localConsoleOnly: false
        )
        XCTAssertThrowsError(try missingLAN.validate())

        let unexpectedTailscale = Lease(
            requestID: UUID(), duration: .minutes30, deadlineUptime: 1_800,
            openedAt: Date(timeIntervalSince1970: 1_000), expiresAt: Date(timeIntervalSince1970: 2_800),
            bootSessionID: "boot-a", scope: .lan,
            lanInterfaceName: "en0", lanSourceCIDR: "192.168.1.0/24",
            tailscaleInterfaceName: "utun6", tailscaleAddressCIDR: "100.101.102.103/32",
            localConsoleOnly: false
        )
        XCTAssertThrowsError(try unexpectedTailscale.validate())
    }

    func testLeaseAcceptsValidLANAndTailscaleScope() throws {
        let lease = Lease(
            requestID: UUID(), duration: .minutes30, deadlineUptime: 1_800,
            openedAt: Date(timeIntervalSince1970: 1_000), expiresAt: Date(timeIntervalSince1970: 2_800),
            bootSessionID: "boot-a", scope: .lanAndTailscale,
            lanInterfaceName: "en0", lanSourceCIDR: "192.168.1.0/24",
            tailscaleInterfaceName: "utun6", tailscaleAddressCIDR: "100.101.102.103/32",
            localConsoleOnly: false
        )
        try lease.validate()
    }

    func testLeaseRejectsRawSchemaVersionOneJSON() {
        let v1JSON = """
        {
            "schemaVersion": 1,
            "requestID": "75948C79-1EF8-4497-A048-33C307893B2A",
            "duration": 1800,
            "deadlineUptime": 1800,
            "openedAt": 1000,
            "expiresAt": 2800,
            "bootSessionID": "boot-a",
            "interfaceName": "en0",
            "sourceCIDR": "192.168.1.0/24",
            "localConsoleOnly": false
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(Lease.self, from: v1JSON))
    }

    func testNetworkScopeFromBooleansCoversAllCombinations() throws {
        XCTAssertEqual(try SSHNetworkScope.from(lan: true, tailscale: false), .lan)
        XCTAssertEqual(try SSHNetworkScope.from(lan: false, tailscale: true), .tailscale)
        XCTAssertEqual(try SSHNetworkScope.from(lan: true, tailscale: true), .lanAndTailscale)
        XCTAssertThrowsError(try SSHNetworkScope.from(lan: false, tailscale: false)) { error in
            XCTAssertEqual(error as? ControlErrorCode, .invalidNetworkScope)
        }
    }

    func testNetworkScopeDecodingRejectsUnknownRawValue() {
        let data = Data(#""neither""#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(SSHNetworkScope.self, from: data))
    }

    func testStatusEncodingDoesNotContainPrivilegedOutput() throws {
        let data = try JSONEncoder().encode(
            AccessStatus.closed(lastTransition: nil, localConsoleOnly: false)
        )
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("commandOutput"))
    }

    func testResponseEnvelopeIsBoundedAndStable() throws {
        let response = ControlResponse(
            status: .unavailable(reason: .pfUnavailable, localConsoleOnly: false),
            error: .pfUnavailable
        )
        let encoded = try JSONEncoder().encode(response)

        XCTAssertLessThan(encoded.count, ControlResponse.maximumEncodedBytes)
        XCTAssertEqual(try JSONDecoder().decode(ControlResponse.self, from: encoded), response)
    }

    func testInstalledPathsAreFixed() {
        XCTAssertEqual(InstalledPaths.pfAnchorName, "com.serverpc.ssh-control")
        XCTAssertEqual(InstalledPaths.controllerMachService, "com.serverpc.ssh-control.controller")
        XCTAssertEqual(InstalledPaths.applicationBundle, "/Applications/Mac SSH Manager.app")
        XCTAssertEqual(InstalledPaths.stateRoot, "/Library/Application Support/ServerPCSSHControl/State")
    }
}
