import Foundation
import Security
import XCTest
@testable import MenuAppCore
@testable import SharedProtocol

@MainActor
final class ControllerClientTests: XCTestCase {
    func testLocalControllerRequirementPinsCertificateAndHelperIdentifier() throws {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        let text = XPCControllerClient.controllerRequirement(localCertificateSHA1: fingerprint)
        XCTAssertEqual(text, "identifier \"com.serverpc.ssh-control.controller\" and certificate leaf = H\"0123456789ABCDEF0123456789ABCDEF01234567\"")
        var requirement: SecRequirement?
        XCTAssertEqual(SecRequirementCreateWithString(text as CFString, [], &requirement), errSecSuccess)
        XCTAssertNotNil(requirement)
    }

    func testMalformedLocalCertificatePinFailsClosed() {
        for value in ["", "1234", String(repeating: "G", count: 40), "0123456789ABCDEF0123456789ABCDEF01234567 or always"] {
            XCTAssertEqual(XPCControllerClient.controllerRequirement(localCertificateSHA1: value), "never")
        }
    }

    func testAppleControllerRequirementRemainsDefaultWithoutLocalPin() {
        XCTAssertEqual(XPCControllerClient.controllerRequirement(localCertificateSHA1: nil),
                       XPCControllerClient.controllerRequirement)
    }

    func testHistoryDecoderRejectsMoreThanTwoHundredFiftyEntries() throws {
        let entry = AuditHistoryEntry(
            timestamp: Date(timeIntervalSince1970: 1_000),
            kind: .sshConnected,
            outcome: .success,
            reason: nil,
            duration: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            localConsoleOnly: nil,
            sshUser: "deploy",
            sourceAddress: "192.168.8.20"
        )
        let response = AuditHistoryResponse.success(.init(entries: Array(repeating: entry, count: 251)))
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(response)

        XCTAssertThrowsError(try XPCControllerClient.decodeHistoryResponse(data)) { error in
            XCTAssertEqual(error as? ControlErrorCode, .malformedRequest)
        }
    }
}
