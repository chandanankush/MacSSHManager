import Darwin
import Foundation
import XCTest
@testable import SecurityCore

final class PFInstallationValidatorTests: XCTestCase {
    func testExactRootOwnedAnchorLinkageIsAccepted() throws {
        let fixture = try Fixture()
        try fixture.writeValidFiles()

        XCTAssertTrue(fixture.validator.isValid())
    }

    func testMissingLoadReferenceIsRejected() throws {
        let fixture = try Fixture()
        try fixture.writeValidFiles()
        try fixture.writePFConfig("anchor \"com.serverpc.ssh-control\"\n")

        XCTAssertFalse(fixture.validator.isValid())
    }

    func testDuplicateManagedReferencesAreRejected() throws {
        let fixture = try Fixture()
        let reference = "load anchor \"com.serverpc.ssh-control\" from \"/etc/pf.anchors/com.serverpc.ssh-control\"\n"
        try fixture.writeValidFiles()
        try fixture.writePFConfig(fixture.validConfig + reference)

        XCTAssertFalse(fixture.validator.isValid())
    }

    func testWritableAnchorFileIsRejected() throws {
        let fixture = try Fixture()
        try fixture.writeValidFiles()
        XCTAssertEqual(chmod(fixture.anchor.path, 0o622), 0)

        XCTAssertFalse(fixture.validator.isValid())
    }
}

private final class Fixture {
    let root: URL
    let pfConfig: URL
    let anchor: URL
    let validator: FilePFInstallationValidator

    let validConfig = """
    set skip on lo0
    # BEGIN SERVERPC SSH CONTROL
    anchor "com.serverpc.ssh-control"
    load anchor "com.serverpc.ssh-control" from "/etc/pf.anchors/com.serverpc.ssh-control"
    # END SERVERPC SSH CONTROL

    """

    init() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        pfConfig = root.appendingPathComponent("pf.conf")
        anchor = root.appendingPathComponent("anchor.conf")
        validator = FilePFInstallationValidator(
            pfConfigurationURL: pfConfig,
            anchorURL: anchor,
            expectedOwnerUID: getuid()
        )
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    func writeValidFiles() throws {
        try writePFConfig(validConfig)
        try Data("block drop in quick proto tcp from any to any port 22\n".utf8).write(to: anchor)
        XCTAssertEqual(chmod(anchor.path, 0o600), 0)
    }

    func writePFConfig(_ text: String) throws {
        try Data(text.utf8).write(to: pfConfig)
        XCTAssertEqual(chmod(pfConfig.path, 0o600), 0)
    }
}
