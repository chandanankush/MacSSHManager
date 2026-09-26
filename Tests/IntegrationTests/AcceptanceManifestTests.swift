import Foundation
import XCTest

final class AcceptanceManifestTests: XCTestCase {
    func testCloseOnlyHelperRunsItsAsyncWorkOffTheBlockedMainThread() throws {
        let helper = try repositoryFile("Sources/ExpiryEnforcer/main.swift")
        XCTAssertTrue(helper.contains("Task.detached"))
    }

    func testEveryApprovedPhysicalGateHasAnInstruction() throws {
        let readme = try repositoryFile("docs/SECURITY_AND_OPERATIONS.md")
        for heading in [
            "Install from the attached console",
            "Verify CLOSED before login",
            "Exercise expiry",
            "Exercise crash recovery",
            "Rollback"
        ] {
            XCTAssertTrue(readme.contains(heading), "Missing acceptance instruction: \(heading)")
        }
    }

    private func repositoryFile(_ relativePath: String) throws -> String {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(contentsOf: repository.appendingPathComponent(relativePath), encoding: .utf8)
    }
}
