import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class SSHPolicyValidatorTests: XCTestCase {
    func testPolicyRequiresPublicKeyOnlyAuthentication() async throws {
        let validator = SSHPolicyValidator(runner: PolicyCommandRunner.returning(
            "passwordauthentication no\n" +
                "kbdinteractiveauthentication no\n" +
                "pubkeyauthentication yes\n" +
                "permitrootlogin no\n" +
                "port 22\n"
        ))

        let result = try await validator.validate()
        XCTAssertTrue(result.isSafe)
        XCTAssertNil(result.reason)
    }

    func testPolicyRejectsRootLoginBecauseRootSessionProofIsAmbiguous() async throws {
        let validator = SSHPolicyValidator(runner: PolicyCommandRunner.returning(
            "passwordauthentication no\n" +
                "kbdinteractiveauthentication no\n" +
                "pubkeyauthentication yes\n" +
                "permitrootlogin yes\n" +
                "port 22\n"
        ))

        let result = try await validator.validate()
        XCTAssertFalse(result.isSafe)
        XCTAssertEqual(result.reason, .unsafeSSHPolicy)
    }

    func testPolicyRejectsPasswordAuthentication() async throws {
        let validator = SSHPolicyValidator(runner: PolicyCommandRunner.returning(
            "passwordauthentication yes\n" +
                "kbdinteractiveauthentication no\n" +
                "pubkeyauthentication yes\n" +
                "permitrootlogin no\n" +
                "port 22\n"
        ))

        let result = try await validator.validate()
        XCTAssertFalse(result.isSafe)
        XCTAssertEqual(result.reason, .unsafeSSHPolicy)
    }

    func testPolicyRejectsMissingDuplicateAndTruncatedSettings() async throws {
        let duplicate = PolicyCommandRunner.returning(
            "passwordauthentication no\npasswordauthentication yes\n" +
                "kbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\nport 22\n"
        )
        let missing = PolicyCommandRunner.returning(
            "passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\n"
        )
        let truncated = PolicyCommandRunner.returning(
            "passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin no\nport 22\n",
            truncated: true
        )

        for runner in [duplicate, missing, truncated] {
            let result = try await SSHPolicyValidator(runner: runner).validate()
            XCTAssertEqual(result.reason, .unsafeSSHPolicy)
        }
    }
}

private actor PolicyCommandRunner: CommandRunning {
    let result: BoundedCommandResult

    init(result: BoundedCommandResult) { self.result = result }

    static func returning(_ output: String, truncated: Bool = false) -> PolicyCommandRunner {
        PolicyCommandRunner(result: BoundedCommandResult(
            terminationStatus: 0,
            standardOutput: Data(output.utf8),
            standardError: Data(),
            outputWasTruncated: truncated
        ))
    }

    func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        XCTAssertEqual(command, .sshdEffectiveConfiguration)
        return result
    }
}
