import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class FixedCommandRunnerTests: XCTestCase {
    func testEveryCommandUsesAnApprovedAbsoluteExecutable() throws {
        let commands: [FixedCommand] = [
            .pfStatus,
            .pfEnable,
            .pfReadAnchor,
            .sshdEffectiveConfiguration,
            .lsofEstablishedSSH,
            .launchctlPrint(.screenSharing),
            .enforcerStatus
        ]

        XCTAssertEqual(
            try commands.map { try $0.specification().executable },
            ["/sbin/pfctl", "/sbin/pfctl", "/sbin/pfctl", "/usr/sbin/sshd", "/usr/sbin/lsof", "/bin/launchctl", "/bin/launchctl"]
        )
    }

    func testPolicyFileRejectsPathsOutsideRootStateDirectory() {
        XCTAssertThrowsError(try PolicyFile(path: "/tmp/rules.conf")) { error in
            XCTAssertEqual(error as? FixedCommandError, .invalidPolicyPath)
        }
    }

    func testLaunchctlLabelsAreClosedEnumValues() throws {
        let specification = try FixedCommand.launchctlPrint(.remoteManagement).specification()
        XCTAssertEqual(
            specification.arguments,
            ["print", "system/com.apple.RemoteDesktop.PrivilegeProxy"]
        )
    }

    func testCommandResultNeverExceedsConfiguredLimit() {
        XCTAssertEqual(SystemFixedCommandRunner.maximumOutputBytes, 64 * 1_024)
        XCTAssertEqual(SystemFixedCommandRunner.fixedEnvironment.keys.sorted(), ["LANG", "LC_ALL", "PATH"])
    }
}
