import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class RemoteControlDetectorTests: XCTestCase {
    func testSupportedScreenSharingBlocksWhenSettingEnabled() async throws {
        let detector = RemoteControlDetector(
            runner: RemoteServiceRunner(active: [.screenSharing]),
            processes: StaticRemoteProcessSource(paths: [])
        )

        let result = try await detector.detect(localConsoleOnly: true)

        XCTAssertEqual(result.enforcement, .denyOpen)
        XCTAssertEqual(result.detectedIdentifiers, [KnownLaunchService.screenSharing.rawValue])
    }

    func testDetectionIsAuditOnlyWhenSettingDisabled() async throws {
        let detector = RemoteControlDetector(
            runner: RemoteServiceRunner(active: [.remoteManagement]),
            processes: StaticRemoteProcessSource(paths: [])
        )

        let result = try await detector.detect(localConsoleOnly: false)

        XCTAssertEqual(result.enforcement, .auditOnly)
        XCTAssertFalse(result.detectedIdentifiers.isEmpty)
    }

    func testRegisteredButNotRunningScreenSharingDoesNotBlockSSH() async throws {
        let detector = RemoteControlDetector(
            runner: RemoteServiceRunner(registeredButNotRunning: [.screenSharing]),
            processes: StaticRemoteProcessSource(paths: [])
        )

        let result = try await detector.detect(localConsoleOnly: true)

        XCTAssertEqual(result.enforcement, .none)
        XCTAssertEqual(result.detectedIdentifiers, [])
    }

    func testReviewedRemoteProcessPathIsDetectedWithoutCallerInput() async throws {
        let path = RemoteControlDetector.reviewedExecutablePaths[0]
        let detector = RemoteControlDetector(
            runner: RemoteServiceRunner(active: []),
            processes: StaticRemoteProcessSource(paths: [path, "/tmp/not-reviewed"])
        )

        let result = try await detector.detect(localConsoleOnly: true)

        XCTAssertEqual(result.enforcement, .denyOpen)
        XCTAssertEqual(result.detectedIdentifiers, [path])
    }
}

private actor RemoteServiceRunner: CommandRunning {
    let active: Set<KnownLaunchService>
    let registeredButNotRunning: Set<KnownLaunchService>

    init(
        active: Set<KnownLaunchService> = [],
        registeredButNotRunning: Set<KnownLaunchService> = []
    ) {
        self.active = active
        self.registeredButNotRunning = registeredButNotRunning
    }

    func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        guard case .launchctlPrint(let service) = command else { throw ControlErrorCode.internalFailure }
        let output: Data
        let status: Int32
        if active.contains(service) {
            output = Data("state = running\n".utf8)
            status = 0
        } else if registeredButNotRunning.contains(service) {
            output = Data("state = not running\n".utf8)
            status = 0
        } else {
            output = Data()
            status = 113
        }
        return BoundedCommandResult(
            terminationStatus: status,
            standardOutput: output,
            standardError: Data(),
            outputWasTruncated: false
        )
    }
}

private struct StaticRemoteProcessSource: RemoteProcessSourcing {
    let paths: [String]
    func runningExecutablePaths() -> [String] { paths }
}
