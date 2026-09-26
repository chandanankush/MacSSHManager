import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class PFControllerTests: XCTestCase {
    func testOpenLANOnlyTouchesOnlyDedicatedAnchorAndVerifiesReadback() async throws {
        let rules = try PFRuleBuilder().openRules(.lanOnly)
        let runner = RecordingCommandRunner(results: [
            .success(),
            .success(),
            .success(output: rules)
        ])
        let writer = RecordingPolicyWriter()
        let policy = try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf")
        let controller = PFController(
            runner: runner,
            writer: writer,
            policyFile: policy,
            installation: ValidPFInstallation()
        )

        try await controller.open(for: .lanOnly)

        let commands = await runner.commands
        XCTAssertEqual(commands, [.pfSyntax(policy), .pfLoad(policy), .pfReadAnchor])
        XCTAssertEqual(writer.writes, [rules])
    }

    func testOpenTailscaleOnlySucceedsAgainstRealPfctlHostAddressRendering() async throws {
        // Captured verbatim from a live `pfctl -a <anchor> -sr` readback:
        // pfctl renders both the `port 22` test as `port = 22` and a /32
        // destination as a bare host address with no explicit mask.
        let liveReadback = "pass in quick on utun8 inet proto tcp from 100.64.0.0/10 to 100.103.228.109 " +
            "port = 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port = 22\n"
        let snapshot = try SSHAccessNetworkSnapshot(
            scope: .tailscale,
            lan: nil,
            tailscale: TailscaleSnapshot(interfaceName: "utun8", addressCIDR: "100.103.228.109/32")
        )
        let runner = RecordingCommandRunner(results: [.success(), .success(), .success(output: liveReadback)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        try await controller.open(for: snapshot)
    }

    func testOpenTailscaleOnlyWritesNarrowlyScopedPassRule() async throws {
        let rules = try PFRuleBuilder().openRules(.tailscaleOnly)
        let runner = RecordingCommandRunner(results: [
            .success(), .success(), .success(output: rules), .success(output: rules)
        ])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        try await controller.open(for: .tailscaleOnly)

        let rulesReturned = try await controller.effectiveNetworkRules()
        XCTAssertNil(rulesReturned?.lanInterfaceName)
        XCTAssertEqual(rulesReturned?.tailscaleInterfaceName, "utun6")
        XCTAssertEqual(rulesReturned?.tailscaleAddressCIDR, "100.101.102.103/32")
    }

    func testOpenLANAndTailscaleVerifiesBothPathsPresent() async throws {
        let rules = try PFRuleBuilder().openRules(.lanAndTailscale)
        let runner = RecordingCommandRunner(results: [
            .success(), .success(), .success(output: rules), .success(output: rules)
        ])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        try await controller.open(for: .lanAndTailscale)

        let rulesReturned = try await controller.effectiveNetworkRules()
        XCTAssertEqual(rulesReturned?.lanInterfaceName, "en0")
        XCTAssertEqual(rulesReturned?.tailscaleInterfaceName, "utun6")
    }

    func testOpenFailsClosedWhenReadbackDriftsFromWhatWasWritten() async throws {
        let unrelated = try PFRuleBuilder().openRules(.init(
            scope: .lan,
            lan: LANSnapshot(interfaceName: "en9", sourceCIDR: "10.0.0.0/24", isPrivate: true),
            tailscale: nil
        ))
        let runner = RecordingCommandRunner(results: [
            .success(),
            .success(),
            .success(output: unrelated),
            .success(output: "Status: Enabled\n"),
            .success(),
            .success(),
            .success(output: PFRuleBuilder().closedRules()),
            .success(output: "Status: Enabled\n"),
            .success(output: PFRuleBuilder().closedRules())
        ])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.open(for: .lanOnly))
    }

    func testOpenFailureImmediatelyAttemptsClosedRules() async throws {
        let runner = RecordingCommandRunner(results: [
            .success(status: 1),
            .success(output: "Status: Enabled\n"),
            .success(),
            .success(),
            .success(output: PFRuleBuilder().closedRules()),
            .success(output: "Status: Enabled\n"),
            .success(output: PFRuleBuilder().closedRules())
        ])
        let writer = RecordingPolicyWriter()
        let policy = try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf")
        let controller = PFController(
            runner: runner,
            writer: writer,
            policyFile: policy,
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.open(for: .lanOnly))

        let commands = await runner.commands
        XCTAssertEqual(writer.writes.last, PFRuleBuilder().closedRules())
        XCTAssertEqual(commands.last, .pfReadAnchor)
    }

    func testEnforceClosedEnablesPFWhenItIsDisabledAndVerifiesHealth() async throws {
        let closed = PFRuleBuilder().closedRules()
        let runner = RecordingCommandRunner(results: [
            .success(output: "Status: Disabled\n"),
            .success(),
            .success(output: "Status: Enabled\n"),
            .success(),
            .success(),
            .success(output: closed),
            .success(output: "Status: Enabled\n"),
            .success(output: closed)
        ])
        let policy = try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf")
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: policy,
            installation: ValidPFInstallation()
        )

        try await controller.enforceClosed()

        let commands = await runner.commands
        XCTAssertEqual(
            commands,
            [.pfStatus, .pfEnable, .pfStatus, .pfSyntax(policy), .pfLoad(policy), .pfReadAnchor, .pfStatus, .pfReadAnchor]
        )
    }

    func testStartupAlreadyEnabledLoadsOnlyApplicationAnchor() async throws {
        let closed = PFRuleBuilder().closedRules()
        let runner = RecordingCommandRunner(results: startupSuccessResults(closed: closed))
        let policy = try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf")
        let controller = PFController(runner: runner, writer: RecordingPolicyWriter(), policyFile: policy,
                                      installation: ValidPFInstallation(), startupRetryDelays: [0])

        await controller.recoverAtStartup()

        let state = await controller.startupState()
        let commands = await runner.commands
        XCTAssertEqual(state, .ready)
        XCTAssertFalse(commands.contains(.pfEnable))
        XCTAssertEqual(commands.filter { $0 == .pfLoad(policy) }.count, 1)
    }

    func testStartupEnableFailureReachesBoundedFailure() async throws {
        let runner = RecordingCommandRunner(results: [
            .success(output: "Status: Disabled\n"), .success(status: 1)
        ])
        let controller = PFController(runner: runner, writer: RecordingPolicyWriter(),
                                      policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
                                      installation: ValidPFInstallation(), startupRetryDelays: [0])

        await controller.recoverAtStartup()

        let state = await controller.startupState()
        XCTAssertEqual(state, .failed(.pfEnableFailed))
    }

    func testStartupRejectsEnableSuccessWhenPFRemainsDisabled() async throws {
        let runner = RecordingCommandRunner(results: [
            .success(output: "Status: Disabled\n"), .success(output: "Token : 42\n"),
            .success(output: "Status: Disabled\n")
        ])
        let controller = PFController(runner: runner, writer: RecordingPolicyWriter(),
                                      policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
                                      installation: ValidPFInstallation(), startupRetryDelays: [0])

        await controller.recoverAtStartup()

        let state = await controller.startupState()
        XCTAssertEqual(state, .failed(.pfEnableUnverified))
    }

    func testStartupSucceedsAfterRetry() async throws {
        let closed = PFRuleBuilder().closedRules()
        let runner = RecordingCommandRunner(results: [.success(status: 1)] + startupSuccessResults(closed: closed))
        let controller = PFController(runner: runner, writer: RecordingPolicyWriter(),
                                      policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
                                      installation: ValidPFInstallation(), startupRetryDelays: [0, 0])

        await controller.recoverAtStartup()

        let state = await controller.startupState()
        XCTAssertEqual(state, .ready)
    }

    func testAnchorLoadAndValidationFailuresAreDistinct() async throws {
        let policy = try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf")
        let loadRunner = RecordingCommandRunner(results: [
            .success(output: "Status: Enabled\n"), .success(), .success(status: 1)
        ])
        let loadController = PFController(runner: loadRunner, writer: RecordingPolicyWriter(), policyFile: policy,
                                          installation: ValidPFInstallation(), startupRetryDelays: [0])
        await loadController.recoverAtStartup()
        let loadState = await loadController.startupState()
        XCTAssertEqual(loadState, .failed(.pfRulesLoadFailed))

        let validationRunner = RecordingCommandRunner(results: [
            .success(output: "Status: Enabled\n"), .success(), .success(), .success(output: "pass in all\n")
        ])
        let validationController = PFController(runner: validationRunner, writer: RecordingPolicyWriter(), policyFile: policy,
                                                installation: ValidPFInstallation(), startupRetryDelays: [0])
        await validationController.recoverAtStartup()
        let validationState = await validationController.startupState()
        XCTAssertEqual(validationState, .failed(.pfAnchorValidationFailed))
    }

    func testEffectiveModeRejectsUnexpectedAnchorText() async throws {
        let runner = RecordingCommandRunner(results: [.success(output: "pass in all\n")])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }

    func testEffectiveModeAcceptsPfctlExplicitPortEqualityFormatting() async throws {
        let output = "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port = 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port = 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: output)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        let mode = try await controller.effectiveMode()
        XCTAssertEqual(mode, .open)
    }

    func testEffectiveNetworkRulesNormalizesPfctlsBareHostDestination() async throws {
        let liveReadback = "pass in quick on utun8 inet proto tcp from 100.64.0.0/10 to 100.103.228.109 " +
            "port = 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port = 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: liveReadback)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        let rules = try await controller.effectiveNetworkRules()
        XCTAssertEqual(rules?.tailscaleInterfaceName, "utun8")
        XCTAssertEqual(rules?.tailscaleAddressCIDR, "100.103.228.109/32")
    }

    func testEffectiveNetworkRulesReturnsNilWhenClosed() async throws {
        let runner = RecordingCommandRunner(results: [.success(output: PFRuleBuilder().closedRules())])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        let rules = try await controller.effectiveNetworkRules()
        XCTAssertNil(rules)
    }

    func testReadbackRejectsReorderedLANAndTailscaleRules() async throws {
        let tailscaleFirst = "pass in quick on utun6 inet proto tcp from 100.64.0.0/10 to 100.101.102.103/32 " +
            "port 22 flags S/SA keep state\n" +
            "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: tailscaleFirst)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }

    func testReadbackRejectsDuplicateLANShapedRules() async throws {
        let duplicated = "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
            "pass in quick on en1 inet proto tcp from 10.0.0.0/24 to any port 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: duplicated)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }

    func testReadbackRejectsUnrecognizedVirtualInterfacePassRule() async throws {
        let bridged = "pass in quick on bridge0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: bridged)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }

    func testReadbackRejectsTailscaleShapedRuleWithUnexpectedSourceCIDR() async throws {
        let widened = "pass in quick on utun6 inet proto tcp from 100.64.0.0/11 to 100.101.102.103/32 " +
            "port 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: widened)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }

    func testReadbackRejectsThreeOrMorePassRules() async throws {
        let tooMany = "pass in quick on en0 inet proto tcp from 192.168.50.0/24 to any port 22 flags S/SA keep state\n" +
            "pass in quick on utun6 inet proto tcp from 100.64.0.0/10 to 100.101.102.103/32 " +
            "port 22 flags S/SA keep state\n" +
            "pass in quick on utun7 inet proto tcp from 100.64.0.0/10 to 100.101.102.104/32 " +
            "port 22 flags S/SA keep state\n" +
            "block drop in quick proto tcp from any to any port 22\n"
        let runner = RecordingCommandRunner(results: [.success(output: tooMany)])
        let controller = PFController(
            runner: runner,
            writer: RecordingPolicyWriter(),
            policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
            installation: ValidPFInstallation()
        )

        await XCTAssertThrowsErrorAsync(try await controller.effectiveMode())
    }
}

private struct ValidPFInstallation: PFInstallationValidating {
    func isValid() -> Bool { true }
}

private actor RecordingCommandRunner: CommandRunning {
    private(set) var commands: [FixedCommand] = []
    private var results: [BoundedCommandResult]

    init(results: [BoundedCommandResult]) {
        self.results = results
    }

    func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        commands.append(command)
        guard !results.isEmpty else { throw ControlErrorCode.pfUnavailable }
        return results.removeFirst()
    }
}

private final class RecordingPolicyWriter: PFPolicyWriting, @unchecked Sendable {
    private let lock = NSLock()
    private var storedWrites: [String] = []

    var writes: [String] { lock.withLock { storedWrites } }

    func write(_ rules: String, to policyFile: PolicyFile) throws {
        lock.withLock { storedWrites.append(rules) }
    }
}

private extension BoundedCommandResult {
    static func success(status: Int32 = 0, output: String = "") -> Self {
        BoundedCommandResult(
            terminationStatus: status,
            standardOutput: Data(output.utf8),
            standardError: Data(),
            outputWasTruncated: false
        )
    }
}

private func startupSuccessResults(closed: String) -> [BoundedCommandResult] {
    [
        .success(output: "Status: Enabled\n"),
        .success(),
        .success(),
        .success(output: closed),
        .success(output: "Status: Enabled\n"),
        .success(output: closed)
    ]
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {}
}
