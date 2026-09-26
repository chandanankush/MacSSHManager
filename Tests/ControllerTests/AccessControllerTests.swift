import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class AccessControllerTests: XCTestCase {
    func testRecoveryClosureOfActiveWindowIsAuditedOnce() async throws {
        let fixture = ControllerFixture()
        _ = try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)
        XCTAssertEqual(fixture.firewall.mode, .closed)
        XCTAssertEqual(fixture.audit.kinds.filter { $0 == .recoveredClosed }.count, 1)
    }

    func testSuccessfulRecoveryAuditIsRetriedAfterAuditWriteFailure() async throws {
        let fixture = ControllerFixture()
        _ = try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        fixture.audit.failNextWrite()
        let first = await fixture.controller.close(trigger: .recovery)
        XCTAssertEqual(first.reason, .auditUnavailable)
        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)
        XCTAssertEqual(fixture.audit.kinds.filter { $0 == .recoveredClosed }.count, 1)
    }

    func testHealthyReconciliationDoesNotCreateRecoveryAuditEvents() async {
        let fixture = ControllerFixture()
        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)
        XCTAssertTrue(fixture.audit.kinds.isEmpty)
    }

    func testRecoveryDoesNotHideIncompleteSessionTermination() async {
        let fixture = ControllerFixture(incompleteSessions: true)
        let recovered = await fixture.controller.recoverSecurityService()
        XCTAssertEqual(recovered.mode, .degradedClosed)
        XCTAssertEqual(recovered.reason, .terminationIncomplete)
        let refreshed = await fixture.controller.status()
        XCTAssertEqual(refreshed.mode, .degradedClosed)
        await XCTAssertThrowsErrorAsync(
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        )
        XCTAssertEqual(fixture.authorization.calls, 0)
    }

    func testRetryInvalidatesInFlightOpen() async throws {
        let gate = SuspendedPolicy()
        let fixture = ControllerFixture(sshPolicy: gate)
        let pending = Task {
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        }
        await gate.waitUntilStarted()
        let recovered = await fixture.controller.recoverSecurityService()
        XCTAssertEqual(recovered.mode, .closed)
        await gate.resume()
        do {
            _ = try await pending.value
            XCTFail("An Open started before recovery must not reopen after verified CLOSED")
        } catch {}
        XCTAssertEqual(fixture.firewall.mode, .closed)
    }

    func testRecoveryRemovesActiveLeaseAndTerminatesSessionsBeforeRetryingPF() async throws {
        let gate = SuspendedRecovery()
        let fixture = ControllerFixture(recoveryGate: gate)
        _ = try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        let recovery = Task { await fixture.controller.recoverSecurityService() }
        await gate.waitUntilStarted()
        XCTAssertNil(try fixture.lease.load())
        XCTAssertTrue(fixture.recorder.events.contains(.terminateSessions))
        await gate.resume()
        let status = await recovery.value
        XCTAssertEqual(status.mode, .closed)
    }

    func testOpenIsRejectedThroughoutRecovery() async {
        let gate = SuspendedRecovery()
        let fixture = ControllerFixture(recoveryGate: gate)
        let recovery = Task { await fixture.controller.recoverSecurityService() }
        await gate.waitUntilStarted()
        let status = await fixture.controller.status()
        XCTAssertEqual(status.mode, .recovering)
        await XCTAssertThrowsErrorAsync(
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        )
        XCTAssertEqual(fixture.authorization.calls, 0)
        await gate.resume()
        _ = await recovery.value
    }

    func testOpenPersistsLeaseBeforeLoadingAllowRule() async throws {
        let fixture = ControllerFixture()

        _ = try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())

        XCTAssertEqual(fixture.recorder.events, [
            .validate,
            .auditAuthorized,
            .saveLease,
            .firewallOpen,
            .verifyOpen,
            .auditOpened
        ])
        XCTAssertEqual(fixture.lease.savedLeases.last?.scope, .lan)
        XCTAssertEqual(fixture.lease.savedLeases.last?.lanInterfaceName, "en0")
        XCTAssertNil(fixture.lease.savedLeases.last?.tailscaleInterfaceName)
    }

    func testOpenWithTailscaleOnlyNeverResolvesLAN() async throws {
        let fixture = ControllerFixture(lan: ThrowingLAN())

        let status = try await fixture.controller.open(
            .minutes30,
            scope: .tailscale,
            authorization: Data([1]),
            nonce: UUID()
        )

        XCTAssertEqual(status.networkScope, .tailscale)
        XCTAssertEqual(fixture.lease.savedLeases.last?.tailscaleInterfaceName, "utun6")
        XCTAssertNil(fixture.lease.savedLeases.last?.lanInterfaceName)
    }

    func testOpenWithLANAndTailscaleResolvesAndPersistsBoth() async throws {
        let fixture = ControllerFixture()

        _ = try await fixture.controller.open(
            .minutes30,
            scope: .lanAndTailscale,
            authorization: Data([1]),
            nonce: UUID()
        )

        let saved = fixture.lease.savedLeases.last
        XCTAssertEqual(saved?.scope, .lanAndTailscale)
        XCTAssertEqual(saved?.lanInterfaceName, "en0")
        XCTAssertEqual(saved?.tailscaleInterfaceName, "utun6")
    }

    func testOpenFailsClosedWhenTailscaleUnavailableAndDoesNotFallBackToLAN() async {
        let fixture = ControllerFixture(tailscale: ThrowingTailscale())

        await XCTAssertThrowsErrorAsync(
            try await fixture.controller.open(
                .minutes30,
                scope: .tailscale,
                authorization: Data([1]),
                nonce: UUID()
            )
        )

        XCTAssertTrue(fixture.lease.savedLeases.isEmpty)
        XCTAssertEqual(fixture.firewall.mode, .closed)
    }

    func testCloseBlocksBeforeTerminatingSessionsAndRemovingLease() async {
        let fixture = ControllerFixture()

        _ = await fixture.controller.close(trigger: .manual)

        XCTAssertEqual(Array(fixture.recorder.events.prefix(4)), [
            .firewallClosed,
            .verifyClosed,
            .terminateSessions,
            .removeLease
        ])
    }

    func testAnyOpenFailureRestoresClosedAndRemovesLease() async {
        let fixture = ControllerFixture(failingOpen: true)

        await XCTAssertThrowsErrorAsync(
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        )

        XCTAssertTrue(fixture.recorder.events.contains(.firewallClosed))
        XCTAssertTrue(fixture.recorder.events.contains(.removeLease))
        XCTAssertEqual(fixture.firewall.mode, .closed)
    }

    func testExtensionReplacesDeadlineAndRequiresFreshAuthorization() async throws {
        let fixture = ControllerFixture()
        _ = try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        fixture.clock.uptime = 1_100
        fixture.clock.date = Date(timeIntervalSince1970: 2_000)

        _ = try await fixture.controller.open(.hours3, scope: .lan, authorization: Data([2]), nonce: UUID())

        XCTAssertEqual(fixture.authorization.calls, 2)
        XCTAssertEqual(fixture.lease.savedLeases.last?.duration, .hours3)
        XCTAssertEqual(fixture.lease.savedLeases.last?.deadlineUptime, 11_900)
    }

    func testDisablingLocalConsoleRequiresAuthorizationAndAudit() async throws {
        let fixture = ControllerFixture(localConsoleOnly: true)

        _ = try await fixture.controller.setLocalConsoleOnly(
            false,
            authorization: Data([3]),
            nonce: UUID()
        )

        XCTAssertEqual(fixture.authorization.actions.last, .disableLocalConsoleOnly)
        XCTAssertFalse(fixture.settings.value.localConsoleOnly)
        XCTAssertTrue(fixture.audit.kinds.contains(.settingChanged))
    }

    func testCloseDuringOpenInvalidatesOlderTransitionAndEndsClosed() async {
        let gate = SuspendedPolicy()
        let fixture = ControllerFixture(sshPolicy: gate)
        let openTask = Task {
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        }
        await gate.waitUntilStarted()

        _ = await fixture.controller.close(trigger: .manual)
        await gate.resume()
        do {
            _ = try await openTask.value
            XCTFail("The superseded OPEN should fail")
        } catch {}

        XCTAssertEqual(fixture.firewall.mode, .closed)
    }

    func testOpenFailsClosedWhenIndependentEnforcerIsUnavailable() async {
        let fixture = ControllerFixture(enforcerHealth: UnhealthyEnforcer())

        await XCTAssertThrowsErrorAsync(
            try await fixture.controller.open(.minutes30, scope: .lan, authorization: Data([1]), nonce: UUID())
        )

        XCTAssertTrue(fixture.lease.savedLeases.isEmpty)
        XCTAssertEqual(fixture.firewall.mode, .closed)
    }

    func testDuplicateRecoveryFailuresAreCoalescedAndHealthyTransitionIsRecordedOnce() async {
        let fixture = ControllerFixture(failingClose: true)

        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)
        XCTAssertEqual(fixture.audit.kinds.filter { $0 == .recoveredClosed }.count, 1)

        fixture.firewall.setFailingClose(false)
        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)
        XCTAssertEqual(fixture.audit.kinds.filter { $0 == .recoveredClosed }.count, 2)
    }

    func testRecoveryIncidentIsRetriedWhenFirstAuditWriteFails() async {
        let fixture = ControllerFixture(failingClose: true, auditFailures: 1)

        _ = await fixture.controller.close(trigger: .recovery)
        _ = await fixture.controller.close(trigger: .recovery)

        XCTAssertEqual(fixture.audit.kinds.filter { $0 == .recoveredClosed }.count, 1)
    }
}

private enum RecordedOperation: Equatable {
    case validate, auditAuthorized, saveLease, firewallOpen, verifyOpen, auditOpened
    case firewallClosed, verifyClosed, terminateSessions, removeLease
}

private final class OperationRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [RecordedOperation] = []
    var events: [RecordedOperation] { lock.withLock { stored } }
    func append(_ event: RecordedOperation) { lock.withLock { stored.append(event) } }
}

private final class ControllerFixture: @unchecked Sendable {
    let recorder = OperationRecorder()
    let authorization: FakeAuthorization
    let audit: FakeAudit
    let lease: FakeLeaseStore
    let firewall: FakeFirewall
    let settings: FakeSettingsStore
    let clock = MutableClock()
    let controller: AccessController

    init(
        failingOpen: Bool = false,
        failingClose: Bool = false,
        auditFailures: Int = 0,
        recoveryGate: SuspendedRecovery? = nil,
        incompleteSessions: Bool = false,
        localConsoleOnly: Bool = false,
        sshPolicy: any SSHPolicyValidating = SafePolicy(),
        enforcerHealth: any EnforcerHealthChecking = HealthyEnforcer(),
        lan: any LANResolving = StaticLAN(),
        tailscale: any TailscaleResolving = StaticTailscale()
    ) {
        authorization = FakeAuthorization(recorder: recorder)
        audit = FakeAudit(recorder: recorder, failuresRemaining: auditFailures)
        lease = FakeLeaseStore(recorder: recorder)
        firewall = FakeFirewall(recorder: recorder, failingOpen: failingOpen, failingClose: failingClose, recoveryGate: recoveryGate)
        settings = FakeSettingsStore(value: SecuritySettings(localConsoleOnly: localConsoleOnly))
        controller = AccessController(
            authorization: authorization,
            audit: audit,
            leases: lease,
            firewall: firewall,
            sshPolicy: sshPolicy,
            sessions: FakeSessions(recorder: recorder, complete: !incompleteSessions),
            lan: lan,
            tailscale: tailscale,
            settings: settings,
            remoteControl: NoRemoteControl(),
            enforcerHealth: enforcerHealth,
            continuousClock: clock,
            wallClock: clock
        )
    }
}

private final class FakeAuthorization: AuthorizationValidating, @unchecked Sendable {
    private let recorder: OperationRecorder
    private let lock = NSLock()
    private(set) var calls = 0
    private(set) var actions: [AuthorizationAction] = []
    init(recorder: OperationRecorder) { self.recorder = recorder }
    func consume(form: Data, nonce: UUID, action: AuthorizationAction) throws {
        lock.withLock { calls += 1; actions.append(action) }
        recorder.append(.validate)
    }
}

private final class FakeAudit: AuditLogging, @unchecked Sendable {
    private let recorder: OperationRecorder
    private let lock = NSLock()
    private(set) var kinds: [AuditEvent.Kind] = []
    private var failuresRemaining: Int
    init(recorder: OperationRecorder, failuresRemaining: Int = 0) {
        self.recorder = recorder
        self.failuresRemaining = failuresRemaining
    }
    func failNextWrite() { lock.withLock { failuresRemaining += 1 } }
    func record(_ event: AuditEvent) throws {
        let shouldFail = lock.withLock { () -> Bool in
            guard failuresRemaining > 0 else {
                kinds.append(event.kind)
                return false
            }
            failuresRemaining -= 1
            return true
        }
        if shouldFail { throw ControlErrorCode.auditUnavailable }
        if event.kind == .openRequested { recorder.append(.auditAuthorized) }
        if event.kind == .opened { recorder.append(.auditOpened) }
    }
}

private final class FakeLeaseStore: LeaseStoring, @unchecked Sendable {
    private let recorder: OperationRecorder
    private let lock = NSLock()
    private(set) var savedLeases: [Lease] = []
    private var currentLease: Lease?
    init(recorder: OperationRecorder) { self.recorder = recorder }
    func load() throws -> Lease? { lock.withLock { currentLease } }
    func save(_ lease: Lease) throws { lock.withLock { savedLeases.append(lease); currentLease = lease }; recorder.append(.saveLease) }
    func remove() throws { lock.withLock { currentLease = nil }; recorder.append(.removeLease) }
    func currentState() throws -> LeaseState { try load().map(LeaseState.active) ?? .absent }
}

private final class FakeFirewall: FirewallControlling, @unchecked Sendable {
    private let recorder: OperationRecorder
    private let failingOpen: Bool
    private let lock = NSLock()
    private var storedMode: FirewallMode = .closed
    private var failingClose: Bool
    private let recoveryGate: SuspendedRecovery?
    var mode: FirewallMode { lock.withLock { storedMode } }
    init(recorder: OperationRecorder, failingOpen: Bool, failingClose: Bool = false, recoveryGate: SuspendedRecovery? = nil) {
        self.recorder = recorder
        self.failingOpen = failingOpen
        self.failingClose = failingClose
        self.recoveryGate = recoveryGate
    }
    func health() async -> FirewallHealth { FirewallHealth(pfEnabled: true, mode: mode) }
    func enforceClosed() async throws {
        recorder.append(.firewallClosed)
        if lock.withLock({ failingClose }) { throw ControlErrorCode.pfUnavailable }
        lock.withLock { storedMode = .closed }
    }
    func recoverAtStartup() async {
        await recoveryGate?.suspend()
        try? await enforceClosed()
    }
    func setFailingClose(_ value: Bool) { lock.withLock { failingClose = value } }
    func open(for snapshot: SSHAccessNetworkSnapshot) async throws {
        recorder.append(.firewallOpen)
        if failingOpen { throw ControlErrorCode.pfUnavailable }
        lock.withLock { storedMode = .open }
    }
    func effectiveMode() async throws -> FirewallMode {
        recorder.append(mode == .open ? .verifyOpen : .verifyClosed)
        return mode
    }
    func effectiveNetworkRules() async throws -> EffectiveNetworkRules? { nil }
}

private struct SafePolicy: SSHPolicyValidating {
    func validate() async throws -> SSHPolicyEvaluation { .init(isSafe: true, reason: nil) }
}

private actor SuspendedPolicy: SSHPolicyValidating {
    private var started = false
    private var continuation: CheckedContinuation<Void, Never>?

    func validate() async throws -> SSHPolicyEvaluation {
        started = true
        await withCheckedContinuation { continuation = $0 }
        return .init(isSafe: true, reason: nil)
    }

    func waitUntilStarted() async {
        while !started { await Task.yield() }
    }

    func resume() {
        continuation?.resume()
        continuation = nil
    }
}

private struct FakeSessions: SSHSessionTerminating {
    let recorder: OperationRecorder
    var complete = true
    func terminateAll() async throws -> SSHSessionTerminationResult {
        recorder.append(.terminateSessions)
        return .init(complete: complete, signalledPIDs: [], remainingSessionCount: complete ? 0 : 1)
    }
}

private struct StaticLAN: LANResolving {
    func resolve() throws -> LANSnapshot { .init(interfaceName: "en0", sourceCIDR: "192.168.1.0/24", isPrivate: true) }
}

private struct ThrowingLAN: LANResolving {
    func resolve() throws -> LANSnapshot { throw ControlErrorCode.networkUnavailable }
}

private struct StaticTailscale: TailscaleResolving {
    func resolve() throws -> TailscaleSnapshot { .init(interfaceName: "utun6", addressCIDR: "100.101.102.103/32") }
}

private struct ThrowingTailscale: TailscaleResolving {
    func resolve() throws -> TailscaleSnapshot { throw ControlErrorCode.tailscaleUnavailable }
}

private final class FakeSettingsStore: SecuritySettingsStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: SecuritySettings
    init(value: SecuritySettings) { stored = value }
    var value: SecuritySettings { lock.withLock { stored } }
    func load() throws -> SecuritySettings { value }
    func save(_ settings: SecuritySettings) throws { lock.withLock { stored = settings } }
}

private struct NoRemoteControl: RemoteControlDetecting {
    func detect(localConsoleOnly: Bool) async throws -> RemoteControlDetection {
        .init(detectedIdentifiers: [], enforcement: .none)
    }
}

private struct HealthyEnforcer: EnforcerHealthChecking {
    func isHealthy() async -> Bool { true }
}
private struct UnhealthyEnforcer: EnforcerHealthChecking {
    func isHealthy() async -> Bool { false }
}

private final class MutableClock: ContinuousTimeProviding, WallClockProviding, @unchecked Sendable {
    var uptime: TimeInterval = 1_000
    var date = Date(timeIntervalSince1970: 1_000)
    var uptimeIncludingSleep: TimeInterval { uptime }
    var wallNow: Date { date }
    var bootSessionID: String { "boot-a" }
    func now() -> Date { date }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do { _ = try await expression(); XCTFail("Expected expression to throw", file: file, line: line) } catch {}
}

private actor SuspendedRecovery {
    private var started = false
    private var continuation: CheckedContinuation<Void, Never>?
    func suspend() async {
        started = true
        await withCheckedContinuation { continuation = $0 }
    }
    func waitUntilStarted() async {
        while !started { await Task.yield() }
    }
    func resume() {
        continuation?.resume()
        continuation = nil
    }
}
