import Darwin
import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class SSHSessionMonitorTests: XCTestCase {
    func testMonitorWritesOneConnectThenOneDisconnect() async {
        let session = SSHSession(identity: Data([1, 2, 3]), sshUser: "deploy", sourceAddress: "192.168.8.20")
        let source = SequenceSessionObserver(values: [[session], [session], []])
        let audit = SessionRecordingAudit()
        let monitor = SSHSessionMonitor(observer: source, audit: audit, now: { Date(timeIntervalSince1970: 1_000) })

        await monitor.reconcile()
        await monitor.reconcile()
        await monitor.reconcile()

        XCTAssertEqual(audit.events.map(\.kind), [.sshConnected, .sshDisconnected])
        XCTAssertEqual(audit.events.map(\.sshUser), ["deploy", "deploy"])
        XCTAssertEqual(audit.events.map(\.sourceAddress), ["192.168.8.20", "192.168.8.20"])
    }

    func testObserverReturnsOnlyValidatedNonRootSSHDWithNumericRemoteAddress() async throws {
        let runner = StaticSessionRunner(output: """
        p42
        csshd
        tIPv4
        n192.168.8.10:22->192.168.8.20:51234
        p43
        csshd
        tIPv4
        n192.168.8.10:22->host.example:51235
        p44
        csshd
        tIPv4
        n192.168.8.10:22->192.168.8.22:51236
        """)
        let processes = StaticSessionProcesses(values: [
            42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 501),
            43: .init(pid: 43, executablePath: "/usr/sbin/sshd", auditToken: Data([2]), effectiveUserID: 501),
            44: .init(pid: 44, executablePath: "/usr/bin/other", auditToken: Data([3]), effectiveUserID: 501),
        ])
        let observer = SystemSSHSessionObserver(
            runner: runner,
            processes: processes,
            usernames: StaticUsernameResolver(values: [501: "deploy"])
        )

        let sessions = try await observer.observe()

        XCTAssertEqual(sessions, [SSHSession(identity: Data([1]), sshUser: "deploy", sourceAddress: "192.168.8.20")])
    }

    func testObserverRejectsRootSocketOwnerAsUnauthenticated() async throws {
        let runner = StaticSessionRunner(output: "p42\ncsshd\ntIPv6\nn[fd00::1]:22->[fd00::2]:51234\n")
        let observer = SystemSSHSessionObserver(
            runner: runner,
            processes: StaticSessionProcesses(values: [
                42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 0),
            ]),
            usernames: StaticUsernameResolver(values: [0: "root"])
        )

        let sessions = try await observer.observe()
        XCTAssertEqual(sessions, [])
    }

    func testObserverRejectsMacOSSSHDPrivilegeSeparationAccount() async throws {
        let runner = StaticSessionRunner(output: "p42\ncsshd\ntIPv4\nn192.168.8.10:22->192.168.8.20:51234\n")
        let observer = SystemSSHSessionObserver(
            runner: runner,
            processes: StaticSessionProcesses(values: [
                42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 75),
            ]),
            usernames: StaticUsernameResolver(values: [75: "_sshd"])
        )

        let sessions = try await observer.observe()
        XCTAssertEqual(sessions, [])
    }

    func testObserverAllowsValidatedNonSSHDServiceAccount() async throws {
        let runner = StaticSessionRunner(output: "p42\ncsshd\ntIPv4\nn192.168.8.10:22->192.168.8.20:51234\n")
        let observer = SystemSSHSessionObserver(
            runner: runner,
            processes: StaticSessionProcesses(values: [
                42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 499),
            ]),
            usernames: StaticUsernameResolver(values: [499: "deploy-service"])
        )

        let sessions = try await observer.observe()
        XCTAssertEqual(sessions.map(\.sshUser), ["deploy-service"])
    }

    func testObserverCanonicalizesIPv6AddressForStableIdentity() async throws {
        let runner = StaticSessionRunner(output: "p42\ncsshd\ntIPv6\nn[fd00::1]:22->[FD00:0:0:0:0:0:0:2]:51234\n")
        let observer = SystemSSHSessionObserver(
            runner: runner,
            processes: StaticSessionProcesses(values: [
                42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 501),
            ]),
            usernames: StaticUsernameResolver(values: [501: "deploy"])
        )

        let sessions = try await observer.observe()
        XCTAssertEqual(sessions.map(\.sourceAddress), ["fd00::2"])
    }

    func testObserverDeduplicatesRepeatedSocketRows() async throws {
        let output = "p42\ncsshd\ntIPv4\nn192.168.8.10:22->192.168.8.20:51234\nn192.168.8.10:22->192.168.8.20:51234\n"
        let observer = SystemSSHSessionObserver(
            runner: StaticSessionRunner(output: output),
            processes: StaticSessionProcesses(values: [
                42: .init(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]), effectiveUserID: 501),
            ]),
            usernames: StaticUsernameResolver(values: [501: "deploy"])
        )

        let sessions = try await observer.observe()

        XCTAssertEqual(sessions.count, 1)
    }

    func testAuditFailureDoesNotRepeatOrBreakSessionObservation() async {
        let session = SSHSession(identity: Data([1]), sshUser: "deploy", sourceAddress: "192.168.8.20")
        let audit = FailingSessionAudit()
        let monitor = SSHSessionMonitor(
            observer: SequenceSessionObserver(values: [[session], [session]]),
            audit: audit
        )

        await monitor.reconcile()
        await monitor.reconcile()

        XCTAssertEqual(audit.recordAttempts, 1)
    }
}

private actor SequenceSessionObserver: SSHSessionObserving {
    private var values: [[SSHSession]]
    init(values: [[SSHSession]]) { self.values = values }
    func observe() async throws -> [SSHSession] { values.removeFirst() }
}

private struct StaticSessionRunner: CommandRunning {
    let output: String
    func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        BoundedCommandResult(
            terminationStatus: 0,
            standardOutput: Data(output.utf8),
            standardError: Data(),
            outputWasTruncated: false
        )
    }
}

private struct StaticSessionProcesses: ProcessInspecting {
    let values: [pid_t: InspectedProcess]
    func inspect(pid: pid_t) -> InspectedProcess? { values[pid] }
    func signal(_ process: InspectedProcess, signal: Int32) -> Bool { false }
}

private struct StaticUsernameResolver: UsernameResolving {
    let values: [uid_t: String]
    func username(for userID: uid_t) -> String? { values[userID] }
}

private final class SessionRecordingAudit: AuditLogging, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [AuditEvent] = []
    var events: [AuditEvent] { lock.withLock { stored } }
    func record(_ event: AuditEvent) throws { lock.withLock { stored.append(event) } }
}

private final class FailingSessionAudit: AuditLogging, @unchecked Sendable {
    private let lock = NSLock()
    private var storedRecordAttempts = 0
    var recordAttempts: Int { lock.withLock { storedRecordAttempts } }
    func record(_ event: AuditEvent) throws {
        lock.withLock { storedRecordAttempts += 1 }
        throw ControlErrorCode.auditUnavailable
    }
}
