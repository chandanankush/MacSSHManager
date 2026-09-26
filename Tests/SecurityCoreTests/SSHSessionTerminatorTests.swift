import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class SSHSessionTerminatorTests: XCTestCase {
    func testTerminatorDoesNotSignalNonSSHDProcess() async throws {
        let runner = LsofSequenceRunner(outputs: ["p42\ncsshd\ntIPv4\n", ""])
        let processes = FakeProcessInspector(processes: [42: .init(pid: 42, executablePath: "/usr/bin/other", auditToken: Data([1]))])
        let result = try await SSHSessionTerminator(
            runner: runner,
            processes: processes,
            delayNanoseconds: 0
        ).terminateAll()

        XCTAssertEqual(result.signalledPIDs, [])
        XCTAssertTrue(result.complete)
    }

    func testTerminatorUsesValidatedIdentityForTermThenKill() async throws {
        let identity = InspectedProcess(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1, 2, 3]))
        let runner = LsofSequenceRunner(outputs: [
            "p42\ncsshd\ntIPv4\n",
            "p42\ncsshd\ntIPv4\n",
            "p42\ncsshd\ntIPv4\n",
            "p42\ncsshd\ntIPv4\n",
            ""
        ])
        let processes = FakeProcessInspector(processes: [42: identity])

        let result = try await SSHSessionTerminator(
            runner: runner,
            processes: processes,
            delayNanoseconds: 0
        ).terminateAll()

        XCTAssertTrue(result.complete)
        XCTAssertEqual(result.signalledPIDs, [42])
        XCTAssertEqual(processes.signals, [
            SignalRecord(identity: identity, signal: SIGTERM),
            SignalRecord(identity: identity, signal: SIGKILL)
        ])
    }

    func testTerminatorReportsIncompleteWhenTokenSafeSignalRejectsReusedPID() async throws {
        let identity = InspectedProcess(pid: 42, executablePath: "/usr/sbin/sshd", auditToken: Data([1]))
        let runner = LsofSequenceRunner(outputs: ["p42\n", "p42\n", "p42\n", "p42\n", "p42\n"])
        let processes = FakeProcessInspector(processes: [42: identity], rejectedSignals: true)

        let result = try await SSHSessionTerminator(
            runner: runner,
            processes: processes,
            delayNanoseconds: 0
        ).terminateAll()

        XCTAssertFalse(result.complete)
        XCTAssertEqual(result.remainingSessionCount, 1)
        XCTAssertEqual(result.signalledPIDs, [])
    }

    func testMalformedLsofOutputFailsClosed() async {
        let runner = LsofSequenceRunner(outputs: ["p-1\npabc\np999999999999999999999\n"])
        let terminator = SSHSessionTerminator(
            runner: runner,
            processes: FakeProcessInspector(processes: [:]),
            delayNanoseconds: 0
        )

        await XCTAssertThrowsErrorAsync(try await terminator.terminateAll())
    }

    func testLsofNoMatchExitStatusMeansNoEstablishedSessions() async throws {
        let terminator = SSHSessionTerminator(
            runner: LsofSequenceRunner(outputs: [""], emptyExitStatus: 1),
            processes: FakeProcessInspector(processes: [:]),
            delayNanoseconds: 0
        )

        let result = try await terminator.terminateAll()
        XCTAssertTrue(result.complete)
        XCTAssertEqual(result.remainingSessionCount, 0)
    }
}

private actor LsofSequenceRunner: CommandRunning {
    private var outputs: [String]
    private let emptyExitStatus: Int32

    init(outputs: [String], emptyExitStatus: Int32 = 0) {
        self.outputs = outputs
        self.emptyExitStatus = emptyExitStatus
    }

    func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        XCTAssertEqual(command, .lsofEstablishedSSH)
        guard !outputs.isEmpty else { throw ControlErrorCode.terminationIncomplete }
        let output = outputs.removeFirst()
        return BoundedCommandResult(
            terminationStatus: output.isEmpty ? emptyExitStatus : 0,
            standardOutput: Data(output.utf8),
            standardError: Data(),
            outputWasTruncated: false
        )
    }
}

private struct SignalRecord: Equatable {
    let identity: InspectedProcess
    let signal: Int32
}

private final class FakeProcessInspector: ProcessInspecting, @unchecked Sendable {
    private let lock = NSLock()
    private let processes: [pid_t: InspectedProcess]
    private let rejectedSignals: Bool
    private var storedSignals: [SignalRecord] = []

    init(processes: [pid_t: InspectedProcess], rejectedSignals: Bool = false) {
        self.processes = processes
        self.rejectedSignals = rejectedSignals
    }

    var signals: [SignalRecord] { lock.withLock { storedSignals } }

    func inspect(pid: pid_t) -> InspectedProcess? { processes[pid] }

    func signal(_ process: InspectedProcess, signal: Int32) -> Bool {
        lock.withLock {
            guard !rejectedSignals else { return false }
            storedSignals.append(SignalRecord(identity: process, signal: signal))
            return true
        }
    }
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
