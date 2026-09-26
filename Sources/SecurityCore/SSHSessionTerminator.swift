import Darwin
import Foundation
import SharedProtocol

public struct InspectedProcess: Equatable, Sendable {
    public let pid: pid_t
    public let executablePath: String
    public let auditToken: Data
    public let effectiveUserID: uid_t?

    public init(pid: pid_t, executablePath: String, auditToken: Data, effectiveUserID: uid_t? = nil) {
        self.pid = pid
        self.executablePath = executablePath
        self.auditToken = auditToken
        self.effectiveUserID = effectiveUserID
    }
}

public protocol ProcessInspecting: Sendable {
    func inspect(pid: pid_t) -> InspectedProcess?
    func signal(_ process: InspectedProcess, signal: Int32) -> Bool
}

public struct SSHSessionTerminationResult: Equatable, Sendable {
    public let complete: Bool
    public let signalledPIDs: [pid_t]
    public let remainingSessionCount: Int

    public init(complete: Bool, signalledPIDs: [pid_t], remainingSessionCount: Int) {
        self.complete = complete
        self.signalledPIDs = signalledPIDs
        self.remainingSessionCount = remainingSessionCount
    }
}

public protocol SSHSessionTerminating: Sendable {
    func terminateAll() async throws -> SSHSessionTerminationResult
}

public struct SSHSessionTerminator: SSHSessionTerminating, Sendable {
    private static let maximumPIDs = 4_096

    private let runner: any CommandRunning
    private let processes: any ProcessInspecting
    private let delayNanoseconds: UInt64

    public init(
        runner: any CommandRunning,
        processes: any ProcessInspecting = SystemProcessInspector(),
        delayNanoseconds: UInt64 = 250_000_000
    ) {
        self.runner = runner
        self.processes = processes
        self.delayNanoseconds = delayNanoseconds
    }

    public func terminateAll() async throws -> SSHSessionTerminationResult {
        var signalled = Set<pid_t>()
        let initial = try await establishedPIDs()
        if initial.isEmpty {
            return SSHSessionTerminationResult(complete: true, signalledPIDs: [], remainingSessionCount: 0)
        }
        let termCandidates = validatedSSHDProcesses(initial)
        if !termCandidates.isEmpty {
            let currentOwners = try await establishedPIDs()
            for process in termCandidates where currentOwners.contains(process.pid) {
                if processes.signal(process, signal: SIGTERM) { signalled.insert(process.pid) }
            }
        }

        await pause()
        let survivors = try await establishedPIDs()
        if survivors.isEmpty {
            return SSHSessionTerminationResult(
                complete: true,
                signalledPIDs: signalled.sorted(),
                remainingSessionCount: 0
            )
        }
        let killCandidates = validatedSSHDProcesses(survivors)
        if !killCandidates.isEmpty {
            let currentOwners = try await establishedPIDs()
            for process in killCandidates where currentOwners.contains(process.pid) {
                if processes.signal(process, signal: SIGKILL) { signalled.insert(process.pid) }
            }
        }

        await pause()
        let remaining = try await establishedPIDs()
        return SSHSessionTerminationResult(
            complete: remaining.isEmpty,
            signalledPIDs: signalled.sorted(),
            remainingSessionCount: remaining.count
        )
    }

    private func establishedPIDs() async throws -> Set<pid_t> {
        let result = try await runner.run(.lsofEstablishedSSH)
        guard !result.outputWasTruncated else {
            throw ControlErrorCode.terminationIncomplete
        }
        if result.terminationStatus == 1,
           result.standardOutput.isEmpty,
           result.standardError.isEmpty {
            return []
        }
        guard result.terminationStatus == 0 else { throw ControlErrorCode.terminationIncomplete }
        let text = String(decoding: result.standardOutput, as: UTF8.self)
        var pids = Set<pid_t>()
        for line in text.split(separator: "\n") {
            guard let field = line.first, ["p", "c", "f", "n", "t", "u"].contains(field) else {
                throw ControlErrorCode.terminationIncomplete
            }
            guard field == "p" else { continue }
            let value = line.dropFirst()
            guard !value.isEmpty,
                  value.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let parsed = Int32(value),
                  parsed > 1
            else {
                throw ControlErrorCode.terminationIncomplete
            }
            pids.insert(parsed)
            guard pids.count <= Self.maximumPIDs else {
                throw ControlErrorCode.terminationIncomplete
            }
        }
        return pids
    }

    private func validatedSSHDProcesses(_ pids: Set<pid_t>) -> [InspectedProcess] {
        pids.sorted().compactMap { pid in
            guard let process = processes.inspect(pid: pid),
                  process.pid == pid,
                  process.executablePath == "/usr/sbin/sshd",
                  !process.auditToken.isEmpty
            else {
                return nil
            }
            return process
        }
    }

    private func pause() async {
        guard delayNanoseconds > 0 else { return }
        try? await Task.sleep(nanoseconds: delayNanoseconds)
    }
}

public struct SystemProcessInspector: ProcessInspecting, Sendable {
    private static let executablePath = "/usr/sbin/sshd"

    public init() {}

    public func inspect(pid: pid_t) -> InspectedProcess? {
        guard pid > 1 else { return nil }
        var task: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var token = audit_token_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { integers in
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), integers, &count)
            }
        }
        guard result == KERN_SUCCESS,
              audit_token_to_pid(token) == pid,
              let path = executablePath(for: &token),
              path == Self.executablePath
        else {
            return nil
        }
        let effectiveUserID = audit_token_to_euid(token)
        return withUnsafeBytes(of: &token) { bytes in
            InspectedProcess(
                pid: pid,
                executablePath: path,
                auditToken: Data(bytes),
                effectiveUserID: effectiveUserID
            )
        }
    }

    public func signal(_ process: InspectedProcess, signal: Int32) -> Bool {
        guard process.auditToken.count == MemoryLayout<audit_token_t>.size,
              process.executablePath == Self.executablePath,
              signal == SIGTERM || signal == SIGKILL
        else {
            return false
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { destination in
            process.auditToken.copyBytes(to: destination)
        }
        guard audit_token_to_pid(token) == process.pid,
              executablePath(for: &token) == Self.executablePath
        else {
            return false
        }
        return proc_signal_with_audittoken(&token, signal) == 0
    }

    private func executablePath(for token: inout audit_token_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        let count = proc_pidpath_audittoken(&token, &buffer, UInt32(buffer.count))
        guard count > 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
