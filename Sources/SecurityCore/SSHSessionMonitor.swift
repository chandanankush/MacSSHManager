import Darwin
import Foundation
import OSLog
import SharedProtocol

public struct SSHSession: Equatable, Sendable {
    public let identity: Data
    public let sshUser: String
    public let sourceAddress: String

    public init(identity: Data, sshUser: String, sourceAddress: String) {
        self.identity = identity
        self.sshUser = sshUser
        self.sourceAddress = sourceAddress
    }
}

public protocol SSHSessionObserving: Sendable {
    func observe() async throws -> [SSHSession]
}

public protocol UsernameResolving: Sendable {
    func username(for userID: uid_t) -> String?
}

public struct SystemUsernameResolver: UsernameResolving, Sendable {
    public init() {}

    public func username(for userID: uid_t) -> String? {
        var password = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        guard getpwuid_r(userID, &password, &buffer, buffer.count, &result) == 0,
              result != nil,
              let name = password.pw_name
        else { return nil }
        let username = String(cString: name)
        guard !username.isEmpty, username.utf8.count <= 256 else { return nil }
        return username
    }
}

public struct SystemSSHSessionObserver: SSHSessionObserving, Sendable {
    private static let maximumProcesses = 4_096
    private static let privilegeSeparationUserID: uid_t = 75

    private let runner: any CommandRunning
    private let processes: any ProcessInspecting
    private let usernames: any UsernameResolving

    public init(
        runner: any CommandRunning,
        processes: any ProcessInspecting = SystemProcessInspector(),
        usernames: any UsernameResolving = SystemUsernameResolver()
    ) {
        self.runner = runner
        self.processes = processes
        self.usernames = usernames
    }

    public func observe() async throws -> [SSHSession] {
        let result = try await runner.run(.lsofEstablishedSSH)
        guard !result.outputWasTruncated else { throw ControlErrorCode.auditUnavailable }
        if result.terminationStatus == 1,
           result.standardOutput.isEmpty,
           result.standardError.isEmpty {
            return []
        }
        guard result.terminationStatus == 0 else { throw ControlErrorCode.auditUnavailable }

        let records = try parse(String(decoding: result.standardOutput, as: UTF8.self))
        let observed = records.flatMap { record -> [SSHSession] in
            guard let process = processes.inspect(pid: record.pid),
                  process.pid == record.pid,
                  process.executablePath == "/usr/sbin/sshd",
                  !process.auditToken.isEmpty,
                  let userID = process.effectiveUserID,
                  userID != 0,
                  userID != Self.privilegeSeparationUserID,
                  let username = usernames.username(for: userID),
                  username != "_sshd",
                  username != "sshd"
            else { return [] }

            return record.names.compactMap { name in
                guard let sourceAddress = numericRemoteAddress(from: name) else { return nil }
                return SSHSession(
                    identity: process.auditToken,
                    sshUser: username,
                    sourceAddress: sourceAddress
                )
            }
        }
        var unique: [SessionIdentity: SSHSession] = [:]
        for session in observed {
            unique[SessionIdentity(token: session.identity, sourceAddress: session.sourceAddress)] = session
        }
        return Array(unique.values)
    }

    private func parse(_ output: String) throws -> [SocketRecord] {
        var records: [SocketRecord] = []
        var currentPID: pid_t?
        var names: [String] = []

        func appendCurrent() {
            if let currentPID, !names.isEmpty {
                records.append(.init(pid: currentPID, names: names))
            }
        }

        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let field = line.first, ["p", "c", "f", "n", "t"].contains(field) else {
                throw ControlErrorCode.auditUnavailable
            }
            let value = String(line.dropFirst())
            if field == "p" {
                appendCurrent()
                guard !value.isEmpty,
                      value.utf8.allSatisfy({ (48...57).contains($0) }),
                      let pid = Int32(value),
                      pid > 1
                else { throw ControlErrorCode.auditUnavailable }
                currentPID = pid
                names = []
                guard records.count < Self.maximumProcesses else {
                    throw ControlErrorCode.auditUnavailable
                }
            } else if field == "n" {
                guard currentPID != nil, value.utf8.count <= 512 else {
                    throw ControlErrorCode.auditUnavailable
                }
                names.append(value)
            }
        }
        appendCurrent()
        return records
    }

    private func numericRemoteAddress(from name: String) -> String? {
        guard let arrow = name.range(of: "->") else { return nil }
        let endpoint = String(name[arrow.upperBound...])
        let address: String
        if endpoint.hasPrefix("[") {
            guard let closing = endpoint.firstIndex(of: "]"),
                  endpoint.index(after: closing) < endpoint.endIndex,
                  endpoint[endpoint.index(after: closing)] == ":"
            else { return nil }
            address = String(endpoint[endpoint.index(after: endpoint.startIndex)..<closing])
        } else {
            guard let colon = endpoint.lastIndex(of: ":"), colon > endpoint.startIndex else { return nil }
            address = String(endpoint[..<colon])
        }
        let unscoped = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        return canonicalNumericIPAddress(unscoped)
    }

    private func canonicalNumericIPAddress(_ address: String) -> String? {
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return String(
                decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
        }
        var ipv6 = in6_addr()
        guard address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        return String(
            decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
    }
}

private struct SocketRecord: Sendable {
    let pid: pid_t
    let names: [String]
}

private struct SessionIdentity: Hashable, Sendable {
    let token: Data
    let sourceAddress: String
}

public protocol SSHSessionReconciling: Sendable {
    func reconcile() async
}

public actor SSHSessionMonitor: SSHSessionReconciling {
    private let observer: any SSHSessionObserving
    private let audit: any AuditLogging
    private let now: @Sendable () -> Date
    private let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "security-audit")
    private var active: [SessionIdentity: SSHSession] = [:]

    public init(
        observer: any SSHSessionObserving,
        audit: any AuditLogging,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.observer = observer
        self.audit = audit
        self.now = now
    }

    public func reconcile() async {
        guard let sessions = try? await observer.observe() else { return }
        var current: [SessionIdentity: SSHSession] = [:]
        for session in sessions {
            current[SessionIdentity(token: session.identity, sourceAddress: session.sourceAddress)] = session
        }

        for (identity, session) in current where active[identity] == nil {
            record(event(kind: .sshConnected, session: session))
        }
        for (identity, session) in active where current[identity] == nil {
            record(event(kind: .sshDisconnected, session: session))
        }
        active = current
    }

    private func record(_ event: AuditEvent) {
        do {
            try audit.record(event)
        } catch {
            logger.error("Failed to record SSH lifecycle audit event")
        }
    }

    private func event(kind: AuditEvent.Kind, session: SSHSession) -> AuditEvent {
        AuditEvent(
            kind: kind,
            timestamp: now(),
            requestID: nil,
            reason: nil,
            duration: nil,
            userID: nil,
            auditSessionID: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            outcome: .success,
            sshUser: session.sshUser,
            sourceAddress: session.sourceAddress
        )
    }
}

public struct NoopSSHSessionMonitor: SSHSessionReconciling, Sendable {
    public init() {}
    public func reconcile() async {}
}
