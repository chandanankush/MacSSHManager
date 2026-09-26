import Darwin
import Foundation
import OSLog
import SharedProtocol

public struct AuditAttribution: Equatable, Sendable {
    public let userID: uid_t
    public let auditSessionID: UInt32

    public init(userID: uid_t, auditSessionID: UInt32) {
        self.userID = userID
        self.auditSessionID = auditSessionID
    }
}

public enum RequestAuditContext {
    @TaskLocal public static var attribution: AuditAttribution?
}

public struct AuditEvent: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case openRequested
        case opened
        case openFailed
        case closed
        case closeDegraded
        case expired
        case recoveredClosed
        case settingChanged
        case networkChanged
        case publicNetwork
        case sshConnected
        case sshDisconnected
    }

    public enum Outcome: String, Codable, Sendable {
        case success
        case failure
        case degraded
    }

    public let kind: Kind
    public let timestamp: Date
    public let requestID: UUID?
    public let reason: ControlErrorCode?
    public let duration: AccessDuration?
    public let userID: uid_t?
    public let auditSessionID: UInt32?
    public let networkScope: SSHNetworkScope?
    public let interfaceName: String?
    public let sourceCIDR: String?
    public let tailscaleInterfaceName: String?
    public let tailscaleAddressCIDR: String?
    public let localConsoleOnly: Bool?
    public let sshUser: String?
    public let sourceAddress: String?
    public let outcome: Outcome

    public init(
        kind: Kind,
        timestamp: Date,
        requestID: UUID?,
        reason: ControlErrorCode?,
        duration: AccessDuration?,
        userID: uid_t?,
        auditSessionID: UInt32?,
        interfaceName: String?,
        sourceCIDR: String?,
        outcome: Outcome,
        networkScope: SSHNetworkScope? = nil,
        tailscaleInterfaceName: String? = nil,
        tailscaleAddressCIDR: String? = nil,
        localConsoleOnly: Bool? = nil,
        sshUser: String? = nil,
        sourceAddress: String? = nil
    ) {
        self.kind = kind
        self.timestamp = timestamp
        self.requestID = requestID
        self.reason = reason
        self.duration = duration
        self.userID = userID
        self.auditSessionID = auditSessionID
        self.networkScope = networkScope
        self.interfaceName = interfaceName
        self.sourceCIDR = sourceCIDR
        self.tailscaleInterfaceName = tailscaleInterfaceName
        self.tailscaleAddressCIDR = tailscaleAddressCIDR
        self.localConsoleOnly = localConsoleOnly
        self.sshUser = sshUser
        self.sourceAddress = sourceAddress
        self.outcome = outcome
    }
}

public struct AuditEncoder: Sendable {
    public static let maximumEventBytes = 4 * 1_024

    public init() {}

    public func encodeLine(_ event: AuditEvent) throws -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(event)
        data.append(0x0A)
        guard data.count <= Self.maximumEventBytes,
              let line = String(data: data, encoding: .utf8)
        else {
            throw ControlErrorCode.auditUnavailable
        }
        return line
    }
}

public protocol AuditLogging: Sendable {
    func record(_ event: AuditEvent) throws
}

public final class SecurityAuditLogger: AuditLogging, @unchecked Sendable {
    private let encoder: AuditEncoder
    private let writer: RotatingAuditFileWriter
    private let logger: Logger

    public init(
        writer: RotatingAuditFileWriter = RotatingAuditFileWriter(),
        encoder: AuditEncoder = AuditEncoder()
    ) {
        self.writer = writer
        self.encoder = encoder
        logger = Logger(subsystem: "com.serverpc.ssh-control", category: "security-audit")
    }

    public func record(_ event: AuditEvent) throws {
        let line = try encoder.encodeLine(event)
        try writer.append(line)
        logger.notice("event=\(event.kind.rawValue, privacy: .public) outcome=\(event.outcome.rawValue, privacy: .public)")
    }
}

public final class RotatingAuditFileWriter: @unchecked Sendable {
    public static let defaultMaximumBytes = 5 * 1_024 * 1_024
    public static let defaultRetainedFiles = 5

    public let fileURL: URL

    private let maximumBytes: Int
    private let retainedFiles: Int
    private let expectedOwnerUID: uid_t
    private let lock = NSLock()

    public init(
        fileURL: URL = URL(fileURLWithPath: InstalledPaths.auditFile),
        maximumBytes: Int = defaultMaximumBytes,
        retainedFiles: Int = defaultRetainedFiles,
        expectedOwnerUID: uid_t = 0
    ) {
        self.fileURL = fileURL
        self.maximumBytes = max(1, maximumBytes)
        self.retainedFiles = max(0, retainedFiles)
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func append(_ line: String) throws {
        guard let data = line.data(using: .utf8),
              data.count <= AuditEncoder.maximumEventBytes,
              line.hasSuffix("\n")
        else {
            throw ControlErrorCode.auditUnavailable
        }

        try lock.withLock {
            try rejectSymlinkIfPresent(at: fileURL)
            if try currentSize() + data.count > maximumBytes {
                try rotate()
            }
            try appendSecurely(data)
        }
    }

    private func currentSize() throws -> Int {
        var metadata = stat()
        if lstat(fileURL.path, &metadata) != 0 {
            if errno == ENOENT { return 0 }
            throw ControlErrorCode.auditUnavailable
        }
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size >= 0
        else {
            throw ControlErrorCode.auditUnavailable
        }
        return Int(metadata.st_size)
    }

    private func appendSecurely(_ data: Data) throws {
        let descriptor = open(
            fileURL.path,
            O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else { throw ControlErrorCode.auditUnavailable }
        defer { close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              fchmod(descriptor, 0o600) == 0
        else {
            throw ControlErrorCode.auditUnavailable
        }

        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    rawBuffer.count - offset
                )
                guard count > 0 else { throw ControlErrorCode.auditUnavailable }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw ControlErrorCode.auditUnavailable }
    }

    private func rotate() throws {
        guard retainedFiles > 0 else {
            if unlink(fileURL.path) != 0, errno != ENOENT {
                throw ControlErrorCode.auditUnavailable
            }
            return
        }

        let oldest = rotatedURL(retainedFiles)
        try removeRegularFileIfPresent(at: oldest)
        if retainedFiles > 1 {
            for index in stride(from: retainedFiles - 1, through: 1, by: -1) {
                let source = rotatedURL(index)
                let destination = rotatedURL(index + 1)
                try moveRegularFileIfPresent(from: source, to: destination)
            }
        }
        try moveRegularFileIfPresent(from: fileURL, to: rotatedURL(1))
    }

    private func rotatedURL(_ index: Int) -> URL {
        URL(fileURLWithPath: fileURL.path + ".\(index)")
    }

    private func moveRegularFileIfPresent(from source: URL, to destination: URL) throws {
        var metadata = stat()
        if lstat(source.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw ControlErrorCode.auditUnavailable
        }
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID
        else {
            throw ControlErrorCode.auditUnavailable
        }
        try removeRegularFileIfPresent(at: destination)
        guard rename(source.path, destination.path) == 0 else {
            throw ControlErrorCode.auditUnavailable
        }
    }

    private func removeRegularFileIfPresent(at url: URL) throws {
        var metadata = stat()
        if lstat(url.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw ControlErrorCode.auditUnavailable
        }
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              unlink(url.path) == 0
        else {
            throw ControlErrorCode.auditUnavailable
        }
    }

    private func rejectSymlinkIfPresent(at url: URL) throws {
        var metadata = stat()
        if lstat(url.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw ControlErrorCode.auditUnavailable
        }
        guard metadata.st_mode & S_IFMT != S_IFLNK else {
            throw ControlErrorCode.auditUnavailable
        }
    }
}
