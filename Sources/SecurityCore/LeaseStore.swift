import Darwin
import Foundation
import SharedProtocol

public enum LeaseState: Equatable, Sendable {
    case absent
    case active(Lease)
    case expired(Lease)
    case invalid
}

public protocol LeaseStoring: Sendable {
    func load() throws -> Lease?
    func save(_ lease: Lease) throws
    func remove() throws
    func currentState() throws -> LeaseState
}

public final class FileLeaseStore: LeaseStoring, @unchecked Sendable {
    public static let maximumLeaseBytes = 16 * 1_024

    public let fileURL: URL

    private let clock: any ContinuousTimeProviding
    private let expectedOwnerUID: uid_t
    private let fileManager: FileManager
    private let lock = NSLock()

    public init(
        fileURL: URL = URL(fileURLWithPath: InstalledPaths.leaseFile),
        clock: any ContinuousTimeProviding,
        expectedOwnerUID: uid_t = 0,
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.clock = clock
        self.expectedOwnerUID = expectedOwnerUID
        self.fileManager = fileManager
    }

    public func load() throws -> Lease? {
        try lock.withLock {
            try loadUnlocked()
        }
    }

    public func save(_ lease: Lease) throws {
        try lease.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(lease)
        guard data.count <= Self.maximumLeaseBytes else {
            throw ControlErrorCode.invalidLease
        }

        try lock.withLock {
            try ensureStateDirectory()
            try writeAtomically(data)
        }
    }

    public func remove() throws {
        try lock.withLock {
            if unlink(fileURL.path) != 0, errno != ENOENT {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try synchronizeDirectory()
        }
    }

    public func currentState() throws -> LeaseState {
        do {
            guard let lease = try load() else { return .absent }
            guard lease.bootSessionID == clock.bootSessionID else { return .invalid }
            if lease.deadlineUptime <= clock.uptimeIncludingSleep {
                return .expired(lease)
            }
            return .active(lease)
        } catch {
            return .invalid
        }
    }

    private func loadUnlocked() throws -> Lease? {
        let descriptor = open(fileURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_uid == expectedOwnerUID,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size >= 0,
              metadata.st_size <= Self.maximumLeaseBytes
        else {
            throw ControlErrorCode.invalidLease
        }

        guard let data = try handle.readToEnd(), data.count <= Self.maximumLeaseBytes else {
            throw ControlErrorCode.invalidLease
        }
        let lease = try JSONDecoder().decode(Lease.self, from: data)
        try lease.validate()
        return lease
    }

    private func ensureStateDirectory() throws {
        let directoryURL = fileURL.deletingLastPathComponent()
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: directoryURL.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else { throw ControlErrorCode.invalidLease }
        } else {
            try fileManager.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        guard chmod(directoryURL.path, 0o700) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    private func writeAtomically(_ data: Data) throws {
        let temporaryURL = fileURL.deletingLastPathComponent()
            .appendingPathComponent(".lease-\(UUID().uuidString).tmp")
        let descriptor = open(
            temporaryURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var shouldRemoveTemporary = true
        defer {
            close(descriptor)
            if shouldRemoveTemporary { unlink(temporaryURL.path) }
        }

        guard fchmod(descriptor, 0o600) == 0,
              fchown(descriptor, expectedOwnerUID, gid_t.max) == 0
        else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let written = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    rawBuffer.count - offset
                )
                guard written > 0 else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                offset += written
            }
        }

        guard fsync(descriptor) == 0,
              rename(temporaryURL.path, fileURL.path) == 0
        else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        shouldRemoveTemporary = false
        try synchronizeDirectory()
    }

    private func synchronizeDirectory() throws {
        let descriptor = open(fileURL.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT { return }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
}
