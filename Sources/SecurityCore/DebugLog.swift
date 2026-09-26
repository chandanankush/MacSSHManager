import Darwin
import Foundation
import SharedProtocol

/// A plain, bounded, root-owned diagnostic log for bring-up debugging. This
/// is intentionally separate from `AuditLogging`: it is not a security
/// record, carries no field allowlist, and callers must still never write
/// credentials, keys, or authorization material into it. It exists to make
/// live troubleshooting fast; it is not part of the security boundary and
/// its absence or failure never affects enforcement.
public protocol DebugLogging: Sendable {
    func log(_ message: String)
}

public struct DebugLog: DebugLogging, Sendable {
    public static let maximumBytes = 1 * 1_024 * 1_024
    public static let fileURL = URL(fileURLWithPath: InstalledPaths.applicationRoot + "/debug.log")

    private let expectedOwnerUID: uid_t

    public init(expectedOwnerUID: uid_t = 0) {
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func log(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        let line = "[\(timestamp)] \(message.prefix(1_000))\n"
        guard let data = line.data(using: .utf8) else { return }
        if (try? currentSize()) ?? 0 + data.count > Self.maximumBytes {
            unlink(Self.fileURL.path)
        }
        append(data)
    }

    private func append(_ data: Data) {
        let descriptor = open(
            Self.fileURL.path,
            O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
            0o600
        )
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              fchmod(descriptor, 0o600) == 0
        else { return }
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                guard written > 0 else { return }
                offset += written
            }
        }
    }

    private func currentSize() throws -> Int {
        var metadata = stat()
        guard lstat(Self.fileURL.path, &metadata) == 0 else { return 0 }
        guard metadata.st_mode & S_IFMT == S_IFREG else { return 0 }
        return Int(metadata.st_size)
    }
}

public struct NoopDebugLog: DebugLogging, Sendable {
    public init() {}
    public func log(_ message: String) {}
}
