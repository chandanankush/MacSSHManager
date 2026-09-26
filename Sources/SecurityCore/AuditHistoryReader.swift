import Darwin
import Foundation
import SharedProtocol

public protocol AuditHistoryReading: Sendable {
    func recent(query: String?) throws -> AuditHistoryPage
}

public struct AuditHistoryReader: AuditHistoryReading, Sendable {
    public static let maximumEntries = AuditHistoryPage.maximumEntries
    public static let retention: TimeInterval = 30 * 24 * 60 * 60

    private let fileURLs: [URL]
    private let now: @Sendable () -> Date
    private let expectedOwnerUID: uid_t

    public init(
        auditFileURL: URL = URL(fileURLWithPath: InstalledPaths.auditFile),
        now: @escaping @Sendable () -> Date = Date.init,
        expectedOwnerUID: uid_t = 0
    ) {
        fileURLs = [auditFileURL] + (1...RotatingAuditFileWriter.defaultRetainedFiles).map {
            URL(fileURLWithPath: auditFileURL.path + ".\($0)")
        }
        self.now = now
        self.expectedOwnerUID = expectedOwnerUID
    }

    init(
        fileURLs: [URL],
        now: @escaping @Sendable () -> Date = Date.init,
        expectedOwnerUID: uid_t = 0
    ) {
        self.fileURLs = fileURLs
        self.now = now
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func recent(query: String?) throws -> AuditHistoryPage {
        guard query.map({ $0.utf8.count <= 128 }) ?? true else { throw ControlErrorCode.malformedRequest }
        let cutoff = now().addingTimeInterval(-Self.retention)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entries = try fileURLs.flatMap { url in
            try read(url).split(separator: 0x0A).compactMap { line -> AuditHistoryEntry? in
                guard line.count <= AuditEncoder.maximumEventBytes,
                      let event = try? decoder.decode(AuditEvent.self, from: Data(line)),
                      event.timestamp >= cutoff
                else { return nil }
                guard let kind = AuditHistoryKind(rawValue: event.kind.rawValue),
                      let outcome = AuditHistoryOutcome(rawValue: event.outcome.rawValue)
                else { return nil }
                return AuditHistoryEntry(
                    timestamp: event.timestamp,
                    kind: kind,
                    outcome: outcome,
                    reason: event.reason,
                    duration: event.duration,
                    networkScope: event.networkScope,
                    interfaceName: event.interfaceName,
                    sourceCIDR: event.sourceCIDR,
                    tailscaleInterfaceName: event.tailscaleInterfaceName,
                    tailscaleAddressCIDR: event.tailscaleAddressCIDR,
                    localConsoleOnly: event.localConsoleOnly,
                    sshUser: event.sshUser,
                    sourceAddress: event.sourceAddress
                )
            }
        }
        let normalizedQuery = query?.trimmingCharacters(in: .whitespacesAndNewlines)
        let filtered = entries.filter { entry in
            guard let normalizedQuery, !normalizedQuery.isEmpty else { return true }
            return entry.searchableText.localizedCaseInsensitiveContains(normalizedQuery)
        }
        return .init(entries: filtered.sorted { $0.timestamp > $1.timestamp }.prefix(Self.maximumEntries).map { $0 })
    }

    private func read(_ url: URL) throws -> Data {
        let maximumBytes = RotatingAuditFileWriter.defaultMaximumBytes + AuditEncoder.maximumEventBytes
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else {
            if errno == ENOENT { return Data() }
            throw ControlErrorCode.auditUnavailable
        }
        guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_uid == expectedOwnerUID, metadata.st_mode & 0o777 == 0o600 else { throw ControlErrorCode.auditUnavailable }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw ControlErrorCode.auditUnavailable }
        defer { close(descriptor) }
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size >= 0,
              metadata.st_size <= maximumBytes
        else { throw ControlErrorCode.auditUnavailable }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        var data = Data()
        while data.count <= maximumBytes {
            let remaining = maximumBytes + 1 - data.count
            guard let chunk = try handle.read(upToCount: min(64 * 1_024, remaining)),
                  !chunk.isEmpty
            else { break }
            data.append(chunk)
        }
        guard data.count <= maximumBytes else { throw ControlErrorCode.auditUnavailable }
        return data
    }
}

private extension AuditHistoryEntry {
    var searchableText: String {
        [
            kind.rawValue,
            outcome.rawValue,
            reason?.rawValue,
            duration?.label,
            networkScope?.rawValue,
            interfaceName,
            sourceCIDR,
            tailscaleInterfaceName,
            tailscaleAddressCIDR,
            localConsoleOnly.map(String.init),
            sshUser,
            sourceAddress,
        ]
        .compactMap { $0 }
        .joined(separator: " ")
    }
}
