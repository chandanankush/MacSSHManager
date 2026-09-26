import CryptoKit
import Darwin
import Foundation
import Security
import SharedProtocol

public enum AuthorizationAction: String, Sendable {
    case open
    case disableLocalConsoleOnly

    var rightName: String { InstalledPaths.authorizationRight }
}

public enum AuthorizationRightPolicy {
    public static let tokenLifetimeSeconds = 10

    public static var requiredDefinition: [String: Any] {
        [
            "class": "user",
            "group": "admin",
            "shared": false,
            "timeout": tokenLifetimeSeconds,
            "allow-root": false,
            "authenticate-user": true
        ]
    }

    public static func matches(_ definition: [String: Any]) -> Bool {
        guard definition["class"] as? String == "user",
              definition["group"] as? String == "admin",
              definition["shared"] as? Bool == false,
              (definition["timeout"] as? NSNumber)?.intValue == tokenLifetimeSeconds,
              definition["allow-root"] as? Bool == false,
              definition["authenticate-user"] as? Bool == true
        else {
            return false
        }
        return true
    }

    public static func installedDefinitionMatches(rightName: String) -> Bool {
        var rightDefinition: CFDictionary?
        let status = rightName.withCString { AuthorizationRightGet($0, &rightDefinition) }
        guard status == errAuthorizationSuccess,
              let definition = rightDefinition as? [String: Any]
        else {
            return false
        }
        return matches(definition)
    }
}

public protocol AuthorizationChecking: Sendable {
    func check(externalForm: Data, rightName: String) -> Bool
}

public protocol AuthorizationValidating: Sendable {
    func consume(form: Data, nonce: UUID, action: AuthorizationAction) throws
}

public final class OneUseAuthorizationValidator: AuthorizationValidating, @unchecked Sendable {
    public static let maximumRememberedCredentials = 4_096

    private let checker: any AuthorizationChecking
    private let lock = NSLock()
    private var nonces = Set<UUID>()
    private var formDigests = Set<String>()
    private var insertionOrder: [(UUID, String)] = []

    public init(checker: any AuthorizationChecking = SystemAuthorizationChecker()) {
        self.checker = checker
    }

    public func consume(form: Data, nonce: UUID, action: AuthorizationAction) throws {
        guard form.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw ControlErrorCode.invalidAuthorization
        }
        let digest = SHA256.hash(data: form).map { String(format: "%02x", $0) }.joined()

        try lock.withLock {
            guard !nonces.contains(nonce), !formDigests.contains(digest) else {
                throw ControlErrorCode.invalidAuthorization
            }
            nonces.insert(nonce)
            formDigests.insert(digest)
            insertionOrder.append((nonce, digest))
            trimReplayCache()

            guard checker.check(externalForm: form, rightName: action.rightName) else {
                throw ControlErrorCode.invalidAuthorization
            }
        }
    }

    private func trimReplayCache() {
        while insertionOrder.count > Self.maximumRememberedCredentials {
            let removed = insertionOrder.removeFirst()
            nonces.remove(removed.0)
            formDigests.remove(removed.1)
        }
    }
}

public struct SystemAuthorizationChecker: AuthorizationChecking, Sendable {
    public init() {}

    public func check(externalForm data: Data, rightName: String) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size,
              AuthorizationRightPolicy.installedDefinitionMatches(rightName: rightName)
        else {
            return false
        }
        var externalForm = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &externalForm) { destination in
            data.copyBytes(to: destination)
        }

        var authorization: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&externalForm, &authorization) == errAuthorizationSuccess,
              let authorization
        else {
            return false
        }
        defer { AuthorizationFree(authorization, [.destroyRights]) }

        return rightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(
                    authorization,
                    &rights,
                    nil,
                    [.extendRights],
                    nil
                ) == errAuthorizationSuccess
            }
        }
    }
}

public struct SecuritySettings: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let localConsoleOnly: Bool

    public init(localConsoleOnly: Bool) {
        schemaVersion = 1
        self.localConsoleOnly = localConsoleOnly
    }

    func validate() throws {
        guard schemaVersion == 1 else { throw ControlErrorCode.internalFailure }
    }
}

public protocol SecuritySettingsStoring: Sendable {
    func load() throws -> SecuritySettings
    func save(_ settings: SecuritySettings) throws
}

public final class FileSecuritySettingsStore: SecuritySettingsStoring, @unchecked Sendable {
    public static let maximumSettingsBytes = 4 * 1_024

    public let fileURL: URL
    private let expectedOwnerUID: uid_t
    private let lock = NSLock()

    public init(
        fileURL: URL = URL(fileURLWithPath: InstalledPaths.settingsFile),
        expectedOwnerUID: uid_t = 0
    ) {
        self.fileURL = fileURL
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func load() throws -> SecuritySettings {
        try lock.withLock {
            let descriptor = open(fileURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            if descriptor < 0 {
                if errno == ENOENT { return SecuritySettings(localConsoleOnly: false) }
                throw ControlErrorCode.internalFailure
            }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            var metadata = stat()
            guard fstat(descriptor, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFREG,
                  metadata.st_uid == expectedOwnerUID,
                  metadata.st_mode & 0o777 == 0o600,
                  metadata.st_size >= 0,
                  metadata.st_size <= Self.maximumSettingsBytes,
                  let data = try handle.readToEnd(),
                  data.count <= Self.maximumSettingsBytes
            else {
                throw ControlErrorCode.internalFailure
            }
            let settings = try JSONDecoder().decode(SecuritySettings.self, from: data)
            try settings.validate()
            return settings
        }
    }

    public func save(_ settings: SecuritySettings) throws {
        try settings.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(settings)
        guard data.count <= Self.maximumSettingsBytes else { throw ControlErrorCode.internalFailure }

        try lock.withLock {
            try rejectSymlink()
            try ensureDirectory()
            try writeAtomically(data)
        }
    }

    private func rejectSymlink() throws {
        var metadata = stat()
        if lstat(fileURL.path, &metadata) != 0 {
            if errno == ENOENT { return }
            throw ControlErrorCode.internalFailure
        }
        guard metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID
        else {
            throw ControlErrorCode.internalFailure
        }
    }

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent().path
        if mkdir(directory, 0o700) != 0, errno != EEXIST { throw ControlErrorCode.internalFailure }
        var metadata = stat()
        guard lstat(directory, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == expectedOwnerUID,
              chmod(directory, 0o700) == 0
        else {
            throw ControlErrorCode.internalFailure
        }
    }

    private func writeAtomically(_ data: Data) throws {
        let directory = fileURL.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".settings-\(UUID().uuidString).tmp").path
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw ControlErrorCode.internalFailure }
        var removeTemporary = true
        defer {
            close(descriptor)
            if removeTemporary { unlink(temporary) }
        }
        guard fchmod(descriptor, 0o600) == 0,
              fchown(descriptor, expectedOwnerUID, gid_t.max) == 0
        else {
            throw ControlErrorCode.internalFailure
        }
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                guard written > 0 else { throw ControlErrorCode.internalFailure }
                offset += written
            }
        }
        guard fsync(descriptor) == 0,
              rename(temporary, fileURL.path) == 0
        else {
            throw ControlErrorCode.internalFailure
        }
        removeTemporary = false
    }
}
