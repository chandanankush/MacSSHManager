import Darwin
import Foundation
import SharedProtocol
import SystemConfiguration

public struct InstalledClientCodePolicy: Codable, Equatable, Sendable {
    public let applicationPath: String
    public let bundleIdentifier: String
    public let designatedRequirement: String
    public let cdHash: String

    public init(
        applicationPath: String,
        bundleIdentifier: String,
        designatedRequirement: String,
        cdHash: String
    ) {
        self.applicationPath = applicationPath
        self.bundleIdentifier = bundleIdentifier
        self.designatedRequirement = designatedRequirement
        self.cdHash = cdHash.uppercased()
    }

    public func validate() throws {
        let expectedPath = InstalledPaths.applicationBundle + "/Contents/MacOS/Mac SSH Manager"
        guard applicationPath == expectedPath,
              bundleIdentifier == InstalledPaths.menuBundleIdentifier,
              !designatedRequirement.isEmpty,
              designatedRequirement.utf8.count <= 4_096,
              [40, 64].contains(cdHash.utf8.count),
              cdHash.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) })
        else {
            throw ControlErrorCode.untrustedClient
        }
    }
}

public struct ConsoleIdentity: Equatable, Sendable {
    public let userID: uid_t
    public let groupID: gid_t

    public init(userID: uid_t, groupID: gid_t) {
        self.userID = userID
        self.groupID = groupID
    }
}

public protocol ConsoleIdentityProviding: Sendable {
    func activeConsoleIdentity() throws -> ConsoleIdentity
}

public struct SystemConsoleIdentityProvider: ConsoleIdentityProviding, Sendable {
    public init() {}

    public func activeConsoleIdentity() throws -> ConsoleIdentity {
        var userID: uid_t = 0
        var groupID: gid_t = 0
        guard let user = SCDynamicStoreCopyConsoleUser(nil, &userID, &groupID) as String?,
              !user.isEmpty,
              user != "loginwindow",
              userID > 0
        else {
            throw ControlErrorCode.untrustedClient
        }
        return ConsoleIdentity(userID: userID, groupID: groupID)
    }
}

public final class FileInstalledClientPolicyStore: @unchecked Sendable {
    public static let maximumBytes = 16 * 1_024
    private let fileURL: URL
    private let expectedOwnerUID: uid_t

    public init(
        fileURL: URL = URL(fileURLWithPath: InstalledPaths.clientPolicyFile),
        expectedOwnerUID: uid_t = 0
    ) {
        self.fileURL = fileURL
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func load() throws -> InstalledClientCodePolicy {
        let descriptor = open(fileURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw ControlErrorCode.untrustedClient }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size > 0,
              metadata.st_size <= Self.maximumBytes,
              let data = try handle.readToEnd(),
              data.count <= Self.maximumBytes
        else {
            throw ControlErrorCode.untrustedClient
        }
        let policy = try JSONDecoder().decode(InstalledClientCodePolicy.self, from: data)
        try policy.validate()
        return policy
    }
}
