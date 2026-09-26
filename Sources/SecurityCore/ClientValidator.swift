import Darwin
import Foundation
import SharedProtocol

public struct TrustedClientPolicy: Codable, Equatable, Sendable {
    public let consoleUserID: uid_t
    public let consoleGroupID: gid_t
    public let applicationPath: String
    public let bundleIdentifier: String
    public let designatedRequirement: String
    public let cdHash: String

    public init(
        consoleUserID: uid_t,
        consoleGroupID: gid_t,
        applicationPath: String,
        bundleIdentifier: String,
        designatedRequirement: String,
        cdHash: String
    ) {
        self.consoleUserID = consoleUserID
        self.consoleGroupID = consoleGroupID
        self.applicationPath = applicationPath
        self.bundleIdentifier = bundleIdentifier
        self.designatedRequirement = designatedRequirement
        self.cdHash = cdHash.uppercased()
    }
}

public struct ClientIdentityEvidence: Equatable, Sendable {
    public let effectiveUserID: uid_t
    public let effectiveGroupID: gid_t
    public let auditSessionID: UInt32
    public let executablePath: String
    public let bundleIdentifier: String
    public let designatedRequirement: String
    public let cdHash: String
    public let codeSignatureValid: Bool

    public init(
        effectiveUserID: uid_t,
        effectiveGroupID: gid_t,
        auditSessionID: UInt32,
        executablePath: String,
        bundleIdentifier: String,
        designatedRequirement: String,
        cdHash: String,
        codeSignatureValid: Bool
    ) {
        self.effectiveUserID = effectiveUserID
        self.effectiveGroupID = effectiveGroupID
        self.auditSessionID = auditSessionID
        self.executablePath = executablePath
        self.bundleIdentifier = bundleIdentifier
        self.designatedRequirement = designatedRequirement
        self.cdHash = cdHash.uppercased()
        self.codeSignatureValid = codeSignatureValid
    }
}

public protocol ClientValidating: Sendable {
    func validate(_ evidence: ClientIdentityEvidence) throws
}

public struct ClientValidator: ClientValidating, Sendable {
    private let policy: TrustedClientPolicy

    public init(policy: TrustedClientPolicy) {
        self.policy = policy
    }

    public func validate(_ evidence: ClientIdentityEvidence) throws {
        guard evidence.codeSignatureValid,
              evidence.effectiveUserID == policy.consoleUserID,
              evidence.effectiveGroupID == policy.consoleGroupID,
              evidence.auditSessionID != 0,
              evidence.auditSessionID != UInt32.max,
              evidence.executablePath == policy.applicationPath,
              evidence.bundleIdentifier == policy.bundleIdentifier,
              evidence.designatedRequirement == policy.designatedRequirement,
              evidence.cdHash == policy.cdHash
        else {
            throw ControlErrorCode.untrustedClient
        }
    }
}
