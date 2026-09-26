import Foundation

public enum ControlErrorCode: String, Codable, Error, Equatable, Sendable {
    case invalidDuration
    case invalidLease
    case invalidAuthorization
    case malformedRequest
    case untrustedClient
    case auditUnavailable
    case networkUnavailable
    case invalidNetworkScope
    case tailscaleUnavailable
    case pfUnavailable
    case pfDisabled
    case pfEnableFailed
    case pfEnableUnverified
    case pfAnchorValidationFailed
    case pfRulesLoadFailed
    case permissionFailure
    case unsafeSSHPolicy
    case remoteControlActive
    case terminationIncomplete
    case serviceApprovalRequired
    case unavailable
    case internalFailure
}

extension ControlErrorCode: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidDuration: "The requested access duration is not allowed."
        case .invalidLease: "The access lease is invalid."
        case .invalidAuthorization: "Administrator authorization was not accepted."
        case .malformedRequest: "The request is malformed."
        case .untrustedClient: "The requesting application is not trusted."
        case .auditUnavailable: "Security auditing is unavailable."
        case .networkUnavailable: "A physical LAN could not be identified."
        case .invalidNetworkScope: "No network scope was selected for SSH access."
        case .tailscaleUnavailable: "A trusted Tailscale route could not be established."
        case .pfUnavailable: "Packet Filter enforcement is unavailable."
        case .pfDisabled: "Packet Filter is disabled."
        case .pfEnableFailed: "Packet Filter could not be enabled."
        case .pfEnableUnverified: "Packet Filter did not remain enabled."
        case .pfAnchorValidationFailed: "The Packet Filter anchor could not be verified."
        case .pfRulesLoadFailed: "The Packet Filter rules could not be loaded."
        case .permissionFailure: "The privileged service does not have the required permissions."
        case .unsafeSSHPolicy: "SSH is not configured for public-key-only authentication."
        case .remoteControlActive: "A prohibited remote-control service is active."
        case .terminationIncomplete: "One or more SSH sessions could not be terminated."
        case .serviceApprovalRequired: "The privileged service requires local approval."
        case .unavailable: "SSH access control is unavailable."
        case .internalFailure: "SSH access control failed safely."
        }
    }
}

public struct ControlResponse: Codable, Equatable, Sendable {
    public static let maximumEncodedBytes = 16 * 1_024

    public let status: AccessStatus?
    public let error: ControlErrorCode?

    public init(status: AccessStatus?, error: ControlErrorCode?) {
        self.status = status
        self.error = error
    }

    public static func success(_ status: AccessStatus) -> Self {
        .init(status: status, error: nil)
    }

    public static func failure(_ error: ControlErrorCode, status: AccessStatus? = nil) -> Self {
        .init(status: status, error: error)
    }
}
