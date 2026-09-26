import Foundation

public enum AuditHistoryKind: String, Codable, Equatable, Sendable {
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

public enum AuditHistoryOutcome: String, Codable, Equatable, Sendable {
    case success
    case failure
    case degraded
}

public struct AuditHistoryEntry: Codable, Equatable, Sendable {
    public let timestamp: Date
    public let kind: AuditHistoryKind
    public let outcome: AuditHistoryOutcome
    public let reason: ControlErrorCode?
    public let duration: AccessDuration?
    public let networkScope: SSHNetworkScope?
    public let interfaceName: String?
    public let sourceCIDR: String?
    public let tailscaleInterfaceName: String?
    public let tailscaleAddressCIDR: String?
    public let localConsoleOnly: Bool?
    public let sshUser: String?
    public let sourceAddress: String?

    public init(
        timestamp: Date,
        kind: AuditHistoryKind,
        outcome: AuditHistoryOutcome,
        reason: ControlErrorCode?,
        duration: AccessDuration?,
        networkScope: SSHNetworkScope? = nil,
        interfaceName: String?,
        sourceCIDR: String?,
        tailscaleInterfaceName: String? = nil,
        tailscaleAddressCIDR: String? = nil,
        localConsoleOnly: Bool?,
        sshUser: String?,
        sourceAddress: String?
    ) {
        self.timestamp = timestamp
        self.kind = kind
        self.outcome = outcome
        self.reason = reason
        self.duration = duration
        self.networkScope = networkScope
        self.interfaceName = interfaceName
        self.sourceCIDR = sourceCIDR
        self.tailscaleInterfaceName = tailscaleInterfaceName
        self.tailscaleAddressCIDR = tailscaleAddressCIDR
        self.localConsoleOnly = localConsoleOnly
        self.sshUser = sshUser
        self.sourceAddress = sourceAddress
    }
}

public struct AuditHistoryPage: Codable, Equatable, Sendable {
    public static let maximumEntries = 250
    public let entries: [AuditHistoryEntry]
    public init(entries: [AuditHistoryEntry]) { self.entries = entries }
}

public struct AuditHistoryResponse: Codable, Equatable, Sendable {
    public static let maximumEncodedBytes = 64 * 1_024

    public let page: AuditHistoryPage?
    public let error: ControlErrorCode?

    public init(page: AuditHistoryPage?, error: ControlErrorCode?) {
        self.page = page
        self.error = error
    }

    public static func success(_ page: AuditHistoryPage) -> Self {
        .init(page: page, error: nil)
    }

    public static func failure(_ error: ControlErrorCode) -> Self {
        .init(page: nil, error: error)
    }
}
