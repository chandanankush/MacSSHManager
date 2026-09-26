import Foundation

public struct Lease: Codable, Equatable, Sendable {
    public static let currentSchemaVersion = 2

    public let schemaVersion: Int
    public let requestID: UUID
    public let duration: AccessDuration
    public let deadlineUptime: TimeInterval
    public let openedAt: Date
    public let expiresAt: Date
    public let bootSessionID: String
    public let scope: SSHNetworkScope
    public let lanInterfaceName: String?
    public let lanSourceCIDR: String?
    public let tailscaleInterfaceName: String?
    public let tailscaleAddressCIDR: String?
    public let localConsoleOnly: Bool

    public init(
        schemaVersion: Int = Lease.currentSchemaVersion,
        requestID: UUID,
        duration: AccessDuration,
        deadlineUptime: TimeInterval,
        openedAt: Date,
        expiresAt: Date,
        bootSessionID: String,
        scope: SSHNetworkScope,
        lanInterfaceName: String?,
        lanSourceCIDR: String?,
        tailscaleInterfaceName: String?,
        tailscaleAddressCIDR: String?,
        localConsoleOnly: Bool
    ) {
        self.schemaVersion = schemaVersion
        self.requestID = requestID
        self.duration = duration
        self.deadlineUptime = deadlineUptime
        self.openedAt = openedAt
        self.expiresAt = expiresAt
        self.bootSessionID = bootSessionID
        self.scope = scope
        self.lanInterfaceName = lanInterfaceName
        self.lanSourceCIDR = lanSourceCIDR
        self.tailscaleInterfaceName = tailscaleInterfaceName
        self.tailscaleAddressCIDR = tailscaleAddressCIDR
        self.localConsoleOnly = localConsoleOnly
    }

    private static let interfaceNamePattern = #"^[A-Za-z0-9]{1,15}$"#

    public func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion,
              deadlineUptime.isFinite,
              deadlineUptime > 0,
              openedAt <= expiresAt,
              !bootSessionID.isEmpty,
              bootSessionID.utf8.count <= 128
        else {
            throw ControlErrorCode.invalidLease
        }

        if scope.includesLAN {
            guard let lanInterfaceName,
                  let lanSourceCIDR,
                  lanInterfaceName.range(of: Self.interfaceNamePattern, options: .regularExpression) != nil,
                  !lanSourceCIDR.isEmpty,
                  lanSourceCIDR.utf8.count <= 64
            else {
                throw ControlErrorCode.invalidLease
            }
        } else {
            guard lanInterfaceName == nil, lanSourceCIDR == nil else {
                throw ControlErrorCode.invalidLease
            }
        }

        if scope.includesTailscale {
            guard let tailscaleInterfaceName,
                  let tailscaleAddressCIDR,
                  tailscaleInterfaceName.range(of: Self.interfaceNamePattern, options: .regularExpression) != nil,
                  !tailscaleAddressCIDR.isEmpty,
                  tailscaleAddressCIDR.utf8.count <= 64
            else {
                throw ControlErrorCode.invalidLease
            }
        } else {
            guard tailscaleInterfaceName == nil, tailscaleAddressCIDR == nil else {
                throw ControlErrorCode.invalidLease
            }
        }
    }
}
