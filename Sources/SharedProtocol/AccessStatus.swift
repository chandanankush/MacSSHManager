import Foundation

public struct AccessStatus: Codable, Equatable, Sendable {
    public enum Mode: String, Codable, Sendable {
        case closed
        case opening
        case open
        case closing
        case recovering
        case degradedClosed
        case unavailable
    }

    public let mode: Mode
    public let expiresAt: Date?
    public let lastTransition: Date?
    public let reason: ControlErrorCode?
    public let localConsoleOnly: Bool
    public let networkScope: SSHNetworkScope?

    public init(
        mode: Mode,
        expiresAt: Date? = nil,
        lastTransition: Date? = nil,
        reason: ControlErrorCode? = nil,
        localConsoleOnly: Bool,
        networkScope: SSHNetworkScope? = nil
    ) {
        self.mode = mode
        self.expiresAt = expiresAt
        self.lastTransition = lastTransition
        self.reason = reason
        self.localConsoleOnly = localConsoleOnly
        self.networkScope = networkScope
    }

    public static func closed(lastTransition: Date?, localConsoleOnly: Bool) -> Self {
        .init(mode: .closed, lastTransition: lastTransition, localConsoleOnly: localConsoleOnly)
    }

    public static func open(
        expiresAt: Date,
        lastTransition: Date,
        localConsoleOnly: Bool,
        networkScope: SSHNetworkScope? = nil
    ) -> Self {
        .init(
            mode: .open,
            expiresAt: expiresAt,
            lastTransition: lastTransition,
            localConsoleOnly: localConsoleOnly,
            networkScope: networkScope
        )
    }

    public static func degradedClosed(
        reason: ControlErrorCode,
        lastTransition: Date?,
        localConsoleOnly: Bool
    ) -> Self {
        .init(
            mode: .degradedClosed,
            lastTransition: lastTransition,
            reason: reason,
            localConsoleOnly: localConsoleOnly
        )
    }

    public static func unavailable(reason: ControlErrorCode, localConsoleOnly: Bool) -> Self {
        .init(mode: .unavailable, reason: reason, localConsoleOnly: localConsoleOnly)
    }

    public static func recovering(localConsoleOnly: Bool) -> Self {
        .init(mode: .recovering, localConsoleOnly: localConsoleOnly)
    }
}
