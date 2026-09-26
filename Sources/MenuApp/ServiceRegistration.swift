import Foundation
import ServiceManagement

public enum ManagedService: Equatable, Sendable {
    case menuLoginItem
}

public enum ServicePreparation: Equatable, Sendable {
    case ready
    case approvalRequired
}

enum LoginItemAction: Equatable {
    case register
    case unregister
    case none
}

@MainActor
public protocol ServiceRegistering: AnyObject {
    var launchAtLogin: Bool { get }
    func prepare() async throws -> ServicePreparation
    func setLaunchAtLogin(_ enabled: Bool) throws
    func openApprovalSettings()
}

@MainActor
public final class SystemServiceRegistration: ServiceRegistering {
    private let loginItem = SMAppService.mainApp

    public init() {}

    public var launchAtLogin: Bool {
        loginItem.status == .enabled || loginItem.status == .requiresApproval
    }

    public func prepare() async throws -> ServicePreparation {
        .ready
    }

    public func setLaunchAtLogin(_ enabled: Bool) throws {
        switch Self.loginItemAction(requestedEnabled: enabled, status: loginItem.status) {
        case .register:
            try loginItem.register()
        case .unregister:
            try loginItem.unregister()
        case .none:
            break
        }
    }

    static func loginItemAction(
        requestedEnabled: Bool,
        status: SMAppService.Status
    ) -> LoginItemAction {
        if requestedEnabled {
            return status == .enabled || status == .requiresApproval ? .none : .register
        }
        return status == .enabled || status == .requiresApproval ? .unregister : .none
    }

    public func openApprovalSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    public static func unregisterLoginItemForUninstall() throws {
        try SMAppService.mainApp.unregister()
    }
}
