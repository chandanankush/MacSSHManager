import Combine
import Foundation
import SharedProtocol

@MainActor
public final class MenuModel: ObservableObject {
    @Published public var selectedDuration: AccessDuration = .default
    @Published public var scopeLAN = true
    @Published public var scopeTailscale = true
    @Published public private(set) var accessStatus = AccessStatus.closed(
        lastTransition: nil,
        localConsoleOnly: false
    )
    @Published public private(set) var isBusy = false
    @Published public private(set) var message: String?
    @Published public private(set) var servicePreparation: ServicePreparation = .ready
    @Published public private(set) var launchAtLogin = false

    private let client: any ControllerRequesting
    private let authorization: any AuthorizationRequesting
    private let services: any ServiceRegistering

    public init(
        client: any ControllerRequesting = XPCControllerClient(),
        authorization: any AuthorizationRequesting = SystemAuthorizationRequester(),
        services: any ServiceRegistering = SystemServiceRegistration()
    ) {
        self.client = client
        self.authorization = authorization
        self.services = services
    }

    public var menuSymbol: String {
        switch accessStatus.mode {
        case .open, .opening: "lock.open.fill"
        case .degradedClosed, .unavailable: "exclamationmark.shield.fill"
        default: "lock.fill"
        }
    }

    public func prepareServices() async {
        do {
            servicePreparation = try await services.prepare()
            launchAtLogin = services.launchAtLogin
            if servicePreparation == .ready { await refresh() }
        } catch {
            servicePreparation = .approvalRequired
            message = readable(error)
        }
    }

    public var canOpen: Bool {
        (scopeLAN || scopeTailscale) && accessStatus.mode != .recovering &&
            accessStatus.mode != .unavailable && accessStatus.mode != .degradedClosed
    }

    public func retrySecurityService() async {
        guard !isBusy else { return }
        isBusy = true
        message = nil
        accessStatus = .recovering(localConsoleOnly: accessStatus.localConsoleOnly)
        defer { isBusy = false }
        do {
            accessStatus = try await client.retrySecurityService()
        } catch {
            accessStatus = .unavailable(reason: .unavailable, localConsoleOnly: accessStatus.localConsoleOnly)
            message = readable(error)
        }
    }

    public func open(_ duration: AccessDuration) async {
        guard !isBusy else { return }
        guard let scope = try? SSHNetworkScope.from(lan: scopeLAN, tailscale: scopeTailscale) else {
            message = readable(ControlErrorCode.invalidNetworkScope)
            return
        }
        isBusy = true
        message = nil
        defer { isBusy = false }
        do {
            let grant = try await authorization.request(.open)
            defer { grant.destroy() }
            accessStatus = try await client.open(
                duration: duration,
                scope: scope,
                authorization: grant.form,
                nonce: grant.nonce
            )
        } catch {
            message = readable(error)
            await refresh()
        }
    }

    public func closeNow() async {
        guard !isBusy else { return }
        isBusy = true
        message = nil
        defer { isBusy = false }
        do {
            accessStatus = try await client.close()
        } catch {
            message = readable(error)
            await refresh()
        }
    }

    public func setLocalConsoleOnly(_ enabled: Bool) async {
        guard !isBusy else { return }
        isBusy = true
        message = nil
        defer { isBusy = false }
        do {
            if enabled {
                accessStatus = try await client.setLocalConsoleOnly(
                    true,
                    authorization: nil,
                    nonce: nil
                )
            } else {
                let grant = try await authorization.request(.disableLocalConsoleOnly)
                defer { grant.destroy() }
                accessStatus = try await client.setLocalConsoleOnly(
                    false,
                    authorization: grant.form,
                    nonce: grant.nonce
                )
            }
        } catch {
            message = readable(error)
            await refresh()
        }
    }

    public func refresh() async {
        do {
            accessStatus = try await client.status()
        } catch {
            accessStatus = .unavailable(reason: .unavailable, localConsoleOnly: accessStatus.localConsoleOnly)
            message = readable(error)
        }
    }

    public func poll() async {
        while !Task.isCancelled {
            await refresh()
            let seconds: UInt64 = accessStatus.mode == .open ? 5 : 30
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
        }
    }

    public func openApprovalSettings() { services.openApprovalSettings() }

    public func setLaunchAtLogin(_ enabled: Bool) async {
        do {
            if enabled {
                servicePreparation = try await services.prepare()
            }
            try services.setLaunchAtLogin(enabled)
            launchAtLogin = services.launchAtLogin
            if servicePreparation == .ready { await refresh() }
        } catch {
            launchAtLogin = services.launchAtLogin
            servicePreparation = .approvalRequired
            message = readable(error)
        }
    }

    private func readable(_ error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? "SSH control is unavailable."
    }
}
