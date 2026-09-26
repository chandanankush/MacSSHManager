import Foundation
import SharedProtocol

public protocol ExpiryEnforcing: Sendable {
    func reconcile() async -> AccessStatus
}

public actor ExpiryService: ExpiryEnforcing {
    private let leases: any LeaseStoring
    private let firewall: any FirewallControlling
    private let settings: any SecuritySettingsStoring
    private let remoteControl: any RemoteControlDetecting
    private let lan: any LANResolving
    private let tailscale: any TailscaleResolving
    private let audit: any AuditLogging
    private let closeController: any CloseOnlyControlling
    private let sessionMonitor: any SSHSessionReconciling

    public init(
        leases: any LeaseStoring,
        firewall: any FirewallControlling,
        settings: any SecuritySettingsStoring,
        remoteControl: any RemoteControlDetecting,
        lan: any LANResolving,
        tailscale: any TailscaleResolving,
        audit: any AuditLogging,
        closeController: any CloseOnlyControlling,
        sessionMonitor: any SSHSessionReconciling = NoopSSHSessionMonitor()
    ) {
        self.leases = leases
        self.firewall = firewall
        self.settings = settings
        self.remoteControl = remoteControl
        self.lan = lan
        self.tailscale = tailscale
        self.audit = audit
        self.closeController = closeController
        self.sessionMonitor = sessionMonitor
    }

    public func recoverSecurityService() async {
        // Always attempt session termination and lease removal before bounded
        // PF retry sleeps, including when the first firewall attempt fails.
        _ = await closeController.close(trigger: .recovery)
        await firewall.recoverAtStartup()
    }

    public func reconcile() async -> AccessStatus {
        let status: AccessStatus
        do {
            let state = try leases.currentState()
            switch state {
            case .absent:
                status = await closeController.close(trigger: .recovery)
            case .expired:
                status = await closeController.close(trigger: .expired)
            case .invalid:
                status = await closeController.close(trigger: .invalidState)
            case .active(let lease):
                status = try await reconcileActive(lease)
            }
        } catch {
            status = await closeController.close(trigger: .recovery)
        }
        await sessionMonitor.reconcile()
        return status
    }

    /// Any thrown error here (an unresolvable authorized LAN, or a firewall
    /// read failure) is caught by `reconcile()`'s outer `catch` and forces
    /// CLOSED -- matching the existing strict LAN-resolution behavior, now
    /// correctly scoped to only the paths the active lease actually
    /// authorized.
    private func reconcileActive(_ lease: Lease) async throws -> AccessStatus {
        let health = await firewall.health()
        guard health.pfEnabled, health.mode == .open else {
            return await closeController.close(trigger: .recovery)
        }

        let currentSettings = try settings.load()
        let remote = try await remoteControl.detect(localConsoleOnly: currentSettings.localConsoleOnly)
        if remote.enforcement == .denyOpen {
            return await closeController.close(trigger: .remoteControl)
        }

        // The PF anchor's actual content must still match exactly what this
        // lease authorized -- not merely "some rule is loaded and PF reports
        // open". Any drift (tampering, a degraded anchor, a stale rule from
        // an earlier transition) forces CLOSED and a fresh authorized OPEN.
        let effective = try await firewall.effectiveNetworkRules()
        guard effective?.lanInterfaceName == lease.lanInterfaceName,
              effective?.lanSourceCIDR == lease.lanSourceCIDR,
              effective?.tailscaleInterfaceName == lease.tailscaleInterfaceName,
              effective?.tailscaleAddressCIDR == lease.tailscaleAddressCIDR
        else {
            return await closeController.close(trigger: .recovery)
        }

        if lease.scope.includesLAN {
            let currentLAN = try lan.resolve()
            // Existing, deliberate behavior: a live LAN change is audited but
            // never adopted and never closes the window on its own -- the
            // originally captured rule keeps running until close or expiry.
            if currentLAN.interfaceName != lease.lanInterfaceName || currentLAN.sourceCIDR != lease.lanSourceCIDR {
                try audit.record(event(
                    kind: .networkChanged,
                    interfaceName: currentLAN.interfaceName,
                    sourceCIDR: currentLAN.sourceCIDR
                ))
            }
            if !currentLAN.isPrivate {
                try audit.record(event(
                    kind: .publicNetwork,
                    interfaceName: currentLAN.interfaceName,
                    sourceCIDR: currentLAN.sourceCIDR
                ))
            }
        }

        if lease.scope.includesTailscale {
            let currentTailscale: TailscaleSnapshot?
            currentTailscale = try? tailscale.resolve()
            let drifted = currentTailscale?.interfaceName != lease.tailscaleInterfaceName ||
                currentTailscale?.addressCIDR != lease.tailscaleAddressCIDR
            if drifted {
                // Disappearance, ambiguity, interface renumbering, or address
                // drift are all treated the same way: audit and close. A
                // stale rule bound to a freed utunN name must never be left
                // running, since that name can later be reused by an
                // unrelated interface.
                try? audit.record(event(
                    kind: .networkChanged,
                    tailscaleInterfaceName: currentTailscale?.interfaceName,
                    tailscaleAddressCIDR: currentTailscale?.addressCIDR
                ))
                return await closeController.close(trigger: .recovery)
            }
        }

        return .open(
            expiresAt: lease.expiresAt,
            lastTransition: lease.openedAt,
            localConsoleOnly: currentSettings.localConsoleOnly,
            networkScope: lease.scope
        )
    }

    private func event(
        kind: AuditEvent.Kind,
        interfaceName: String? = nil,
        sourceCIDR: String? = nil,
        tailscaleInterfaceName: String? = nil,
        tailscaleAddressCIDR: String? = nil
    ) -> AuditEvent {
        AuditEvent(
            kind: kind,
            timestamp: Date(),
            requestID: nil,
            reason: nil,
            duration: nil,
            userID: nil,
            auditSessionID: nil,
            interfaceName: interfaceName,
            sourceCIDR: sourceCIDR,
            outcome: .success,
            tailscaleInterfaceName: tailscaleInterfaceName,
            tailscaleAddressCIDR: tailscaleAddressCIDR
        )
    }
}
