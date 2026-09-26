import Foundation
import SharedProtocol

public protocol WallClockProviding: Sendable {
    func now() -> Date
}

extension SystemContinuousClock: WallClockProviding {
    public func now() -> Date { wallNow }
}

public enum CloseTrigger: String, Codable, Equatable, Sendable {
    case manual
    case expired
    case recovery
    case invalidState
    case remoteControl
    case openFailure
}

public protocol CloseOnlyControlling: Sendable {
    func close(trigger: CloseTrigger) async -> AccessStatus
}

public protocol AccessControlling: CloseOnlyControlling {
    func open(
        _ duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus
    func setLocalConsoleOnly(
        _ enabled: Bool,
        authorization: Data?,
        nonce: UUID?
    ) async throws -> AccessStatus
    func status() async -> AccessStatus
    func recoverSecurityService() async -> AccessStatus
}

public extension AccessControlling {
    func recoverSecurityService() async -> AccessStatus { await status() }
}

public actor AccessController: AccessControlling {
    private let authorization: any AuthorizationValidating
    private let audit: any AuditLogging
    private let leases: any LeaseStoring
    private let firewall: any FirewallControlling
    private let sshPolicy: any SSHPolicyValidating
    private let lan: any LANResolving
    private let tailscale: any TailscaleResolving
    private let settings: any SecuritySettingsStoring
    private let remoteControl: any RemoteControlDetecting
    private let enforcerHealth: any EnforcerHealthChecking
    private let continuousClock: any ContinuousTimeProviding
    private let wallClock: any WallClockProviding
    private let closeCoordinator: any CloseOnlyControlling
    private let debug: any DebugLogging
    private var transitionGeneration: UInt64 = 0
    private var securityRecoveryInProgress = false
    private var recoveryCleanupFailure: ControlErrorCode?

    public init(
        authorization: any AuthorizationValidating,
        audit: any AuditLogging,
        leases: any LeaseStoring,
        firewall: any FirewallControlling,
        sshPolicy: any SSHPolicyValidating,
        sessions: any SSHSessionTerminating,
        lan: any LANResolving,
        tailscale: any TailscaleResolving,
        settings: any SecuritySettingsStoring,
        remoteControl: any RemoteControlDetecting,
        enforcerHealth: any EnforcerHealthChecking,
        continuousClock: any ContinuousTimeProviding,
        wallClock: any WallClockProviding,
        debug: any DebugLogging = NoopDebugLog()
    ) {
        self.authorization = authorization
        self.audit = audit
        self.leases = leases
        self.firewall = firewall
        self.sshPolicy = sshPolicy
        self.lan = lan
        self.tailscale = tailscale
        self.settings = settings
        self.remoteControl = remoteControl
        self.enforcerHealth = enforcerHealth
        self.continuousClock = continuousClock
        self.wallClock = wallClock
        self.debug = debug
        closeCoordinator = CloseCoordinator(
            audit: audit,
            leases: leases,
            firewall: firewall,
            sessions: sessions,
            settings: settings,
            wallClock: wallClock
        )
    }

    public func open(
        _ duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization authorizationForm: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        guard !securityRecoveryInProgress else { throw ControlErrorCode.pfUnavailable }
        if let recoveryCleanupFailure { throw recoveryCleanupFailure }
        transitionGeneration &+= 1
        let generation = transitionGeneration
        let requestID = nonce
        do {
            guard await firewall.startupState() == .ready else {
                throw ControlErrorCode.pfUnavailable
            }
            try requireCurrent(generation)
            try authorization.consume(form: authorizationForm, nonce: nonce, action: .open)
            let currentSettings = try settings.load()
            try audit.record(event(
                kind: .openRequested,
                requestID: requestID,
                duration: duration,
                networkScope: scope,
                outcome: .success
            ))

            let firewallHealth = await firewall.health()
            try requireCurrent(generation)
            guard firewallHealth.pfEnabled, firewallHealth.mode != nil else {
                debug.log("open(): firewall.health() reported pfEnabled=\(firewallHealth.pfEnabled) mode=\(String(describing: firewallHealth.mode))")
                throw ControlErrorCode.pfUnavailable
            }
            guard await enforcerHealth.isHealthy() else {
                throw ControlErrorCode.unavailable
            }
            try requireCurrent(generation)
            let policy = try await sshPolicy.validate()
            try requireCurrent(generation)
            guard policy.isSafe else { throw policy.reason ?? ControlErrorCode.unsafeSSHPolicy }

            let remote = try await remoteControl.detect(localConsoleOnly: currentSettings.localConsoleOnly)
            try requireCurrent(generation)
            guard remote.enforcement != .denyOpen else { throw ControlErrorCode.remoteControlActive }

            let lanSnapshot: LANSnapshot?
            if scope.includesLAN {
                lanSnapshot = try lan.resolve()
                try requireCurrent(generation)
                if let lanSnapshot, !lanSnapshot.isPrivate {
                    try audit.record(event(
                        kind: .publicNetwork,
                        requestID: requestID,
                        duration: duration,
                        interfaceName: lanSnapshot.interfaceName,
                        sourceCIDR: lanSnapshot.sourceCIDR,
                        outcome: .success
                    ))
                }
            } else {
                lanSnapshot = nil
            }

            let tailscaleSnapshot: TailscaleSnapshot?
            if scope.includesTailscale {
                tailscaleSnapshot = try tailscale.resolve()
                try requireCurrent(generation)
            } else {
                tailscaleSnapshot = nil
            }

            let networkSnapshot = try SSHAccessNetworkSnapshot(
                scope: scope,
                lan: lanSnapshot,
                tailscale: tailscaleSnapshot
            )

            let openedAt = wallClock.now()
            let lease = Lease(
                requestID: requestID,
                duration: duration,
                deadlineUptime: continuousClock.uptimeIncludingSleep + TimeInterval(duration.seconds),
                openedAt: openedAt,
                expiresAt: openedAt.addingTimeInterval(TimeInterval(duration.seconds)),
                bootSessionID: continuousClock.bootSessionID,
                scope: scope,
                lanInterfaceName: lanSnapshot?.interfaceName,
                lanSourceCIDR: lanSnapshot?.sourceCIDR,
                tailscaleInterfaceName: tailscaleSnapshot?.interfaceName,
                tailscaleAddressCIDR: tailscaleSnapshot?.addressCIDR,
                localConsoleOnly: currentSettings.localConsoleOnly
            )
            try requireCurrent(generation)
            try leases.save(lease)
            try await firewall.open(for: networkSnapshot)
            try requireCurrent(generation)
            guard try await firewall.effectiveMode() == .open else {
                throw ControlErrorCode.pfUnavailable
            }
            try requireCurrent(generation)
            try audit.record(event(
                kind: .opened,
                requestID: requestID,
                duration: duration,
                networkScope: scope,
                interfaceName: lanSnapshot?.interfaceName,
                sourceCIDR: lanSnapshot?.sourceCIDR,
                tailscaleInterfaceName: tailscaleSnapshot?.interfaceName,
                tailscaleAddressCIDR: tailscaleSnapshot?.addressCIDR,
                outcome: .success
            ))
            return .open(
                expiresAt: lease.expiresAt,
                lastTransition: openedAt,
                localConsoleOnly: currentSettings.localConsoleOnly,
                networkScope: scope
            )
        } catch {
            let reason = error as? ControlErrorCode ?? .internalFailure
            debug.log("open() requestID=\(requestID) duration=\(duration) scope=\(scope) failed: \(error) -> reason=\(reason.rawValue)")
            _ = await close(trigger: .openFailure)
            try? audit.record(event(
                kind: .openFailed,
                requestID: requestID,
                reason: reason,
                duration: duration,
                networkScope: scope,
                outcome: .failure
            ))
            throw reason
        }
    }

    public func close(trigger: CloseTrigger) async -> AccessStatus {
        transitionGeneration &+= 1
        let result = await closeCoordinator.close(trigger: trigger)
        if result.mode == .closed { recoveryCleanupFailure = nil }
        return result
    }

    public func setLocalConsoleOnly(
        _ enabled: Bool,
        authorization authorizationForm: Data?,
        nonce: UUID?
    ) async throws -> AccessStatus {
        let current = try settings.load()
        guard current.localConsoleOnly != enabled else { return await status() }
        transitionGeneration &+= 1
        let generation = transitionGeneration

        if !enabled {
            guard let authorizationForm, let nonce else {
                throw ControlErrorCode.invalidAuthorization
            }
            try authorization.consume(
                form: authorizationForm,
                nonce: nonce,
                action: .disableLocalConsoleOnly
            )
        }
        try requireCurrent(generation)

        try settings.save(SecuritySettings(localConsoleOnly: enabled))
        do {
            try audit.record(event(
                kind: .settingChanged,
                requestID: nonce,
                localConsoleOnly: enabled,
                outcome: .success
            ))
        } catch {
            if !enabled {
                try? settings.save(SecuritySettings(localConsoleOnly: true))
            }
            throw ControlErrorCode.auditUnavailable
        }

        if enabled {
            let detection = try await remoteControl.detect(localConsoleOnly: true)
            try requireCurrent(generation)
            if detection.enforcement == .denyOpen {
                return await close(trigger: .remoteControl)
            }
        }
        return await status()
    }

    public func status() async -> AccessStatus {
        let localConsoleOnly = (try? settings.load().localConsoleOnly) ?? false
        guard !securityRecoveryInProgress else {
            return .recovering(localConsoleOnly: localConsoleOnly)
        }
        switch await firewall.startupState() {
        case .idle, .recovering:
            return .recovering(localConsoleOnly: localConsoleOnly)
        case .failed(let reason):
            return .unavailable(reason: reason, localConsoleOnly: localConsoleOnly)
        case .ready:
            break
        }
        let health = await firewall.health()
        guard health.pfEnabled, let mode = health.mode else {
            return .unavailable(reason: .pfUnavailable, localConsoleOnly: localConsoleOnly)
        }
        if let recoveryCleanupFailure {
            return .degradedClosed(reason: recoveryCleanupFailure, lastTransition: nil, localConsoleOnly: localConsoleOnly)
        }
        let state = (try? leases.currentState()) ?? .invalid
        switch (state, mode) {
        case (.absent, .closed):
            return .closed(lastTransition: nil, localConsoleOnly: localConsoleOnly)
        case (.active(let lease), .open):
            return .open(
                expiresAt: lease.expiresAt,
                lastTransition: lease.openedAt,
                localConsoleOnly: localConsoleOnly,
                networkScope: lease.scope
            )
        case (.active, .closed):
            return .degradedClosed(
                reason: .invalidLease,
                lastTransition: nil,
                localConsoleOnly: localConsoleOnly
            )
        default:
            return .unavailable(reason: .invalidLease, localConsoleOnly: localConsoleOnly)
        }
    }

    public func recoverSecurityService() async -> AccessStatus {
        guard !securityRecoveryInProgress else {
            return .recovering(localConsoleOnly: (try? settings.load().localConsoleOnly) ?? false)
        }
        // Recovery is a CLOSE transition: supersede any OPEN already suspended
        // in a dependency, and reject new OPENs until the entire recovery ends.
        securityRecoveryInProgress = true
        transitionGeneration &+= 1
        _ = await closeCoordinator.close(trigger: .recovery)
        await firewall.recoverAtStartup()
        // Recheck cleanup after recovery, and retain non-firewall failures in
        // status/OPEN gating rather than hiding surviving sessions or a failed
        // audit write behind an otherwise healthy CLOSED anchor.
        let cleanup = await closeCoordinator.close(trigger: .recovery)
        recoveryCleanupFailure = cleanup.mode == .closed ? nil : cleanup.reason
        securityRecoveryInProgress = false
        return await status()
    }

    private func event(
        kind: AuditEvent.Kind,
        requestID: UUID? = nil,
        reason: ControlErrorCode? = nil,
        duration: AccessDuration? = nil,
        networkScope: SSHNetworkScope? = nil,
        interfaceName: String? = nil,
        sourceCIDR: String? = nil,
        tailscaleInterfaceName: String? = nil,
        tailscaleAddressCIDR: String? = nil,
        localConsoleOnly: Bool? = nil,
        outcome: AuditEvent.Outcome
    ) -> AuditEvent {
        AuditEvent(
            kind: kind,
            timestamp: wallClock.now(),
            requestID: requestID,
            reason: reason,
            duration: duration,
            userID: RequestAuditContext.attribution?.userID,
            auditSessionID: RequestAuditContext.attribution?.auditSessionID,
            interfaceName: interfaceName,
            sourceCIDR: sourceCIDR,
            outcome: outcome,
            networkScope: networkScope,
            tailscaleInterfaceName: tailscaleInterfaceName,
            tailscaleAddressCIDR: tailscaleAddressCIDR,
            localConsoleOnly: localConsoleOnly
        )
    }

    private func requireCurrent(_ generation: UInt64) throws {
        guard transitionGeneration == generation else { throw ControlErrorCode.unavailable }
    }
}
