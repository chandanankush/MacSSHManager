import Foundation
import OSLog
import SharedProtocol

public actor CloseCoordinator: CloseOnlyControlling {
    private let audit: any AuditLogging
    private let leases: any LeaseStoring
    private let firewall: any FirewallControlling
    private let sessions: any SSHSessionTerminating
    private let settings: any SecuritySettingsStoring
    private let wallClock: any WallClockProviding
    private var lastRecoveryFailure: ControlErrorCode?
    private var recoveryClosureNeedsAudit = false
    private let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "recovery")

    public init(
        audit: any AuditLogging,
        leases: any LeaseStoring,
        firewall: any FirewallControlling,
        sessions: any SSHSessionTerminating,
        settings: any SecuritySettingsStoring,
        wallClock: any WallClockProviding
    ) {
        self.audit = audit
        self.leases = leases
        self.firewall = firewall
        self.sessions = sessions
        self.settings = settings
        self.wallClock = wallClock
    }

    public func close(trigger: CloseTrigger) async -> AccessStatus {
        let transitionTime = wallClock.now()
        let localConsoleOnly = (try? settings.load().localConsoleOnly) ?? false
        let isRecovery = trigger == .recovery || trigger == .invalidState
        if isRecovery {
            // A real lease (including invalid/expired state) being discarded
            // is an incident, even when every CLOSE operation succeeds.
            // Retain it across an audit-write failure after lease removal.
            if case .absent? = try? leases.currentState() {} else {
                recoveryClosureNeedsAudit = true
            }
        }
        var firewallFailure = false
        var degradedReason: ControlErrorCode?

        do {
            try await firewall.enforceClosed()
            guard try await firewall.effectiveMode() == .closed else {
                throw ControlErrorCode.pfUnavailable
            }
        } catch {
            firewallFailure = true
            degradedReason = .pfUnavailable
        }

        do {
            let result = try await sessions.terminateAll()
            if !result.complete { degradedReason = .terminationIncomplete }
        } catch {
            degradedReason = .terminationIncomplete
        }

        do {
            try leases.remove()
        } catch {
            degradedReason = degradedReason ?? .invalidLease
        }

        let kind: AuditEvent.Kind
        switch trigger {
        case .expired: kind = .expired
        case .recovery, .invalidState: kind = .recoveredClosed
        default: kind = degradedReason == nil ? .closed : .closeDegraded
        }
        let shouldRecord: Bool
        if isRecovery {
            if let degradedReason {
                shouldRecord = degradedReason != lastRecoveryFailure
                if shouldRecord { logger.error("entered degraded state reason=\(degradedReason.rawValue, privacy: .public)") }
            } else {
                shouldRecord = lastRecoveryFailure != nil || recoveryClosureNeedsAudit
                if shouldRecord { logger.notice("security enforcement recovered") }
            }
        } else {
            shouldRecord = true
        }
        do {
            guard shouldRecord else {
                if firewallFailure { return .unavailable(reason: .pfUnavailable, localConsoleOnly: localConsoleOnly) }
                if let degradedReason { return .degradedClosed(reason: degradedReason, lastTransition: transitionTime, localConsoleOnly: localConsoleOnly) }
                return .closed(lastTransition: transitionTime, localConsoleOnly: localConsoleOnly)
            }
            try audit.record(AuditEvent(
                kind: kind,
                timestamp: transitionTime,
                requestID: nil,
                reason: degradedReason,
                duration: nil,
                userID: RequestAuditContext.attribution?.userID,
                auditSessionID: RequestAuditContext.attribution?.auditSessionID,
                interfaceName: nil,
                sourceCIDR: nil,
                outcome: degradedReason == nil ? .success : .degraded,
                localConsoleOnly: localConsoleOnly
            ))
            if isRecovery {
                lastRecoveryFailure = degradedReason
                if degradedReason == nil { recoveryClosureNeedsAudit = false }
            }
        } catch {
            degradedReason = degradedReason ?? .auditUnavailable
        }

        if firewallFailure {
            return .unavailable(reason: .pfUnavailable, localConsoleOnly: localConsoleOnly)
        }
        if let degradedReason {
            return .degradedClosed(
                reason: degradedReason,
                lastTransition: transitionTime,
                localConsoleOnly: localConsoleOnly
            )
        }
        return .closed(lastTransition: transitionTime, localConsoleOnly: localConsoleOnly)
    }
}
