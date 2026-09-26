import Foundation
import SharedProtocol

public enum ProductionComposition {
    public static func makeAccessController() throws -> AccessController {
        let components = try Components()
        return AccessController(
            authorization: OneUseAuthorizationValidator(),
            audit: components.audit,
            leases: components.leases,
            firewall: components.firewall,
            sshPolicy: SSHPolicyValidator(runner: components.runner),
            sessions: components.sessions,
            lan: components.lan,
            tailscale: components.tailscale,
            settings: components.settings,
            remoteControl: components.remoteControl,
            enforcerHealth: LaunchdEnforcerHealthChecker(runner: components.runner),
            continuousClock: components.clock,
            wallClock: components.clock,
            debug: DebugLog()
        )
    }

    public static func makeExpiryService() throws -> ExpiryService {
        let components = try Components()
        let closer = CloseCoordinator(
            audit: components.audit,
            leases: components.leases,
            firewall: components.firewall,
            sessions: components.sessions,
            settings: components.settings,
            wallClock: components.clock
        )
        return ExpiryService(
            leases: components.leases,
            firewall: components.firewall,
            settings: components.settings,
            remoteControl: components.remoteControl,
            lan: components.lan,
            tailscale: components.tailscale,
            audit: components.audit,
            closeController: closer,
            sessionMonitor: components.sessionMonitor
        )
    }

    private struct Components {
        let clock: SystemContinuousClock
        let runner: SystemFixedCommandRunner
        let leases: FileLeaseStore
        let firewall: PFController
        let audit: SecurityAuditLogger
        let sessions: SSHSessionTerminator
        let sessionMonitor: SSHSessionMonitor
        let lan: PhysicalLANResolver
        let tailscale: TailscaleRouteResolver
        let settings: FileSecuritySettingsStore
        let remoteControl: RemoteControlDetector

        init() throws {
            clock = try SystemContinuousClock()
            runner = SystemFixedCommandRunner()
            leases = FileLeaseStore(clock: clock)
            firewall = PFController(
                runner: runner,
                policyFile: try PolicyFile(path: InstalledPaths.stateRoot + "/runtime-anchor.conf"),
                installation: FilePFInstallationValidator(debug: DebugLog()),
                debug: DebugLog()
            )
            audit = SecurityAuditLogger()
            sessions = SSHSessionTerminator(runner: runner)
            sessionMonitor = SSHSessionMonitor(
                observer: SystemSSHSessionObserver(runner: runner),
                audit: audit
            )
            lan = PhysicalLANResolver()
            tailscale = TailscaleRouteResolver(debug: DebugLog())
            settings = FileSecuritySettingsStore()
            remoteControl = RemoteControlDetector(runner: runner)
        }
    }
}
