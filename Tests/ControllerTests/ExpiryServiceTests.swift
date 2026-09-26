import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class ExpiryServiceTests: XCTestCase {
    func testStartupClosesBeforeWaitingForPacketFilterRecovery() async {
        let close = RecordingCloseController()
        let firewall = SuspendedStartupFirewall()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.fixture)),
            firewall: firewall,
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: StaticResolver(.fixtureLAN),
            tailscale: ThrowingTailscale(),
            audit: NoopAudit(),
            closeController: close
        )
        let recovery = Task { await service.recoverSecurityService() }
        await firewall.waitUntilStarted()
        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.recovery], "Session and lease cleanup must precede PF retry waits")
        await firewall.resume()
        await recovery.value
    }

    func testExpiredLeaseClosesThroughCloseOnlyBoundary() async {
        let close = RecordingCloseController()
        let sessions = RecordingSessionMonitor()
        let service = ExpiryService(
            leases: StaticLeaseState(.expired(.fixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open)),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: StaticResolver(.fixtureLAN),
            tailscale: ThrowingTailscale(),
            audit: NoopAudit(),
            closeController: close,
            sessionMonitor: sessions
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.expired])
        let reconcileCount = await sessions.reconcileCount
        XCTAssertEqual(reconcileCount, 1)
    }

    func testNetworkChangeIsAuditedWithoutClosingOrAdopting() async {
        let close = RecordingCloseController()
        let audit = RecordingKindsAudit()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.fixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open)),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: StaticResolver(.init(interfaceName: "en1", sourceCIDR: "10.0.0.0/24", isPrivate: true)),
            tailscale: ThrowingTailscale(),
            audit: audit,
            closeController: close
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [])
        XCTAssertTrue(audit.kinds.contains(.networkChanged))
    }

    func testProhibitedRemoteControlClosesActiveLease() async {
        let close = RecordingCloseController()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.fixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open)),
            settings: StaticSettings(localConsoleOnly: true),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: ["screen"], enforcement: .denyOpen)),
            lan: StaticResolver(.fixtureLAN),
            tailscale: ThrowingTailscale(),
            audit: NoopAudit(),
            closeController: close
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.remoteControl])
    }

    func testPFAnchorMismatchAgainstTheLeaseClosesTheWindow() async {
        let close = RecordingCloseController()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.fixture)),
            firewall: StaticFirewallHealth(
                .init(pfEnabled: true, mode: .open),
                rules: .init(lanInterfaceName: "en9", lanSourceCIDR: "10.0.0.0/24", tailscaleInterfaceName: nil, tailscaleAddressCIDR: nil)
            ),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: StaticResolver(.fixtureLAN),
            tailscale: ThrowingTailscale(),
            audit: NoopAudit(),
            closeController: close
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.recovery])
    }

    func testTailscaleInterfaceDriftClosesTheWindowAndAudits() async {
        let close = RecordingCloseController()
        let audit = RecordingKindsAudit()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.tailscaleFixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open), rules: .tailscaleFixture),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: ThrowingLAN(),
            tailscale: StaticTailscale(.init(interfaceName: "utun9", addressCIDR: "100.101.102.200/32")),
            audit: audit,
            closeController: close
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.recovery])
        XCTAssertTrue(audit.kinds.contains(.networkChanged))
    }

    func testTailscaleDisappearanceClosesTheWindow() async {
        let close = RecordingCloseController()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.tailscaleFixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open), rules: .tailscaleFixture),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: ThrowingLAN(),
            tailscale: ThrowingTailscale(),
            audit: NoopAudit(),
            closeController: close
        )

        _ = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [.recovery])
    }

    func testMatchingTailscaleLeaseStaysOpen() async {
        let close = RecordingCloseController()
        let service = ExpiryService(
            leases: StaticLeaseState(.active(.tailscaleFixture)),
            firewall: StaticFirewallHealth(.init(pfEnabled: true, mode: .open), rules: .tailscaleFixture),
            settings: StaticSettings(),
            remoteControl: StaticRemoteDetection(.init(detectedIdentifiers: [], enforcement: .none)),
            lan: ThrowingLAN(),
            tailscale: StaticTailscale(.init(interfaceName: "utun6", addressCIDR: "100.101.102.103/32")),
            audit: NoopAudit(),
            closeController: close
        )

        let status = await service.reconcile()

        let triggers = await close.triggers
        XCTAssertEqual(triggers, [])
        XCTAssertEqual(status.mode, .open)
        XCTAssertEqual(status.networkScope, .tailscale)
    }
}

private extension Lease {
    static let fixture = Lease(
        requestID: UUID(), duration: .minutes30, deadlineUptime: 2_000,
        openedAt: Date(timeIntervalSince1970: 1_000), expiresAt: Date(timeIntervalSince1970: 2_800),
        bootSessionID: "boot-a", scope: .lan,
        lanInterfaceName: "en0", lanSourceCIDR: "192.168.1.0/24",
        tailscaleInterfaceName: nil, tailscaleAddressCIDR: nil,
        localConsoleOnly: false
    )
    static let tailscaleFixture = Lease(
        requestID: UUID(), duration: .minutes30, deadlineUptime: 2_000,
        openedAt: Date(timeIntervalSince1970: 1_000), expiresAt: Date(timeIntervalSince1970: 2_800),
        bootSessionID: "boot-a", scope: .tailscale,
        lanInterfaceName: nil, lanSourceCIDR: nil,
        tailscaleInterfaceName: "utun6", tailscaleAddressCIDR: "100.101.102.103/32",
        localConsoleOnly: false
    )
}
private extension LANSnapshot {
    static let fixtureLAN = LANSnapshot(interfaceName: "en0", sourceCIDR: "192.168.1.0/24", isPrivate: true)
}
private extension EffectiveNetworkRules {
    static let fixture = EffectiveNetworkRules(
        lanInterfaceName: "en0", lanSourceCIDR: "192.168.1.0/24",
        tailscaleInterfaceName: nil, tailscaleAddressCIDR: nil
    )
    static let tailscaleFixture = EffectiveNetworkRules(
        lanInterfaceName: nil, lanSourceCIDR: nil,
        tailscaleInterfaceName: "utun6", tailscaleAddressCIDR: "100.101.102.103/32"
    )
}
private struct StaticLeaseState: LeaseStoring {
    let state: LeaseState
    init(_ state: LeaseState) { self.state = state }
    func load() throws -> Lease? { if case .active(let lease) = state { lease } else { nil } }
    func save(_ lease: Lease) throws {}
    func remove() throws {}
    func currentState() throws -> LeaseState { state }
}
private struct StaticFirewallHealth: FirewallControlling {
    let value: FirewallHealth
    let rules: EffectiveNetworkRules?
    init(_ value: FirewallHealth, rules: EffectiveNetworkRules? = .fixture) {
        self.value = value
        self.rules = rules
    }
    func health() async -> FirewallHealth { value }
    func enforceClosed() async throws {}
    func open(for snapshot: SSHAccessNetworkSnapshot) async throws {}
    func effectiveMode() async throws -> FirewallMode { value.mode ?? .closed }
    func effectiveNetworkRules() async throws -> EffectiveNetworkRules? { rules }
}
private struct StaticSettings: SecuritySettingsStoring {
    let localConsoleOnly: Bool
    init(localConsoleOnly: Bool = false) { self.localConsoleOnly = localConsoleOnly }
    func load() throws -> SecuritySettings { .init(localConsoleOnly: localConsoleOnly) }
    func save(_ settings: SecuritySettings) throws {}
}
private struct StaticRemoteDetection: RemoteControlDetecting {
    let value: RemoteControlDetection
    init(_ value: RemoteControlDetection) { self.value = value }
    func detect(localConsoleOnly: Bool) async throws -> RemoteControlDetection { value }
}
private struct StaticResolver: LANResolving {
    let value: LANSnapshot
    init(_ value: LANSnapshot) { self.value = value }
    func resolve() throws -> LANSnapshot { value }
}
private struct ThrowingLAN: LANResolving {
    func resolve() throws -> LANSnapshot { throw ControlErrorCode.networkUnavailable }
}
private struct StaticTailscale: TailscaleResolving {
    let value: TailscaleSnapshot
    init(_ value: TailscaleSnapshot) { self.value = value }
    func resolve() throws -> TailscaleSnapshot { value }
}
private struct ThrowingTailscale: TailscaleResolving {
    func resolve() throws -> TailscaleSnapshot { throw ControlErrorCode.tailscaleUnavailable }
}
private actor RecordingCloseController: CloseOnlyControlling {
    private(set) var triggers: [CloseTrigger] = []
    func close(trigger: CloseTrigger) async -> AccessStatus {
        triggers.append(trigger)
        return .closed(lastTransition: Date(), localConsoleOnly: false)
    }
}
private actor RecordingSessionMonitor: SSHSessionReconciling {
    private(set) var reconcileCount = 0
    func reconcile() async { reconcileCount += 1 }
}
private final class RecordingKindsAudit: AuditLogging, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [AuditEvent.Kind] = []
    var kinds: [AuditEvent.Kind] { lock.withLock { stored } }
    func record(_ event: AuditEvent) throws { lock.withLock { stored.append(event.kind) } }
}
private struct NoopAudit: AuditLogging { func record(_ event: AuditEvent) throws {} }

private actor SuspendedStartupFirewall: FirewallControlling {
    private var started = false
    private var continuation: CheckedContinuation<Void, Never>?
    func health() async -> FirewallHealth { .init(pfEnabled: false, mode: nil) }
    func enforceClosed() async throws { throw ControlErrorCode.pfUnavailable }
    func open(for snapshot: SSHAccessNetworkSnapshot) async throws {}
    func effectiveMode() async throws -> FirewallMode { throw ControlErrorCode.pfUnavailable }
    func effectiveNetworkRules() async throws -> EffectiveNetworkRules? { nil }
    func recoverAtStartup() async {
        started = true
        await withCheckedContinuation { continuation = $0 }
    }
    func waitUntilStarted() async {
        while !started { await Task.yield() }
    }
    func resume() {
        continuation?.resume()
        continuation = nil
    }
}
