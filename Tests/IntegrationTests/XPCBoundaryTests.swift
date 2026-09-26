import Foundation
import Security
import XCTest
@testable import ControllerTransport
@testable import SecurityCore
@testable import SharedProtocol

final class XPCBoundaryTests: XCTestCase {
    func testUnknownDurationReturnsStructuredErrorWithoutCallingController() async {
        let controller = RecordingAccessController()
        let service = ControllerXPCService(controller: controller)

        let response = await service.handleOpen(
            durationSeconds: 17,
            lan: true,
            tailscale: false,
            authorization: Data(repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.size),
            nonce: UUID()
        )

        XCTAssertEqual(response.error, .invalidDuration)
        let openCalls = await controller.openCalls
        XCTAssertEqual(openCalls, 0)
    }

    func testOversizedAuthorizationFormIsRejectedAtTransportEdge() async {
        let controller = RecordingAccessController()
        let service = ControllerXPCService(controller: controller)

        let response = await service.handleOpen(
            durationSeconds: AccessDuration.minutes30.seconds,
            lan: true,
            tailscale: false,
            authorization: Data(repeating: 0, count: 4_096),
            nonce: UUID()
        )

        XCTAssertEqual(response.error, .invalidAuthorization)
        let openCalls = await controller.openCalls
        XCTAssertEqual(openCalls, 0)
    }

    func testValidOpenTranslatesOnlyTypedValues() async {
        let controller = RecordingAccessController()
        let service = ControllerXPCService(controller: controller)
        let form = Data(repeating: 1, count: MemoryLayout<AuthorizationExternalForm>.size)

        let response = await service.handleOpen(
            durationSeconds: AccessDuration.hours3.seconds,
            lan: true,
            tailscale: true,
            authorization: form,
            nonce: UUID()
        )

        XCTAssertNil(response.error)
        let durations = await controller.durations
        XCTAssertEqual(durations, [.hours3])
        let scopes = await controller.scopes
        XCTAssertEqual(scopes, [.lanAndTailscale])
    }

    func testOpenWithNeitherScopeSelectedIsRejectedWithoutCallingController() async {
        let controller = RecordingAccessController()
        let service = ControllerXPCService(controller: controller)
        let form = Data(repeating: 1, count: MemoryLayout<AuthorizationExternalForm>.size)

        let response = await service.handleOpen(
            durationSeconds: AccessDuration.minutes30.seconds,
            lan: false,
            tailscale: false,
            authorization: form,
            nonce: UUID()
        )

        XCTAssertEqual(response.error, .invalidNetworkScope)
        let openCalls = await controller.openCalls
        XCTAssertEqual(openCalls, 0)
    }

    func testEnablingSettingRejectsUnexpectedCredentialPayload() async {
        let service = ControllerXPCService(controller: RecordingAccessController())

        let response = await service.handleSetLocalConsoleOnly(
            enabledValue: 1,
            authorization: Data([1]),
            nonce: UUID()
        )

        XCTAssertEqual(response.error, .malformedRequest)
    }

    func testValidatedConnectionAttributionFlowsIntoControllerTask() async {
        let controller = AttributionRecordingController()
        let attribution = AuditAttribution(userID: 501, auditSessionID: 42)
        let service = ControllerXPCService(controller: controller, attribution: attribution)

        _ = await service.handleClose()

        let received = await controller.receivedAttribution
        XCTAssertEqual(received, attribution)
    }

    func testHistoryRequestReturnsTypedPage() async {
        let entry = AuditHistoryEntry(
            timestamp: Date(timeIntervalSince1970: 1_000),
            kind: .sshConnected,
            outcome: .success,
            reason: nil,
            duration: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            localConsoleOnly: nil,
            sshUser: "deploy",
            sourceAddress: "192.168.8.20"
        )
        let service = ControllerXPCService(
            controller: RecordingAccessController(),
            history: StaticHistoryReader(page: .init(entries: [entry]))
        )

        let response = await service.handleRecentAuditHistory(query: "deploy")

        XCTAssertEqual(response.page?.entries, [entry])
        XCTAssertNil(response.error)
    }

    func testOversizedHistoryQueryIsRejectedBeforeReading() async {
        let history = StaticHistoryReader(page: .init(entries: []))
        let service = ControllerXPCService(controller: RecordingAccessController(), history: history)

        let response = await service.handleRecentAuditHistory(query: String(repeating: "a", count: 129))

        XCTAssertEqual(response.error, .malformedRequest)
        XCTAssertEqual(history.readCount, 0)
    }

    func testEncodedHistoryReplyStaysWithinTransportLimitByKeepingNewestPrefix() async throws {
        let entries = (0..<250).map { index in
            AuditHistoryEntry(
                timestamp: Date(timeIntervalSince1970: TimeInterval(10_000 - index)),
                kind: .sshConnected,
                outcome: .success,
                reason: nil,
                duration: nil,
                interfaceName: nil,
                sourceCIDR: nil,
                localConsoleOnly: nil,
                sshUser: "deploy-\(index)-\(String(repeating: "x", count: 300))",
                sourceAddress: "192.168.8.20"
            )
        }
        let service = ControllerXPCService(
            controller: RecordingAccessController(),
            history: StaticHistoryReader(page: .init(entries: entries))
        )

        let data: Data = await withCheckedContinuation { continuation in
            service.recentAuditHistory(query: nil) { continuation.resume(returning: $0 as Data) }
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let response = try decoder.decode(AuditHistoryResponse.self, from: data)

        XCTAssertLessThanOrEqual(data.count, AuditHistoryResponse.maximumEncodedBytes)
        XCTAssertEqual(response.page?.entries.first, entries.first)
        XCTAssertLessThan(response.page?.entries.count ?? 0, entries.count)
    }

    func testEncodedHistoryReplyCapsInjectedReaderAtTwoHundredFiftyEntries() async throws {
        let entry = AuditHistoryEntry(
            timestamp: Date(timeIntervalSince1970: 1_000),
            kind: .closed,
            outcome: .success,
            reason: nil,
            duration: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            localConsoleOnly: false,
            sshUser: nil,
            sourceAddress: nil
        )
        let service = ControllerXPCService(
            controller: RecordingAccessController(),
            history: StaticHistoryReader(page: .init(entries: Array(repeating: entry, count: 300)))
        )

        let data: Data = await withCheckedContinuation { continuation in
            service.recentAuditHistory(query: nil) { continuation.resume(returning: $0 as Data) }
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let response = try decoder.decode(AuditHistoryResponse.self, from: data)

        XCTAssertEqual(response.page?.entries.count, AuditHistoryPage.maximumEntries)
    }
}

private final class StaticHistoryReader: AuditHistoryReading, @unchecked Sendable {
    private let lock = NSLock()
    private let page: AuditHistoryPage
    private var storedReadCount = 0

    init(page: AuditHistoryPage) { self.page = page }
    var readCount: Int { lock.withLock { storedReadCount } }
    func recent(query: String?) throws -> AuditHistoryPage {
        lock.withLock { storedReadCount += 1 }
        return page
    }
}

private actor RecordingAccessController: AccessControlling {
    private(set) var openCalls = 0
    private(set) var durations: [AccessDuration] = []
    private(set) var scopes: [SSHNetworkScope] = []

    func open(
        _ duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        openCalls += 1
        durations.append(duration)
        scopes.append(scope)
        return .open(
            expiresAt: Date().addingTimeInterval(60),
            lastTransition: Date(),
            localConsoleOnly: false,
            networkScope: scope
        )
    }
    func close(trigger: CloseTrigger) async -> AccessStatus {
        .closed(lastTransition: Date(), localConsoleOnly: false)
    }
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus {
        .closed(lastTransition: Date(), localConsoleOnly: enabled)
    }
    func status() async -> AccessStatus { .closed(lastTransition: nil, localConsoleOnly: false) }
}

private actor AttributionRecordingController: AccessControlling {
    private(set) var receivedAttribution: AuditAttribution?
    func open(
        _ duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        receivedAttribution = RequestAuditContext.attribution
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
    func close(trigger: CloseTrigger) async -> AccessStatus {
        receivedAttribution = RequestAuditContext.attribution
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus {
        receivedAttribution = RequestAuditContext.attribution
        return .closed(lastTransition: nil, localConsoleOnly: enabled)
    }
    func status() async -> AccessStatus {
        receivedAttribution = RequestAuditContext.attribution
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
}
