import Foundation
import XCTest
@testable import MenuAppCore
@testable import SharedProtocol

@MainActor
final class AuditHistoryModelTests: XCTestCase {
    func testLoadShowsHistoryReturnedByController() async {
        let entry = historyEntry(user: "deploy")
        let controller = HistoryController(result: .success(.init(entries: [entry])))
        let model = AuditHistoryModel(client: controller)

        await model.load(query: "deploy")

        XCTAssertEqual(model.entries, [entry])
        XCTAssertNil(model.message)
        XCTAssertEqual(controller.queries, ["deploy"])
    }

    func testUnavailableHistoryLeavesAccessControllerUntouched() async {
        let controller = HistoryController(result: .failure(ControlErrorCode.auditUnavailable))
        let model = AuditHistoryModel(client: controller)

        await model.load(query: nil)

        XCTAssertEqual(model.entries, [])
        XCTAssertEqual(model.message, "Audit history is unavailable.")
        XCTAssertEqual(controller.controlCalls, 0)
    }

    func testOlderSlowSearchCannotReplaceNewerResults() async {
        let controller = OutOfOrderHistoryController(
            slow: historyEntry(user: "old"),
            fast: historyEntry(user: "new")
        )
        let model = AuditHistoryModel(client: controller)

        let slowLoad = Task { await model.load(query: "slow") }
        try? await Task.sleep(nanoseconds: 10_000_000)
        await model.load(query: "fast")
        await slowLoad.value

        XCTAssertEqual(model.entries.map(\.sshUser), ["new"])
    }

    func testSearchIsDebouncedBeforeLoading() async {
        let controller = HistoryController(result: .success(.init(entries: [])))
        let loaded = expectation(description: "Debounced history request")
        controller.onHistoryRequest = { loaded.fulfill() }
        let model = AuditHistoryModel(client: controller)

        model.searchText = "dep"
        model.scheduleSearch()
        model.searchText = "deploy"
        model.scheduleSearch()
        // The debounce is a minimum delay; the scheduler may run later under load.
        await fulfillment(of: [loaded], timeout: 5)

        XCTAssertEqual(controller.queries, ["deploy"])
    }

    private func historyEntry(user: String) -> AuditHistoryEntry {
        AuditHistoryEntry(
            timestamp: Date(timeIntervalSince1970: 1_000),
            kind: .sshConnected,
            outcome: .success,
            reason: nil,
            duration: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            localConsoleOnly: nil,
            sshUser: user,
            sourceAddress: "192.168.8.20"
        )
    }
}

@MainActor
private final class OutOfOrderHistoryController: ControllerRequesting {
    let slow: AuditHistoryEntry
    let fast: AuditHistoryEntry
    init(slow: AuditHistoryEntry, fast: AuditHistoryEntry) { self.slow = slow; self.fast = fast }

    func recentAuditHistory(query: String?) async throws -> AuditHistoryPage {
        if query == "slow" { try await Task.sleep(nanoseconds: 50_000_000) }
        return .init(entries: [query == "slow" ? slow : fast])
    }
    func open(
        duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus { .closed(lastTransition: nil, localConsoleOnly: false) }
    func close() async throws -> AccessStatus { .closed(lastTransition: nil, localConsoleOnly: false) }
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus { .closed(lastTransition: nil, localConsoleOnly: enabled) }
    func status() async throws -> AccessStatus { .closed(lastTransition: nil, localConsoleOnly: false) }
}

@MainActor
private final class HistoryController: ControllerRequesting {
    private let result: Result<AuditHistoryPage, Error>
    private(set) var queries: [String?] = []
    private(set) var controlCalls = 0
    var onHistoryRequest: (() -> Void)?

    init(result: Result<AuditHistoryPage, Error>) { self.result = result }

    func recentAuditHistory(query: String?) async throws -> AuditHistoryPage {
        queries.append(query)
        onHistoryRequest?()
        return try result.get()
    }
    func open(
        duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        controlCalls += 1
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
    func close() async throws -> AccessStatus {
        controlCalls += 1
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus {
        controlCalls += 1
        return .closed(lastTransition: nil, localConsoleOnly: enabled)
    }
    func status() async throws -> AccessStatus {
        controlCalls += 1
        return .closed(lastTransition: nil, localConsoleOnly: false)
    }
}
