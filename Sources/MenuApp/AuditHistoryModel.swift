import Combine
import Foundation
import SharedProtocol

@MainActor
public final class AuditHistoryModel: ObservableObject {
    @Published public private(set) var entries: [AuditHistoryEntry] = []
    @Published public var searchText = ""
    @Published public private(set) var isLoading = false
    @Published public private(set) var message: String?

    private let client: any ControllerRequesting
    private var searchTask: Task<Void, Never>?
    private var loadGeneration = 0

    public init(client: any ControllerRequesting = XPCControllerClient()) {
        self.client = client
    }

    public func load(query: String?) async {
        loadGeneration &+= 1
        let generation = loadGeneration
        isLoading = true
        message = nil
        defer {
            if generation == loadGeneration { isLoading = false }
        }
        do {
            let page = try await client.recentAuditHistory(query: bounded(query))
            guard generation == loadGeneration else { return }
            entries = page.entries
        } catch {
            guard generation == loadGeneration else { return }
            entries = []
            message = "Audit history is unavailable."
        }
    }

    public func scheduleSearch() {
        searchTask?.cancel()
        let query = searchText
        searchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 250_000_000)
            guard !Task.isCancelled else { return }
            await self?.load(query: query.isEmpty ? nil : query)
        }
    }

    private func bounded(_ query: String?) -> String? {
        guard var query else { return nil }
        while query.utf8.count > 128 { query.removeLast() }
        return query
    }
}
