import Foundation
import OSLog
import SecurityCore
import SharedProtocol

private final class CloseOnceResult: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = EXIT_FAILURE

    func store(_ value: Int32) { lock.withLock { stored = value } }
    func load() -> Int32 { lock.withLock { stored } }
}

do {
    let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "startup")
    let service = try ProductionComposition.makeExpiryService()
    let arguments = Array(CommandLine.arguments.dropFirst())
    if arguments == ["--close-once"] {
        let completion = DispatchSemaphore(value: 0)
        let result = CloseOnceResult()
        Task.detached {
            let status = await service.reconcile()
            result.store(status.mode == .closed ? EXIT_SUCCESS : EXIT_FAILURE)
            completion.signal()
        }
        completion.wait()
        exit(result.load())
    }
    guard arguments.isEmpty else { exit(EXIT_FAILURE) }
    Task {
        logger.notice("expiry enforcer starting bounded packet-filter recovery")
        await service.recoverSecurityService()
        while !Task.isCancelled {
            _ = await service.reconcile()
            try? await Task.sleep(nanoseconds: 15_000_000_000)
        }
    }
    dispatchMain()
} catch {
    exit(EXIT_FAILURE)
}
