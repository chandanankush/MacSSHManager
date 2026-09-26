import Foundation
import SharedProtocol

@MainActor
public protocol ControllerRequesting: AnyObject {
    func open(
        duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus
    func close() async throws -> AccessStatus
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus
    func status() async throws -> AccessStatus
    func retrySecurityService() async throws -> AccessStatus
    func recentAuditHistory(query: String?) async throws -> AuditHistoryPage
}

public extension ControllerRequesting {
    func retrySecurityService() async throws -> AccessStatus {
        throw ControlErrorCode.unavailable
    }
    func recentAuditHistory(query: String?) async throws -> AuditHistoryPage {
        throw ControlErrorCode.auditUnavailable
    }
}

@MainActor
public final class XPCControllerClient: ControllerRequesting {
    public static var controllerRequirement: String {
        controllerRequirement(localCertificateSHA1:
            Bundle.main.object(forInfoDictionaryKey: "ServerPCLocalSigningCertificateSHA1") as? String)
    }

    static func controllerRequirement(localCertificateSHA1: String?) -> String {
        let identifier = "identifier \"com.serverpc.ssh-control.controller\""
        guard let fingerprint = localCertificateSHA1 else {
            return identifier + " and anchor apple generic and certificate leaf[subject.OU] = \"8ZBMSE6RLV\""
        }
        guard fingerprint.utf8.count == 40,
              fingerprint.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) })
        else { return "never" }
        // This value is sealed into the signed bundle at package-build time.
        // Local signing still pins an exact certificate, never just a name.
        return identifier + " and certificate leaf = H\"\(fingerprint)\""
    }

    // Access is confined to MainActor methods. `deinit` is nonisolated in
    // Swift 6, so the explicit invalidation needs this narrowly scoped escape.
    nonisolated(unsafe) private let connection: NSXPCConnection

    public init() {
        connection = NSXPCConnection(
            machServiceName: InstalledPaths.controllerMachService,
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(with: SSHControlXPCProtocol.self)
        connection.setCodeSigningRequirement(Self.controllerRequirement)
        connection.activate()
    }

    deinit { connection.invalidate() }

    public func open(
        duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        try await request { proxy, reply in
            proxy.requestOpen(
                durationSeconds: NSNumber(value: duration.seconds),
                lan: NSNumber(value: scope.includesLAN),
                tailscale: NSNumber(value: scope.includesTailscale),
                authorizationExternalForm: authorization as NSData,
                requestNonce: nonce as NSUUID,
                withReply: reply
            )
        }
    }

    public func close() async throws -> AccessStatus {
        try await request { proxy, reply in proxy.requestClose(withReply: reply) }
    }

    public func setLocalConsoleOnly(
        _ enabled: Bool,
        authorization: Data?,
        nonce: UUID?
    ) async throws -> AccessStatus {
        try await request { proxy, reply in
            proxy.setLocalConsoleOnly(
                NSNumber(value: enabled),
                authorizationExternalForm: authorization as NSData?,
                requestNonce: nonce as NSUUID?,
                withReply: reply
            )
        }
    }

    public func status() async throws -> AccessStatus {
        try await request { proxy, reply in proxy.status(withReply: reply) }
    }

    public func retrySecurityService() async throws -> AccessStatus {
        try await request { proxy, reply in proxy.retrySecurityService(withReply: reply) }
    }

    public func recentAuditHistory(query: String?) async throws -> AuditHistoryPage {
        let response: AuditHistoryResponse = try await withCheckedThrowingContinuation { continuation in
            let gate = HistoryResponseContinuation(continuation)
            let errorHandler: @Sendable (Error) -> Void = { error in
                DispatchQueue.main.async { gate.fail(error) }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler) as? SSHControlXPCProtocol else {
                gate.fail(ControlErrorCode.unavailable)
                return
            }
            let reply: @Sendable (NSData) -> Void = { data in
                do {
                    let response = try Self.decodeHistoryResponse(data as Data)
                    DispatchQueue.main.async { gate.succeed(response) }
                } catch {
                    DispatchQueue.main.async { gate.fail(ControlErrorCode.malformedRequest) }
                }
            }
            proxy.recentAuditHistory(query: query as NSString?, withReply: reply)
        }
        if let error = response.error { throw error }
        guard let page = response.page else { throw ControlErrorCode.internalFailure }
        return page
    }

    nonisolated static func decodeHistoryResponse(_ data: Data) throws -> AuditHistoryResponse {
        guard data.count <= AuditHistoryResponse.maximumEncodedBytes else {
            throw ControlErrorCode.malformedRequest
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let response = try? decoder.decode(AuditHistoryResponse.self, from: data),
              (response.page?.entries.count ?? 0) <= AuditHistoryPage.maximumEntries
        else { throw ControlErrorCode.malformedRequest }
        return response
    }

    private func request(
        _ invoke: (SSHControlXPCProtocol, @escaping (NSData) -> Void) -> Void
    ) async throws -> AccessStatus {
        let response = try await withCheckedThrowingContinuation { continuation in
            let gate = ResponseContinuation(continuation)
            let errorHandler: @Sendable (Error) -> Void = { error in
                DispatchQueue.main.async {
                    gate.fail(error)
                }
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler) as? SSHControlXPCProtocol else {
                gate.fail(ControlErrorCode.unavailable)
                return
            }
            let reply: @Sendable (NSData) -> Void = { data in
                guard data.length <= ControlResponse.maximumEncodedBytes,
                      let response = try? JSONDecoder().decode(ControlResponse.self, from: data as Data)
                else {
                    DispatchQueue.main.async {
                        gate.fail(ControlErrorCode.malformedRequest)
                    }
                    return
                }
                DispatchQueue.main.async {
                    gate.succeed(response)
                }
            }
            invoke(proxy, reply)
        }
        if let error = response.error { throw error }
        guard let status = response.status else { throw ControlErrorCode.internalFailure }
        return status
    }
}

private final class HistoryResponseContinuation: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<AuditHistoryResponse, Error>?

    init(_ continuation: CheckedContinuation<AuditHistoryResponse, Error>) {
        self.continuation = continuation
    }

    func succeed(_ response: AuditHistoryResponse) {
        lock.withLock {
            continuation?.resume(returning: response)
            continuation = nil
        }
    }

    func fail(_ error: Error) {
        lock.withLock {
            continuation?.resume(throwing: error)
            continuation = nil
        }
    }
}

private final class ResponseContinuation: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ControlResponse, Error>?

    init(_ continuation: CheckedContinuation<ControlResponse, Error>) {
        self.continuation = continuation
    }

    func succeed(_ response: ControlResponse) {
        lock.withLock {
            continuation?.resume(returning: response)
            continuation = nil
        }
    }

    func fail(_ error: Error) {
        lock.withLock {
            continuation?.resume(throwing: error)
            continuation = nil
        }
    }
}
