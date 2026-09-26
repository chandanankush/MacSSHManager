import Foundation
import OSLog
import Security
import SecurityCore
import SharedProtocol

@objcMembers
public final class ControllerXPCService: NSObject, SSHControlXPCProtocol, @unchecked Sendable {
    private let controller: any AccessControlling
    private let history: any AuditHistoryReading
    private let attribution: AuditAttribution?
    private let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "xpc")

    public init(
        controller: any AccessControlling,
        history: any AuditHistoryReading = AuditHistoryReader(),
        attribution: AuditAttribution? = nil
    ) {
        self.controller = controller
        self.history = history
        self.attribution = attribution
        super.init()
    }

    public func handleOpen(
        durationSeconds: Int,
        lan: Bool,
        tailscale: Bool,
        authorization: Data,
        nonce: UUID
    ) async -> ControlResponse {
        await RequestAuditContext.$attribution.withValue(attribution) {
            await performOpen(
                durationSeconds: durationSeconds,
                lan: lan,
                tailscale: tailscale,
                authorization: authorization,
                nonce: nonce
            )
        }
    }

    private func performOpen(
        durationSeconds: Int,
        lan: Bool,
        tailscale: Bool,
        authorization: Data,
        nonce: UUID
    ) async -> ControlResponse {
        guard let duration = AccessDuration(seconds: durationSeconds) else {
            return .failure(.invalidDuration)
        }
        guard authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
            return .failure(.invalidAuthorization)
        }
        do {
            let scope = try SSHNetworkScope.from(lan: lan, tailscale: tailscale)
            return .success(try await controller.open(
                duration,
                scope: scope,
                authorization: authorization,
                nonce: nonce
            ))
        } catch {
            return .failure(error as? ControlErrorCode ?? .internalFailure)
        }
    }

    public func handleClose() async -> ControlResponse {
        await RequestAuditContext.$attribution.withValue(attribution) {
            .success(await controller.close(trigger: .manual))
        }
    }

    public func handleSetLocalConsoleOnly(
        enabledValue: Int,
        authorization: Data?,
        nonce: UUID?
    ) async -> ControlResponse {
        await RequestAuditContext.$attribution.withValue(attribution) {
            await performSetLocalConsoleOnly(
                enabledValue: enabledValue,
                authorization: authorization,
                nonce: nonce
            )
        }
    }

    private func performSetLocalConsoleOnly(
        enabledValue: Int,
        authorization: Data?,
        nonce: UUID?
    ) async -> ControlResponse {
        guard enabledValue == 0 || enabledValue == 1 else {
            return .failure(.malformedRequest)
        }
        let enabled = enabledValue == 1
        if enabled {
            guard authorization == nil, nonce == nil else { return .failure(.malformedRequest) }
        } else {
            guard let authorization,
                  authorization.count == MemoryLayout<AuthorizationExternalForm>.size,
                  nonce != nil
            else {
                return .failure(.invalidAuthorization)
            }
        }
        do {
            return .success(try await controller.setLocalConsoleOnly(
                enabled,
                authorization: authorization,
                nonce: nonce
            ))
        } catch {
            return .failure(error as? ControlErrorCode ?? .internalFailure)
        }
    }

    public func handleStatus() async -> ControlResponse {
        await RequestAuditContext.$attribution.withValue(attribution) {
            .success(await controller.status())
        }
    }

    public func handleRetrySecurityService() async -> ControlResponse {
        logger.notice("privileged security recovery requested")
        return .success(await controller.recoverSecurityService())
    }

    public func handleRecentAuditHistory(query: String?) async -> AuditHistoryResponse {
        guard query.map({ $0.utf8.count <= 128 }) ?? true else {
            return .failure(.malformedRequest)
        }
        do {
            return .success(try history.recent(query: query))
        } catch {
            return .failure(error as? ControlErrorCode ?? .auditUnavailable)
        }
    }

    public func requestOpen(
        durationSeconds: NSNumber,
        lan: NSNumber,
        tailscale: NSNumber,
        authorizationExternalForm: NSData,
        requestNonce: NSUUID,
        withReply reply: @escaping (NSData) -> Void
    ) {
        let reply = ReplyBox(reply)
        let seconds = durationSeconds.intValue
        guard durationSeconds.doubleValue == Double(seconds) else {
            reply.send(encode(.failure(.invalidDuration)))
            return
        }
        let lanValue = lan.intValue
        let tailscaleValue = tailscale.intValue
        guard lan.doubleValue == Double(lanValue), lanValue == 0 || lanValue == 1,
              tailscale.doubleValue == Double(tailscaleValue), tailscaleValue == 0 || tailscaleValue == 1
        else {
            reply.send(encode(.failure(.malformedRequest)))
            return
        }
        let form = authorizationExternalForm as Data
        let nonce = requestNonce as UUID
        Task {
            reply.send(encode(await handleOpen(
                durationSeconds: seconds,
                lan: lanValue == 1,
                tailscale: tailscaleValue == 1,
                authorization: form,
                nonce: nonce
            )))
        }
    }

    public func requestClose(withReply reply: @escaping (NSData) -> Void) {
        let reply = ReplyBox(reply)
        Task { reply.send(encode(await handleClose())) }
    }

    public func setLocalConsoleOnly(
        _ enabled: NSNumber,
        authorizationExternalForm: NSData?,
        requestNonce: NSUUID?,
        withReply reply: @escaping (NSData) -> Void
    ) {
        let reply = ReplyBox(reply)
        let value = enabled.intValue
        guard enabled.doubleValue == Double(value) else {
            reply.send(encode(.failure(.malformedRequest)))
            return
        }
        let form = authorizationExternalForm as Data?
        let nonce = requestNonce as UUID?
        Task {
            reply.send(encode(await handleSetLocalConsoleOnly(
                enabledValue: value,
                authorization: form,
                nonce: nonce
            )))
        }
    }

    public func status(withReply reply: @escaping (NSData) -> Void) {
        let reply = ReplyBox(reply)
        Task { reply.send(encode(await handleStatus())) }
    }

    public func retrySecurityService(withReply reply: @escaping (NSData) -> Void) {
        let reply = ReplyBox(reply)
        Task { reply.send(encode(await handleRetrySecurityService())) }
    }

    public func recentAuditHistory(query: NSString?, withReply reply: @escaping (NSData) -> Void) {
        let reply = ReplyBox(reply)
        let query = query as String?
        Task { reply.send(encodeHistory(await handleRecentAuditHistory(query: query))) }
    }

    private func encode(_ response: ControlResponse) -> NSData {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(response),
              data.count <= ControlResponse.maximumEncodedBytes
        else {
            return (try? encoder.encode(ControlResponse.failure(.internalFailure)) as NSData) ?? NSData()
        }
        return data as NSData
    }

    private func encodeHistory(_ response: AuditHistoryResponse) -> NSData {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        if let error = response.error {
            return ((try? encoder.encode(AuditHistoryResponse.failure(error))) ?? Data()) as NSData
        }

        var entries = Array((response.page?.entries ?? []).prefix(AuditHistoryPage.maximumEntries))
        while true {
            let candidate = AuditHistoryResponse.success(.init(entries: entries))
            if let data = try? encoder.encode(candidate), data.count <= AuditHistoryResponse.maximumEncodedBytes {
                return data as NSData
            }
            guard !entries.isEmpty else {
                return ((try? encoder.encode(AuditHistoryResponse.failure(.internalFailure))) ?? Data()) as NSData
            }
            entries.removeLast()
        }
    }
}

private final class ReplyBox: @unchecked Sendable {
    private let callback: (NSData) -> Void
    init(_ callback: @escaping (NSData) -> Void) { self.callback = callback }
    func send(_ data: NSData) { callback(data) }
}
