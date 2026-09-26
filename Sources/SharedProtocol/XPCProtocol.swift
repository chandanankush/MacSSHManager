import Foundation

@objc(SSHControlXPCProtocol)
public protocol SSHControlXPCProtocol {
    func requestOpen(
        durationSeconds: NSNumber,
        lan: NSNumber,
        tailscale: NSNumber,
        authorizationExternalForm: NSData,
        requestNonce: NSUUID,
        withReply reply: @escaping (NSData) -> Void
    )

    func requestClose(withReply reply: @escaping (NSData) -> Void)

    func setLocalConsoleOnly(
        _ enabled: NSNumber,
        authorizationExternalForm: NSData?,
        requestNonce: NSUUID?,
        withReply reply: @escaping (NSData) -> Void
    )

    func status(withReply reply: @escaping (NSData) -> Void)

    func retrySecurityService(withReply reply: @escaping (NSData) -> Void)

    func recentAuditHistory(query: NSString?, withReply reply: @escaping (NSData) -> Void)
}
