import Foundation
import SharedProtocol

/// The exact, independently-validated network paths authorized for the
/// current OPEN transition. Presence of `lan`/`tailscale` must always match
/// `scope` — this is enforced at construction, never trusted from a caller.
public struct SSHAccessNetworkSnapshot: Equatable, Sendable {
    public let scope: SSHNetworkScope
    public let lan: LANSnapshot?
    public let tailscale: TailscaleSnapshot?

    public init(scope: SSHNetworkScope, lan: LANSnapshot?, tailscale: TailscaleSnapshot?) throws {
        guard scope.includesLAN == (lan != nil), scope.includesTailscale == (tailscale != nil) else {
            throw ControlErrorCode.invalidNetworkScope
        }
        self.scope = scope
        self.lan = lan
        self.tailscale = tailscale
    }
}
