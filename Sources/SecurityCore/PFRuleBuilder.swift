import Foundation
import SharedProtocol

public struct PFRuleBuilder: Sendable {
    /// Tailscale's documented, stable CGNAT allocation. Never widened to
    /// "any" and never applied to any interface other than the one
    /// interface validated for this transition by `TailscaleRouteResolver`.
    public static let tailscaleSourceCIDR = "100.64.0.0/10"

    public init() {}

    public func closedRules() -> String {
        "block drop in quick proto tcp from any to any port 22\n"
    }

    public func openRules(_ snapshot: SSHAccessNetworkSnapshot) throws -> String {
        var lines: [String] = []
        if let lan = snapshot.lan {
            lines.append(try lanPassRule(lan))
        }
        if let tailscale = snapshot.tailscale {
            lines.append(try tailscalePassRule(tailscale))
        }
        guard !lines.isEmpty else { throw ControlErrorCode.invalidNetworkScope }
        return lines.reduce(into: "") { $0 += $1 + "\n" } + closedRules()
    }

    private func lanPassRule(_ snapshot: LANSnapshot) throws -> String {
        guard PhysicalLANResolver.isSafeInterfaceName(snapshot.interfaceName),
              !PhysicalLANResolver.isKnownVirtualName(snapshot.interfaceName),
              IPv4Network(cidr: snapshot.sourceCIDR) != nil
        else {
            throw ControlErrorCode.networkUnavailable
        }
        return "pass in quick on \(snapshot.interfaceName) inet proto tcp from \(snapshot.sourceCIDR) " +
            "to any port 22 flags S/SA keep state"
    }

    private func tailscalePassRule(_ snapshot: TailscaleSnapshot) throws -> String {
        guard TailscaleRouteResolver.isTailscaleInterfaceName(snapshot.interfaceName),
              IPv4Network(cidr: snapshot.addressCIDR) != nil
        else {
            throw ControlErrorCode.tailscaleUnavailable
        }
        return "pass in quick on \(snapshot.interfaceName) inet proto tcp from \(Self.tailscaleSourceCIDR) " +
            "to \(snapshot.addressCIDR) port 22 flags S/SA keep state"
    }

    func normalized(_ rules: String) -> String {
        rules
            .split(separator: "\n")
            .map { $0.split(whereSeparator: { $0 == " " || $0 == "\t" }).joined(separator: " ") }
            .filter { !$0.isEmpty }
            .joined(separator: "\n") + "\n"
    }
}
