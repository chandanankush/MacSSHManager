# Security model

Mac SSH Manager is experimental, administrator-operated software. Its controls depend on the installed configuration and the target Mac; a passing unit test or running helper is not proof that SSH is blocked.

[Report vulnerabilities privately](../SECURITY.md). See [architecture](ARCHITECTURE.md) for implementation details and [installation and acceptance](INSTALLATION.md) before relying on a local installation.

## Threat model

### Designed to protect against

- A coding agent or other unprivileged process running as the same macOS user.
- Direct invocation of the privileged helper with arbitrary arguments.
- Reuse of a prior authorization to extend or reopen access.
- UI, controller, or expiry-process crashes.
- Wall-clock changes, sleep across expiry, stale state after reboot, and
  malformed lease files.
- SSH sessions attempting to remain connected after manual close or expiry.
- Accidental exposure through VPN, loopback, Docker, Colima, bridge, or other
  virtual interfaces, and through Tailscale when it was not explicitly
  selected as part of the authorized network scope.
- A network path silently widening: selecting LAN never implies Tailscale,
  selecting Tailscale never implies LAN, and a drifted or renumbered
  Tailscale route never keeps running under its stale authorization.

### Not protected against

- An attacker that already has root access or the administrator credential.
- A user approving an authorization prompt they did not intend to approve.
- A same-user process closing an open window or causing nuisance authorization
  prompts. Both actions fail closed or still require an administrator decision.
- Use of an accepted disk-backed SSH key during a human-approved open window.
- Every possible third-party remote-control product. The optional local-console
  check hard-enforces supported built-in checks and treats the third-party
  detector list as defense in depth.

An open window proves that macOS administrator authorization approved a time
window. It does not establish human identity for each SSH connection during
that window. Existing server-side public keys remain unchanged.

## Hard controls and advisory controls

Hard controls are enforced by root-owned code, macOS authorization, PF,
launchd, file ownership, or `sshd`. Advisory controls are never described as a
security boundary.

| Control | Classification |
| --- | --- |
| Root-owned PF anchor defaults to block TCP 22 | Hard |
| Fresh OS authorization for OPEN or extension | Hard |
| Fixed XPC protocol and signed-client validation | Hard |
| Independent expiry enforcer | Hard |
| Boot-session-bound lease | Hard |
| Public-key-only `sshd` configuration | Hard, validated during installation |
| Menu labels and warning text | Advisory only |
| Detection of unknown third-party remote-control tools | Defense in depth |
| Public-network and network-change audit events | Detective only |

## Operational limits

- Each target installation requires physical acceptance, including independent network probes and CLOSED before login.
- The runtime health check reads the named PF anchor and checks on-disk linkage. It does not independently prove live parent-ruleset traversal.
- Enforcer health checks whether its launchd query succeeds; there is no separate readiness heartbeat.
- Build and target Macs must use the same architecture. The installed policy stores one architecture's client code hash.
- Tailscale scope supports IPv4 only. A supported, unambiguous route is required; route drift closes access.
- There is no generally supported, notarized binary release. Local signing produces an unsigned installer container with signed application code.
- Apple's [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) describes PF as an administrator mechanism rather than a supported firewall-product API.

## Non-goals

- Managing unrelated services or ports.
- Creating another remote-control port.
- Managing SSH keys or authorized keys.
- Adding password authentication to SSH.
- Providing generic root execution, Docker access, or application-data access.
- Centralized management of multiple Macs or a general-purpose firewall distribution.
- Claiming that audit-only network warnings are preventive controls.
