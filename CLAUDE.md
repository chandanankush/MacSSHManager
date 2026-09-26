# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Mac SSH Manager is an experimental macOS menu-bar utility for administrator-operated local installations that keeps normal SSH (TCP 22) closed by default and opens a bounded, freshly-authorized LAN and/or Tailscale access window on demand. It is security-sensitive software — read `docs/SECURITY_AND_OPERATIONS.md` before making behavioral changes; it is the security reference and takes precedence over convenience. The operations guide and architecture summary below describe the current code and security constraints.

This is a standalone repository. Do not import application-service code or add runtime dependencies on unrelated projects.

## Commands

The project is defined in `project.yml` (XcodeGen) and the generated `.xcodeproj` is committed. Regenerate after changing `project.yml`:

```bash
xcodegen generate
```

Build and run the full test suite:

```bash
xcodebuild test -project MacSSHManager.xcodeproj -scheme MacSSHManager -destination 'platform=macOS'
```

Run a single test target's scheme (faster than the umbrella scheme; one exists per target — `SharedProtocolTests`, `SecurityCoreTests`, `ControllerTests`, `IntegrationTests`, `MenuAppTests`):

```bash
xcodebuild test -project MacSSHManager.xcodeproj -scheme SecurityCoreTests -destination 'platform=macOS'
```

Run a single test method:

```bash
xcodebuild test -project MacSSHManager.xcodeproj -scheme MacSSHManager \
  -destination 'platform=macOS' \
  -only-testing:SecurityCoreTests/AuthorizationValidatorTests/testRejectsReplayedNonce
```

Build a signed local installation package (never installs anything; requires your explicitly pinned certificate and matching private key on the building Mac):

```bash
./Installer/build-package.sh \
  --signing-identity "Mac SSH Manager Local Signing" \
  --local-signing-certificate "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  --build-only
```

For the local self-signed build command and preserved trust checks, see `docs/LOCAL_SIGNING.md`.

Installation, uninstallation, and physical-console acceptance procedures are console-only and documented in `docs/SECURITY_AND_OPERATIONS.md` — do not attempt to script or automate them; they require the target Mac's attached display/keyboard and are outside what an agent should execute.

## Architecture

The main source modules are layered so that privileged policy is separate from the menu UI:

- **`SharedProtocol`** — the wire contract. DTOs and enums shared by every process: `AccessDuration`, `AccessStatus`, `Lease`, `ControlError` (stable sanitized reason codes, never raw error text), `AuditHistory`, `Paths` (fixed installed paths), and `XPCProtocol` (the exact `@objc` NSXPC interface — `requestOpen`, `requestClose`, `setLocalConsoleOnly`, `status`, `retrySecurityService`, `recentAuditHistory`). Nothing outside this file may change what the daemon accepts; there are no free-form strings, PIDs, or shell input anywhere in the interface.
- **`SecurityCore`** — all policy and enforcement logic, framework-agnostic and independently testable with fakes (no live PF/sshd/launchd mutation in tests). Key collaborators: `AccessController` (orchestrates OPEN/CLOSE — the composition root's main object), `AuthorizationValidator` (one-time-use Authorization Services check), `ClientValidator`/`InstalledClientPolicy` (validates XPC caller code identity), `LeaseStore` (atomic root-owned lease persistence), `PFController`/`PFRuleBuilder`/`PFInstallationValidator` (PF anchor management), `PhysicalLANResolver` (excludes VPN/Tailscale/loopback/virtual interfaces from the allow rule), `SSHPolicyValidator` (verifies public-key-only `sshd` config), `SSHSessionTerminator`/`SSHSessionMonitor` (kills/observes port-22 sessions), `RemoteControlDetector` (local-console-only enforcement), `ExpiryService`/`CloseCoordinator` (close-first, fail-closed transitions), `AuditLogger`/`AuditHistoryReader` (allowlisted-field audit trail). `ProductionComposition` is the single place that wires real (non-fake) implementations together for both the controller and the enforcer — start here to see how the pieces fit.
- **`ControllerDaemon`** (target `ControllerTransport` + executable `ControllerDaemon`) — the root LaunchDaemon. `ControllerListenerDelegate` validates every incoming XPC connection's code signature and console identity before exposing `ControllerXPCService`, which is the only thing that touches `AccessController`. A client that isn't the exact signed, installed menu app is rejected at the listener, before any request is parsed.
- **`ExpiryEnforcer`** — a separate root launchd job, no XPC listener, no ability to open access. It only reads the lease and can force CLOSED (boot, fixed interval, and at deadline). This independence is deliberate: it's the backstop if the controller or UI crashes or is compromised in a way that doesn't also compromise root.
- **`MenuApp`** (`MenuAppCore` framework + thin `MenuApp` executable target) — the unprivileged AppKit menu-bar popover with SwiftUI content. `MenuModel` drives UI state from `ControllerClient` (the XPC client) and `AuthorizationClient` (requests the custom non-shared, zero-reuse-timeout authorization right). No command-line, URL scheme, AppleScript, or network entry points exist here by design — don't add any.

Test targets mirror source targets 1:1 (`Tests/<X>Tests` ↔ `Sources/<X>`), plus `Tests/IntegrationTests` which crosses the XPC boundary (`XPCBoundaryTests`), exercises installer behavior (`InstallerTests`), and checks the acceptance manifest (`AcceptanceManifestTests`) against the operations guide's verification requirements.

## Working in this codebase

- Hard controls (root-owned PF, fresh OS authorization, fixed XPC protocol, signed-client validation, independent enforcer) are the security boundary; advisory controls (menu text, third-party remote-control detection) are defense-in-depth only — never blur this distinction in code or comments. See the Hard/Advisory table in `docs/SECURITY_AND_OPERATIONS.md`.
- The daemon never accepts a shell, a path, an argument list, or a PID from a caller — `FixedCommandRunner` only runs fixed absolute-path system tools with fixed arguments. Keep new privileged operations to this pattern; don't introduce string-built commands.
- CLOSE and expiry never require authorization and must never be blocked by a failure elsewhere (e.g. audit-write failure); OPEN must fail closed on any uncertainty. Preserve this asymmetry in any control-flow change to `AccessController`/`CloseCoordinator`/`ExpiryService`.
- Audit events use an allowlisted field set (`AuditLogger`) — never add a field that could carry a credential, authorization blob, SSH key, raw command, or process argument.
