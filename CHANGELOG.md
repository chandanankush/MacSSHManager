# Changelog

All notable changes to MacSSHManager are documented here.

## Unreleased

### Changed

- Added a terminal-and-lock macOS app icon and asset catalog.
- Added public-facing documentation, generalized local signing examples, and retained detailed security/acceptance procedures in a separate operations guide.
- Removed personal paths, email signing examples, and local certificate fingerprints from current documentation.

- Renamed the project and main Xcode scheme to `MacSSHManager` and the macOS app to **Mac SSH Manager**. Updated packaging, installed app paths, and current documentation while retaining existing service identifiers and the support directory.

### Fixed

- Added reboot-safe Packet Filter initialization to the privileged controller and expiry-enforcer processes.
- Added bounded asynchronous startup recovery with an immediate attempt followed by successive 1, 2, 4, 8, and 15-second retry delays.
- PF is now explicitly inspected, enabled when necessary, verified, and initialized with the application-owned CLOSED anchor before SSH controls become available.
- Added exact anchor read-back validation without flushing Apple or third-party PF rules.
- Preserved PF enable-reference ownership without using global `pfctl -d` during normal shutdown.
- Prevented repeated identical degraded recovery events from flooding audit history.
- Added one-shot degraded and recovered audit transitions.
- Added structured PF startup failures for enable, enable verification, rule loading, anchor validation, and permission failures.
- Added unified logging for privileged startup, PF commands, rule loading, XPC recovery, and health transitions.
- Added a menu recovery state and privileged Retry action. Open SSH remains disabled until enforcement is fully verified.
- Recovery now invalidates in-flight OPEN requests, blocks new OPENs during recovery, and attempts session/lease cleanup before PF retry waits.
- Recovery retains incomplete cleanup as a degraded state and refuses OPEN until it is resolved.
- Preserved audit records for real recovery closures and retried successful-closure audit failures after lease removal.
- Fixed expanded-payload verification for the optional product-package layout.

### Packaging

- Added an explicit self-signed certificate mode for private builds without Apple Developer enrollment.
- Local builds pin the exact helper signing certificate, preserve root-owned client code-hash checks, and retain hardened runtime by statically linking project modules.
- Added a PKG-containing DMG for administrator installation.

### Tests

- Added coverage for PF already enabled, disabled-and-enabled, enable failure, false enable success, rule-load failure, anchor-validation failure, retry success, retry exhaustion, audit coalescing, readiness gating, and the privileged Retry action.
- Verified the complete suite in Terminal: 181 tests pass. Added recovery-race, cleanup, audit-retry, certificate-pin, and real package-layout coverage.

### Documentation

- Documented private local signing, certificate storage, architecture-specific client policy, and post-install reboot verification.
- Added troubleshooting for the Local-console-only remote-control warning, including intentional remote-desktop use and inconclusive service checks.

For the design, security properties, deployment process, and reboot verification procedure, see [Packet Filter Reboot Recovery](docs/PACKET_FILTER_REBOOT_RECOVERY.md).
