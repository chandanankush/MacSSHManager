# Packet Filter Reboot Recovery

## Summary

Mac SSH Manager depends on a dedicated PF anchor to keep inbound SSH fail-closed and to permit port 22 only for an explicitly authorized LAN or Tailscale scope. On macOS 26.7, PF could be disabled after reboot even though both root LaunchDaemons were loaded and running. The previous implementation exposed the controller immediately and relied on periodic close reconciliation to incidentally enable PF.

The repair introduces an explicit privileged startup and recovery lifecycle. A helper process being alive is no longer considered sufficient evidence that SSH enforcement is ready.

## Original failure

The failure involved four interacting behaviors:

1. `ControllerDaemon/main.swift` started the XPC listener without initializing PF.
2. `ExpiryEnforcer/main.swift` immediately entered a 15-second reconciliation loop without a bounded startup phase.
3. `PFController.enforceClosed()` contained a basic `pfctl -E` attempt, but it was embedded in close processing rather than represented as a retryable readiness state.
4. `CloseCoordinator.close(trigger:)` appended a recovery audit event on every reconciliation pass, including identical failures.

Consequently, a running LaunchDaemon could coexist with disabled PF, the menu could only report generic unavailability, and recovery failures produced repeated `Closed state recovered / Degraded` entries.

## Ownership and trust boundaries

- Only the root controller and root expiry enforcer execute `/sbin/pfctl`.
- The menu app never invokes PF directly.
- All privileged commands use fixed absolute executable paths and fixed command shapes from `FixedCommandRunner.swift`.
- Runtime policy files must be beneath the root-owned application state directory.
- The application only loads `com.serverpc.ssh-control`; it does not flush or replace the global PF ruleset.
- Neither normal shutdown nor menu-app exit calls `pfctl -d`.
- The value returned by `pfctl -E` is retained by the privileged `PFController` instance and is never logged or exposed through XPC. The application does not issue `pfctl -X` because it must not accidentally withdraw enforcement needed by another live application component.

## Startup state machine

Each privileged process creates its own `PFController` actor. Startup first attempts the full close sequence (PF closure, session termination, and lease removal), then invokes `recoverAtStartup()` asynchronously. Session and lease cleanup is attempted even if the first PF operation fails; it does not wait for the retry backoff to expire.

Controller recovery supersedes in-flight OPEN requests and rejects new OPEN requests until recovery completes. A final close pass rechecks cleanup after PF recovery. An incomplete cleanup remains degraded in subsequent status responses and blocks OPEN until a successful close or recovery resolves it.

The state transitions are:

```text
idle -> recovering -> ready
                  \-> failed(reason)
```

Recovery attempts run immediately and then use successive delays of 1, 2, 4, 8, and 15 seconds (30 seconds of total backoff, plus command execution time). Sleeping uses Swift concurrency and does not block the XPC listener or daemon main thread.

Each attempt performs the following sequence:

1. Validate `/etc/pf.conf`, the managed anchor declaration/load line, anchor ownership, permissions, and persistent CLOSED anchor content.
2. Run `/sbin/pfctl -s info` and require a successful, non-truncated result.
3. If PF is disabled, run `/sbin/pfctl -E` and require successful termination.
4. Run `/sbin/pfctl -s info` again and require `Status: Enabled`.
5. Write the runtime CLOSED rules to a root-owned `0600` policy file.
6. Syntax-check only the application anchor.
7. Load only `com.serverpc.ssh-control`.
8. Read the anchor back and compare its parsed semantics to the expected rules.
9. Recheck PF and confirm the effective mode is CLOSED.

No allow rule is installed during initialization. Until all steps succeed, Open SSH remains unavailable.

## Readiness definition

The menu can offer Open SSH only when all relevant checks succeed:

- XPC communication with the privileged controller succeeds.
- Startup recovery state is `ready`.
- PF reports enabled.
- The application anchor can be read and parsed.
- Its rules match the expected CLOSED or active-policy semantics.
- The installed PF configuration and ownership checks pass.
- The independent expiry enforcer is healthy.
- The SSH authentication policy is safe.
- When opening, the requested LAN/Tailscale snapshot is successfully written and verified before the operation is reported as successful.

An active helper PID alone is not readiness.

## Fail-closed behavior

- Startup always installs and verifies CLOSED rules.
- A lease from another boot is invalid and is removed during reconciliation.
- Any PF status, syntax, load, or read-back failure prevents Open SSH.
- A failed open attempt immediately attempts to restore CLOSED rules.
- Existing Apple and third-party anchors remain untouched.
- Global flush commands such as `pfctl -F all` are prohibited by installer tests.

## Errors returned to the menu

Privileged startup can expose safe, structured reasons:

- `pfDisabled`
- `pfEnableFailed`
- `pfEnableUnverified`
- `pfRulesLoadFailed`
- `pfAnchorValidationFailed`
- `permissionFailure`
- `pfUnavailable` for failures that cannot be safely classified further

Raw command output and PF reference values are not sent over XPC.

## Audit coalescing

`CloseCoordinator` tracks the last recovery failure in memory:

- The first transition into a distinct degraded condition is recorded.
- Identical subsequent failures are not appended every 15 seconds.
- A change to a different failure reason is meaningful and is recorded.
- The first successful recovery after a degraded incident is recorded once.
- Normal healthy reconciliation does not create repeated recovery records.
- Discarding an active, expired, or invalid lease is a meaningful recovery closure and is recorded even if closing succeeds on the first attempt.
- A successful closure whose audit write fails is retained in memory for the next reconciliation attempt, even after the lease has been removed.
- Coalescing state changes only after the audit event is successfully written, so a transient audit-write failure can be retried.

The first incident after a helper restart may be recorded again because the in-memory coalescing state intentionally does not weaken or rewrite the append-only audit file.

## Unified logging

The stable subsystem is:

```text
com.serverpc.ssh-control
```

Relevant categories are `startup`, `packet-filter`, `rules`, `xpc`, `recovery`, and `security-audit`.

Inspect recent helper activity with:

```bash
sudo log show --last 10m --style compact \
  --predicate 'subsystem == "com.serverpc.ssh-control"'
```

Logs include the fixed executable path, operation name, termination status, bounded sanitized stderr, retry number, and state transitions. They exclude authorization forms, passwords, keys, and PF enable tokens.

## Menu behavior

- During bounded recovery, the menu shows `RECOVERING SECURITY SERVICE…`.
- Open SSH is disabled while recovering, unavailable, or degraded.
- After retry exhaustion, the menu displays a concise classified error.
- `Retry security service` sends an XPC request to the root controller, which reruns the same verified recovery sequence.
- Closing remains available and fail-closed.

## LaunchDaemon and installer review

Both helpers intentionally use `RunAtLoad`:

- The controller must establish CLOSED enforcement and accept authenticated XPC requests.
- The enforcer must independently reconcile lease expiry, PF state, network drift, and SSH sessions even when the menu app is not running.

Both definitions run as root and use `KeepAlive.SuccessfulExit = false`, avoiding a tight relaunch loop while still restarting an unexpected failure. The installer writes LaunchDaemon plists as `root:wheel` mode `0644`, makes the application root-owned and non-group/world-writable, and installs state files with restrictive permissions.

The implementation does not depend on daemon launch order. Concurrent CLOSED initialization is safe because both components use the same narrow anchor and never install a pass rule during startup.

## Build and packaging

An ordinary Xcode Debug build produces the menu app and helper products separately. Production embedding is performed by `Installer/build-package.sh`, which:

1. Builds Release products.
2. Copies both helpers to `Contents/Library/Helpers`.
3. Copies the frameworks and LaunchDaemon resources.
4. Signs frameworks, helpers, the menu executable, and the containing app.
5. Verifies helper identifiers and either the expected Apple Team ID or the explicitly supplied local signing certificate.
6. Generates the trusted-client policy from the signed menu executable.
7. Builds and re-expands the installer package for verification.

The default build uses an Apple application-signing identity for the fixed maintainer Team ID. The local-signing route instead requires an explicitly supplied DER certificate and its private key in the build Mac's keychain. It seals the certificate fingerprint into the signed app and pins the controller to that exact certificate plus its helper identifier. Ad-hoc signatures remain prohibited.

Local builds statically link the project modules and verify that the three executables depend only on Apple system libraries. This preserves the hardened runtime without a library-validation exception. The controller still validates the menu's exact designated requirement, code hash, installed path, and console identity against the root-owned installation policy. No global certificate trust or Gatekeeper settings are changed. See [Local signing](LOCAL_SIGNING.md).

Local build without Apple enrollment:

```bash
./Installer/build-package.sh \
  --signing-identity "Mac SSH Manager Local Signing" \
  --local-signing-certificate "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  --build-only
```

Optional Apple-signed package build:

```bash
./Installer/build-package.sh \
  --signing-identity "Developer ID Application: <name> (<maintainer-team-id>)" \
  --installer-signing-identity "Developer ID Installer: <name> (<maintainer-team-id>)" \
  --build-only
```

The outputs are `build/MacSSHManager.pkg` and `build/MacSSHManager.dmg`. Package verification supports both the direct component payload and the nested component produced by `productbuild`. The DMG contains the verified installer package rather than a drag-copy app because administrator installation must configure PF, SSH policy, authorization rights, and LaunchDaemons.

## Post-install reboot verification

After installing the newly signed package and restarting the target Mac from its attached console, run:

```bash
sudo /sbin/pfctl -s info
sudo launchctl print system/com.serverpc.ssh-control.enforcer
sudo launchctl print system/com.serverpc.ssh-control.controller
sudo /sbin/pfctl -a 'com.serverpc.ssh-control' -sr
sudo /sbin/pfctl -a '*' -sr
sudo log show --last 10m --style compact \
  --predicate 'subsystem == "com.serverpc.ssh-control"'
```

Expected results:

- PF reports `Status: Enabled`.
- Both helpers are loaded and remain running.
- The application anchor contains the CLOSED port-22 rule before an access window is opened.
- The menu reports control available.
- LAN/Tailscale access can be opened only according to the selected verified policy.
- Audit history contains no repeated identical degraded recovery entries.

## Test coverage

The automated suite covers:

- PF already enabled.
- PF disabled and successfully enabled.
- PF enable command failure.
- PF enable command succeeds but status remains disabled.
- Anchor load and read-back validation failures.
- Success after retry and bounded retry exhaustion.
- Narrow application-anchor command construction.
- Duplicate degraded-event coalescing and degraded-to-healthy recovery.
- Real recovery closures, successful audit-write retry after lease removal, and quiet healthy reconciliation.
- Retry invalidation of an in-flight OPEN, OPEN gating during recovery, and cleanup before retry waits.
- Persistent degraded status and OPEN refusal after incomplete recovery cleanup.
- Exact local-certificate helper requirements and rejection of malformed pins.
- Payload discovery using real component and product packages, plus missing/ambiguous payload rejection.
- Open SSH readiness gating.
- Privileged Retry invocation from the menu model.
- Installer prohibition of global PF disable and flush commands.

Terminal verification on September 19, 2026: all 181 tests passed, and the self-signed Release app, both helpers, PKG, and DMG built successfully. Signature, certificate pin, hardened-runtime flag, system-library dependencies, and generated client-policy checks passed. Xcode emitted test-toolchain warnings; this is not a zero-diagnostics claim.

Local tests and packaging do not prove boot-time enforcement on the target Mac. Live parent-anchor reachability, actual port-22 blocking before login, XPC authentication, and LAN/Tailscale behavior must still be checked on that Mac. The current health checker inspects the named anchor and on-disk linkage; it does not independently prove live parent-ruleset traversal. The independent-enforcer health check also checks launchctl command success, not a separate readiness heartbeat.
