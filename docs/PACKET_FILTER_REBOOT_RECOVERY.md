# Packet Filter Reboot Recovery

## Summary

Mac SSH Manager uses a dedicated PF anchor to keep inbound SSH closed outside an authorized LAN or Tailscale window. Both root helpers perform explicit startup recovery; a running helper alone does not prove enforcement is ready.

See [architecture](ARCHITECTURE.md) for the full policy and [installation](INSTALLATION.md) for independent reboot and network probes.

## Ownership and trust boundaries

- Only the root controller and root expiry enforcer execute `/sbin/pfctl`.
- The menu app never invokes PF directly.
- All privileged commands use fixed absolute executable paths and fixed command shapes from `FixedCommandRunner.swift`.
- Runtime policy files must be beneath the root-owned application state directory.
- Runtime helpers only load `com.serverpc.ssh-control`; they do not flush or replace the global PF ruleset. Installation separately syntax-checks and reloads the complete managed `/etc/pf.conf`.
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
- The independent expiry enforcer passes the launchd-query health check (subject to the limits below).
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

## Verification limits

The health checker inspects the named anchor and on-disk linkage. It does not independently prove live parent-ruleset traversal. Enforcer health checks launchd query success, not a separate readiness heartbeat.

The [installation acceptance checks](INSTALLATION.md#physical-acceptance-tests) must establish actual port-22 blocking before login, XPC authentication, network scope, expiry, and crash behavior on each target Mac. Build/signature verification is covered separately in [Local signing](LOCAL_SIGNING.md).
