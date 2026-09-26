# Security and operations

The macOS app is named **Mac SSH Manager**. The Xcode project and main scheme
are named `MacSSHManager`. Existing `com.serverpc.ssh-control` identifiers and
the `ServerPCSSHControl` support directory are retained for compatibility.

## Status

This repository contains the approved implementation and security design for a
macOS menu-bar utility for administrator-operated SSH access windows.
Automated tests cover the enforcement logic; installation security remains
pending until the physical-console acceptance procedure below is completed
on the target Mac. This is an experimental tool, not a general-purpose firewall product.

The app controls normal SSH on TCP port 22 only. Other ports are out of scope.

## Goal

Normal SSH is unreachable by default. A person at the target Mac can open a
bounded LAN access window through a local menu-bar application after fresh
macOS administrator authorization. Closing is immediate and does not require
authorization. Expiry and reboot restore the closed state and terminate live
port-22 sessions.

The application never receives, validates, stores, logs, or transmits a
password or biometric. macOS owns the complete authorization interaction.

## Repository boundary

This is a standalone Git repository. All source, tests, packaging assets, and
documentation for the capability remain inside it:

```text
MacSSHManager/
  README.md
  docs/SECURITY_AND_OPERATIONS.md
  Resources/Assets.xcassets/
  MacSSHManager.xcodeproj/
  Sources/
    MenuApp/
    ControllerDaemon/
    ExpiryEnforcer/
    SharedProtocol/
  Tests/
    MenuAppTests/
    ControllerTests/
    SecurityCoreTests/
    IntegrationTests/
  Installer/
```

The implementation is standalone and must not depend on unrelated application services.

## Threat model

### Protected against

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
that window. Existing server-side public keys remain unchanged in Phase 1.

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

## Components

### Menu-bar application

The unprivileged application uses an AppKit status item and popover with
SwiftUI content in the interactive user session. It displays:

- `SSH CLOSED`, or `SSH OPEN` with the remaining time.
- Two independent `LAN` and `Tailscale` checkboxes selecting the network
  scope for the next OPEN or replacement window. Both default ON. OPEN is
  unavailable when neither is selected; the selection is never inferred from
  whether Tailscale happens to be installed or running.
- Fixed OPEN choices of 15 minutes, 30 minutes, 60 minutes, 3 hours, and
  6 hours. The default selection is 30 minutes.
- `Close now`, which never asks for authorization.
- A retained `Require local-console-only` setting.
- Health and degraded-state information returned by `status`.

The application has no command-line control, URL scheme, AppleScript API,
HTTP listener, network listener, SFTP feature, or generic execution feature.
It cannot modify PF or privileged files.

### Root controller daemon

A root LaunchDaemon is installed and bootstrapped by the administrator-authorized
package script. Its XPC interface contains only typed operations:

```text
requestOpen(duration, lan, tailscale, authorizationExternalForm, requestNonce)
requestClose()
setLocalConsoleOnly(enabled, authorizationExternalForm?, requestNonce?)
status()
retrySecurityService()
recentAuditHistory(query)
```

The duration is an enum, not an integer supplied by the client. `lan` and
`tailscale` are booleans that only ever select among three fixed scopes
(LAN, Tailscale, or both); the daemon independently resolves and validates
what each selected scope actually means on the host, and rejects a request
that selects neither. The helper accepts no commands, paths, executables,
arguments, environment variables, interfaces, subnets, PF rule text, process
identifiers, or shell input.

Every connection is validated against the expected installed application
identity and root-owned application location. Release installation requires a
code-signed bundle. Development or unsigned builds cannot perform privileged
operations on the host.

The daemon uses fixed absolute executable paths where a system tool is
unavoidable and never invokes a shell. All values derived from system output
are parsed into bounded typed values and revalidated immediately before use.

### Independent expiry enforcer

A separate root launchd job has no XPC listener. It can only inspect the
root-owned lease and enforce CLOSED. It runs at boot, at a short fixed
interval, and at the recorded deadline. It protects expiry when the UI or
controller fails.

The enforcer treats missing, malformed, expired, future-invalid, or
previous-boot state as CLOSED. It never opens access.

### PF anchor

PF is the macOS BSD Packet Filter. This administrator-operated
tool uses one dedicated anchor. It never flushes or replaces the system's main
ruleset or another product's anchor.

The persistent anchor reference is installed idempotently only after the full
PF configuration passes syntax validation. The anchor's boot rule blocks
inbound TCP port 22 on every interface.

During OPEN, the anchor is atomically replaced with rules generated from the
authorized network scope, in this fixed order:

1. If LAN is authorized: permit inbound TCP port 22 only on the physical
   interface and source subnet captured for the approved LAN window.
2. If Tailscale is authorized: permit inbound TCP port 22 only on the single
   validated Tailscale interface, from Tailscale's documented CGNAT range
   (`100.64.0.0/10`), to the host's own captured Tailscale address.
3. Block inbound TCP port 22 on every other interface and source.

The implementation must verify the effective anchor after every transition
against the exact snapshot that transition authorized -- not merely that
some pass-rule-shaped anchor is loaded. It must never disable PF. If PF, the
anchor, or the enforcer is unhealthy, OPEN fails closed.

Apple treats PF as an advanced user and site-administrator mechanism, not as a
supported API for firewall products distributed broadly. Publishing this source
does not establish suitability for general binary distribution. See Apple's
[TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api).

## Authorization policy

OPEN, extension, duration replacement, and changing
`Require local-console-only` from ON to OFF require fresh OS-managed
administrator authorization.

The custom authorization right is non-shared and has zero reuse timeout. The
menu application requests the right through Authorization Services, and
SecurityAgent presents the OS interaction. The daemon reconstructs and checks
the right immediately before the privileged operation. A successful external
form and request nonce are consumed once and cannot authorize a second action.

macOS may use the administrator password, Touch ID, Apple Watch, or another
supported OS mechanism. The application sees only success or failure.

CLOSE and changing `Require local-console-only` from OFF to ON do not require
authorization because both operations reduce access.

## Network scope selection

Every OPEN carries an explicit network scope: LAN, Tailscale, or both. The
scope is never derived from a UI string or trusted from the XPC caller --
the daemon independently resolves and validates each requested path before
authorizing anything, and rejects a request that selects neither.

### LAN

At successful OPEN with LAN in scope, the daemon selects the physical
interface carrying the current default route and snapshots its directly
connected source subnet. Loopback, `utun`, bridge, VPN, Docker, Colima, and
other virtual interfaces are excluded from the allow rule.

The subnet is not required to be private. A public or otherwise unusual subnet
produces an audit warning but does not block an administrator-approved OPEN.

The rule does not automatically follow a later interface or subnet change.
Such a change is audited only -- it never closes the window and never widens
or replaces the originally captured rule. Access on the new LAN requires a
new, freshly authorized OPEN. The original lease continues until close or
expiry, although its snapshotted rule may no longer be reachable.

### Tailscale

At successful OPEN with Tailscale in scope, the daemon identifies the current
Tailscale interface without ever hardcoding a `utunN` number. Exactly one
local interface must independently satisfy three narrow, root-owned signals
at once: a `utun`-prefixed name, a point-to-point host route (`/32`), and an
address inside Tailscale's documented, stable CGNAT allocation
(`100.64.0.0/10`, see Tailscale's
[reserved IP addresses](https://tailscale.com/kb/1015/100.x-addresses) and
[macOS variants](https://tailscale.com/kb/1065/macos-variants) references).
Zero or more than one candidate fails closed. The exact interface/address
shape this assumes must be confirmed by inspection on the actual installed
machine and Tailscale variant before it is relied upon; it is not assumed to
be identical across every macOS Tailscale distribution.

The Tailscale pass rule is bound to that one validated interface, admits only
Tailscale's CGNAT source range, and is additionally narrowed to the host's
own captured Tailscale destination address. This scope is IPv4-only, matching
the LAN scope; Tailscale's IPv6 address on the same node is never passed by
any scope.

A live Tailscale interface renumbering, address change, ambiguity, or
disappearance is treated differently from a LAN change: it is audited **and**
closes the window immediately, requiring a freshly authorized OPEN. A rule
bound to a freed `utunN` name is never left running, because that name can
later be reused by an unrelated interface.

Tailnet ACL/grant configuration restricting which peers may reach TCP 22 is a
required independent external layer, not something this tool enforces or can
verify -- it complements, and does not replace, the interface- and
range-scoped PF rule.

## Local-console-only setting

`Require local-console-only` defaults to OFF on first installation and retains
its last state across application restarts and reboots. The setting is stored
in root-owned state; ordinary user defaults are not authoritative.

While this setting is OFF, there is still no network activation API and OPEN
still requires fresh OS administrator authorization. However, the utility does
not claim strict physical presence against a remote desktop session that can
interact with the local macOS UI. This is the explicitly selected default
trade-off.

When enabled, OPEN is refused if the supported detector reports macOS Screen
Sharing, Remote Management, or a reviewed known remote-control process as
running. A registered built-in service that reports `state = not running`
does not block OPEN. The enforcer continues checking during an open window and
closes access if a supported prohibited service becomes active.

Built-in service checks are enforced hard. A reviewed list of third-party
process and service identifiers is defense in depth because software cannot
reliably enumerate every remote-control mechanism.

Enabling the setting is immediate and password-free. Disabling it requires
fresh OS authorization and creates an audit event.

### Troubleshooting: prohibited remote-control service

If Open SSH shows **A prohibited remote-control service is active**, first
check whether **Local-console-only** is enabled. Supported detection includes
Screen Sharing, Remote Management/ARDAgent, AnyDesk, RustDesk, and TeamViewer.
It detects running services/processes; this does not prove that another person
is currently connected.

If remote desktop and SSH are intentionally needed together, uncheck
**Local-console-only**, approve the administrator prompt, and retry **Open SSH**.
Fresh authorization, the selected LAN/Tailscale scope, and the access-window
deadline still apply. To keep local-console-only protection, stop the detected
remote-control service from the attached console instead.

The same message also covers an inconclusive built-in service check, such as
unexpected `launchctl` output or a failed query. Those errors can still block
OPEN with the setting OFF. If the error persists, inspect the controller's
debug log and the two service states at the attached console:

```bash
sudo /usr/bin/tail -n 100 "/Library/Application Support/ServerPCSSHControl/debug.log"
sudo /bin/launchctl print system/com.apple.screensharing
sudo /bin/launchctl print system/com.apple.RemoteDesktop.PrivilegeProxy
```

A service-not-found response can be normal when that service is absent. Keep
the command result and error text when reporting a persistent failure; the menu
message alone does not identify which service or check caused it.

## Lease and transitions

The root-owned lease contains only:

- Schema version (bumped whenever the lease shape changes; an unrecognized or
  prior version always fails closed rather than being partially trusted).
- Request identifier.
- Selected fixed duration.
- Same-boot monotonic or continuous deadline.
- Wall-clock display timestamps.
- Boot-session identifier.
- The authorized network scope (LAN, Tailscale, or both).
- The captured physical interface and subnet, present only when LAN is in
  scope.
- The captured Tailscale interface and address, present only when Tailscale
  is in scope.
- Local-console-only state used for the decision.

It contains no credential, authorization external form, SSH key material,
secret, command, or email/application data. Writes use a temporary file,
`fsync`, atomic rename, root ownership, and restrictive permissions.

### OPEN

1. Validate the signed caller, request nonce, fixed duration, authorization,
   PF health, anchor installation, enforcer health, and public-key-only SSH
   configuration.
2. Evaluate the optional local-console policy.
3. Discover and validate the active physical LAN.
4. Persist the lease atomically.
5. Load the temporary allow rules atomically.
6. Read back and verify the effective anchor.
7. Return OPEN only after verification succeeds.

Any failure restores the blocking anchor, removes the lease, records a
sanitized audit event, and returns a structured error.

### Extension or duration change

An extension or duration change is a new OPEN request requiring fresh OS
authorization. The replacement duration starts from successful authorization;
durations never accumulate.

### CLOSE and expiry

1. Restore and verify the blocking anchor first.
2. Enumerate established TCP connections whose local port is 22.
3. Revalidate each owning process as an `sshd` session process immediately
   before sending a fixed termination signal.
4. Retry bounded termination and verify that no established port-22 session
   remains.
5. Remove the lease.
6. Record the transition.

The helper never accepts process identifiers from a caller. It must not flush
the complete PF state table, because doing so would disrupt unrelated
connections. If session termination is incomplete, the blocking rule remains,
the UI reports degraded CLOSED, and both root jobs continue bounded retries.

## Crash, sleep, clock, and reboot behavior

- UI crash does not alter the lease.
- Controller crash is restarted by launchd; the independent enforcer remains
  able to close access.
- Sleep counts toward expiry by using a clock that includes sleep.
- Wall-clock rollback or advance cannot extend the lease.
- Wake after deadline triggers immediate close.
- Reboot invalidates every lease through the boot-session identifier.
- The persistent PF configuration starts with the blocking anchor, and the
  enforcer's first action at boot is to verify CLOSED.
- Failure to prove PF, anchor, enforcer, authorization, or SSH policy health
  makes OPEN unavailable.

The installer and acceptance suite must validate actual startup ordering on
the target macOS release. Installation is rejected if the closed rule cannot
be shown to load before port 22 becomes reachable.

## SSH policy

The tool does not inspect, copy, expose, delete, rotate, or replace any SSH
private key or server-side public key. Installation creates one root-owned,
package-managed SSH configuration fragment that disables password,
keyboard-interactive, and root login while enabling public-key authentication.
Disabling root login makes a validated non-root `sshd` account an unambiguous
post-authentication identity for successful-session history.

Before enabling operation, installation verifies effective normal-port-22 SSH
policy includes:

```text
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
```

The check is read-only and does not print keys or authorized-key contents. A
failed or ambiguous effective-policy check prevents OPEN. The installer
verifies its exact managed fragment in the effective policy before making the
menu application available. Uninstallation removes only that exact,
package-owned fragment and restores the previous effective configuration.

## Audit

The root components emit privacy-safe events through Unified Logging and a
bounded, root-owned rotating audit file. Events include:

- Installation and policy validation.
- OPEN requested, authorized, denied, succeeded, or failed.
- Manual CLOSE.
- Automatic expiry.
- Extension or duration replacement.
- Local-console setting changes and detector decisions.
- Public or changed-network warnings.
- Invalid client, nonce, duration, authorization, state, or caller rejection.
- Controller recovery, enforcer recovery, and boot-forced close.
- Incomplete session termination and retry outcome.

Events may contain timestamps, duration enum, local UID and audit session,
request identifier, network scope, LAN interface name and subnet, Tailscale
interface name and address, reason code, and result. They must never contain
passwords, biometrics, authorization blobs, SSH keys, Tailnet status output,
arbitrary environment data, commands, email/application data, or raw process
arguments.

Audit-write failure never permits OPEN. Audit failure during CLOSE cannot
prevent closing and is reported as degraded status.

## Installation and upgrade

The rename changes the installed bundle to `/Applications/Mac SSH Manager.app`.
The installer does not remove an older `/Applications/ServerPC SSH Control.app`
or unregister its login item. At the attached console, use the old app's bundled
uninstaller before installing the renamed package. Removing the old installation
removes its protection until the new installer establishes CLOSED again; plan
this transition locally and verify the new installation before leaving the Mac.

Installation is initiated locally from the target Mac and requires administrator
approval. There is no remote installer. The visible application is installed
root-owned in `/Applications`; its operational state is root-owned in
`/Library/Application Support/ServerPCSSHControl`. The installer places exact
root-owned launchd definitions in `/Library/LaunchDaemons` and bootstraps both
root jobs.

Before changing PF configuration, the installer:

1. Confirms the supported macOS version and required system tools.
2. Verifies the signed bundle and root-owned destination.
3. Captures the existing PF configuration metadata without exposing secrets.
4. Syntax-checks the existing and proposed complete configurations.
5. Creates a root-owned recovery copy.
6. Installs only the dedicated anchor and its exact anchor reference.
7. Loads CLOSED and verifies port 22 is blocked before enabling the UI.

Upgrade repeats these checks and closes any active window first. Failure
leaves or restores the last verified CLOSED configuration. Uninstallation is a
separate administrator-authorized operation and must warn that removing the
controller also removes its port-22 boundary.

## Structured errors and UI states

The protocol uses stable reason codes rather than passing privileged command
output to the UI. UI states are:

- `closed`
- `opening`
- `open(deadline)`
- `closing`
- `degraded_closed(reason)`
- `unavailable(reason)`

There is no degraded-open state. Any uncertainty while opening results in
CLOSED. Error text is bounded and sanitized.

## Verification requirements

Implementation is incomplete until all applicable checks pass on both a test
environment and the target Mac's physical console.

### Automated tests

- Authorization is required for OPEN, extension, duration replacement, and
  disabling local-console-only mode.
- Authorization forms and nonces cannot be replayed.
- Unknown durations, XPC methods, clients, paths, interfaces, and malformed
  state are rejected.
- PF rule generation is deterministic and syntax checked, for LAN only,
  Tailscale only, and LAN + Tailscale.
- Only the dedicated anchor is mutated.
- Virtual interfaces never enter an allow rule; the Tailscale interface is
  never hardcoded and requires an unambiguous single candidate.
- Selecting LAN never implies Tailscale and selecting Tailscale never implies
  LAN; requesting neither is rejected.
- PF read-back is verified against the exact authorized scope -- reordered,
  duplicated, missing, extra, or unrecognized-virtual-interface rules are all
  rejected.
- Public and changed LAN networks audit without automatically closing; a
  changed, ambiguous, or disappeared Tailscale route audits **and** closes.
- Lease deadlines include sleep and ignore wall-clock manipulation.
- Every invalid or stale lease produces CLOSED, including a lease written by
  a prior schema version.
- CLOSE and expiry block first and terminate all port-22 sessions without
  flushing unrelated PF states.
- Audit fields are allowlisted and contain no credential or key material.
- The retained security setting has the approved default and authorization
  behavior.

### Physical acceptance tests

- First installation and helper approval from the attached console.
- CLOSED before login after cold boot and restart.
- OPEN and connection from another LAN host for every duration option, and
  separately over Tailscale, for LAN only, Tailscale only, and LAN +
  Tailscale scopes.
- Rejection from virtual and non-LAN interfaces, and rejection of the
  non-selected path in a narrowed (LAN-only or Tailscale-only) window.
- Tailscale IPv6 SSH remains blocked; MagicDNS hostname SSH falls back to the
  permitted IPv4 path.
- Password and keyboard-interactive SSH authentication remain disabled.
- Manual close immediately drops active SSH sessions.
- Expiry immediately drops active SSH sessions.
- UI crash, controller crash, enforcer restart, sleep past expiry, clock
  changes, DHCP change, and network-interface change.
- PF syntax error, missing anchor, disabled helper, audit failure, corrupt
  lease, and unsuccessful session termination all fail closed.
- Existing non-SSH network traffic and unrelated PF rules remain functional.
- Local-console-only OFF persistence, ON persistence, authorization to turn it
  OFF, and supported remote-control detection while closed and open.

No acceptance test may use normal port 22 until the closed baseline has been
installed and independently verified from the physical console.

## Build a locally signed package

For administrator-controlled local installation, a dedicated self-signed certificate can be used
without Apple Developer enrollment. Its private key stays in the build Mac's
login keychain. This produces a signed, hardened application inside an unsigned
package container and a PKG-containing DMG; it never installs anything:

```bash
./Installer/build-package.sh \
  --signing-identity "Mac SSH Manager Local Signing" \
  --local-signing-certificate "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  --build-only
```

The local route pins the exact signing certificate for helper authentication,
retains the installed menu app's code-hash validation, and statically links the
project modules so no library-validation exception is needed. It does not
change system certificate trust or Gatekeeper settings. See
[Local signing](LOCAL_SIGNING.md) for identity storage and verification.

Alternatively, build on a Mac with a valid Apple Development certificate for
the approved team:

```bash
cd /path/to/MacSSHManager
./Installer/build-package.sh \
  --signing-identity "Apple Development: <name> (<team-id>)" \
  --build-only
```

The Apple-signing route verifies the maintainer TeamIdentifier compiled into
`Installer/build-package.sh` and `Sources/MenuApp/ControllerClient.swift`;
arbitrary Apple teams are not accepted. The local route
verifies the supplied certificate fingerprint. Both verify fixed helper
identifiers, every nested signature, the expanded package payload, and
the generated client CDHash/designated requirement. It prints the package
SHA-256. Record that value through a trusted channel before copying
`build/MacSSHManager.pkg` to the target Mac. A separately signed package can
be produced only by supplying an explicit Developer ID Installer identity;
without one, `pkgutil` correctly reports that the container has no signature.

## Install from the attached console

Perform these steps with the target Mac's attached display and keyboard. Do not use
normal SSH for installation. First verify the copied artifact and its embedded
application without installing it:

```bash
PKG="$HOME/Downloads/MacSSHManager.pkg"
/usr/bin/shasum -a 256 "${PKG}"
/usr/sbin/pkgutil --check-signature "${PKG}"
VERIFY_ROOT=$(/usr/bin/mktemp -d /tmp/serverpc-ssh-control-verify.XXXXXX)
/usr/sbin/pkgutil --expand-full "${PKG}" "${VERIFY_ROOT}/expanded"
/usr/bin/codesign --verify --deep --strict \
  "${VERIFY_ROOT}/expanded/Payload/Library/Application Support/ServerPCSSHControl/.Incoming/Mac SSH Manager.app"
```

These expansion commands assume the default unsigned component package. With
an explicitly installer-signed product package, its payload is nested under
`expanded/MacSSHManager-component.pkg/Payload` instead.

Compare the SHA-256 with the trusted build output. `Status: no signature` for
the package container is expected for the local-signing build; the embedded
application verification must succeed. Then install locally:

```bash
sudo /usr/sbin/installer -pkg "${PKG}" -target /
/usr/bin/codesign --verify --deep --strict \
  "/Applications/Mac SSH Manager.app"
/usr/bin/open "/Applications/Mac SSH Manager.app"
```

The installer checks macOS 13+, root ownership, PF syntax, and conflicting
managed markers. It loads and verifies CLOSED, installs and verifies its
package-owned public-key-only SSH policy fragment, places the menu app in
`/Applications`, installs the two root launch daemons, and verifies that both
services are registered. It does not inspect or change SSH keys. Launch the app
and confirm the controller is available:

```bash
sudo /bin/launchctl print system/com.serverpc.ssh-control.controller >/dev/null
sudo /bin/launchctl print system/com.serverpc.ssh-control.enforcer >/dev/null
```

Do not press **Open SSH** until the next section passes from a second LAN
device.

## Verify CLOSED before login

At the attached console, prove that PF is enabled, the persistent linkage is
exact, the runtime anchor contains only the blocking rule, and SSH remains
public-key-only:

```bash
sudo /sbin/pfctl -s info | /usr/bin/grep '^Status:'
sudo /usr/bin/grep -F 'com.serverpc.ssh-control' /etc/pf.conf
sudo /sbin/pfctl -a com.serverpc.ssh-control -sr
sudo /usr/sbin/sshd -T | /usr/bin/grep -E \
  '^(passwordauthentication no|kbdinteractiveauthentication no|pubkeyauthentication yes)$'
sudo /usr/sbin/lsof -nP -iTCP:22 -sTCP:LISTEN
```

Expected anchor output is one `block drop in quick ... port 22` rule. From a
second device on the current physical LAN, and separately from a device on
the tailnet, a TCP probe must fail or time out:

```bash
/usr/bin/nc -vz mac-host.local 22
/usr/bin/nc -vz <tailscale-hostname-or-address> 22
```

Only after both independent failures may normal port 22 be exercised. In the
menu, confirm the initial duration is 30 minutes and both `LAN` and
`Tailscale` are checked by default. Test 15, 30, 60 minutes, 3 hours, and 6
hours by opening each window, confirming the displayed deadline, probing from
a LAN device, and choosing **Close now** before moving to the next duration.
Every new or replacement window must show a fresh macOS administrator
authorization prompt. Closing must never request authorization.

To test immediate termination, connect from the second LAN device during an
approved window, then choose **Close now** at the target Mac; the session must drop
and the TCP probe must fail again. Confirm unrelated LAN traffic still works.

## Exercise network scope

With CLOSED verified, open a **LAN only** window (uncheck `Tailscale`) and
confirm from a second LAN device that SSH works, while a Tailscale probe from
a tailnet device fails. Close, then open a **Tailscale only** window (uncheck
`LAN`) and confirm the reverse: the Tailscale probe succeeds and the LAN probe
fails. Close, then open a **LAN + Tailscale** window and confirm both probes
succeed. In every case, confirm unrelated VPN, `utun`, Docker, Colima, and
bridge interfaces never gain access, and that unchecking both boxes disables
opening.

Connect over Tailscale using both the target Mac's Tailscale IPv4 address and its
MagicDNS hostname; both must reach the same `sshd`, the target Mac account, and
existing authorized identity as the LAN path. Attempt SSH to the target Mac's
Tailscale **IPv6** address during a Tailscale-scope window and confirm it is
blocked, proving the IPv4-only scope decision holds in practice.

While a Tailscale-scope window is open, restart Tailscale
(`sudo tailscale down && sudo tailscale up`, or relaunch the app) and confirm
access is not silently broadened or left running past the restart in a way
that outlives the validated interface. Where practical, force the Tailscale
interface to renumber (e.g. by toggling the Tailscale app off and on) and
confirm the prior authorization does not silently follow the new interface
name -- the window must close, and a new explicit OPEN is required to
re-establish access on the new interface.

## Exercise expiry

Open the 15-minute window, establish a session from the second LAN device, and
leave it untouched. At the deadline the session must drop, the menu must return
to CLOSED, and the TCP probe must fail. Repeat once by sleeping the target Mac past
the deadline; wake must reconcile immediately to CLOSED. Changing the wall
clock must never extend a lease because deadlines use the continuous clock.

LAN network changes are audit-only by design. During a test window with LAN in
scope, switching from one physical LAN to another does not automatically close
the lease, but the original interface/CIDR snapshot remains the only allowed
source and a `networkChanged` event must be recorded. VPN, bridge, and other
virtual interfaces must never appear in an allow rule. A Tailscale route
change during a test window with Tailscale in scope behaves differently: it
audits **and** closes the window, per "Exercise network scope" above.

## Exercise crash recovery

With a short window open, kill only the menu UI and relaunch it locally:

```bash
/usr/bin/pkill -x "Mac SSH Manager"
/usr/bin/open "/Applications/Mac SSH Manager.app"
```

The root-owned lease remains authoritative. Next, exercise exact launchd jobs
one at a time; launchd must restart them and the enforcer must restore CLOSED
for an invalid or expired lease:

```bash
sudo /bin/launchctl kill SIGKILL system/com.serverpc.ssh-control.controller
sudo /bin/launchctl print system/com.serverpc.ssh-control.controller >/dev/null
sudo /bin/launchctl kill SIGKILL system/com.serverpc.ssh-control.enforcer
sudo /bin/launchctl print system/com.serverpc.ssh-control.enforcer >/dev/null
```

Finally choose **Close now**, reboot from the local Apple menu, and test port 22
from the second LAN device before anyone logs in. It must already be CLOSED.
After local login, verify the two launchd jobs, anchor, and audit again.

The optional **Require local-console-only** setting defaults OFF and retains its
last state. Turning it ON requires no authorization; turning it OFF must require
fresh administrator authorization. When ON, supported Screen Sharing or Remote
Management activity must deny OPEN or close an active window.

## Inspect the audit

Choose **View full history** in the menu to open the searchable local timeline.
It opens directly without an administrator prompt and shows the newest 250
matching events from the last 30 days. Successful SSH sessions appear as
connected and disconnected rows with the SSH username, numeric source IP, and
local timestamp. Access-window changes, expiry, settings, recovery, and network
warnings appear in the same view.

The underlying rotating JSONL log is root-owned and mode 0600. It stores only
bounded event metadata: timestamp, event/outcome, approved reason and duration,
LAN interface/CIDR, local-console-only state, and—for validated successful SSH
sessions—the username and source IP. It never stores failed authentication
attempts, passwords, authorization forms, SSH keys, commands, terminal content,
audit tokens, process arguments, or application data:

```bash
sudo /usr/bin/tail -n 100 /var/log/serverpc-ssh-control.jsonl
/usr/bin/log show --last 1h \
  --predicate 'subsystem == "com.serverpc.ssh-control" AND category == "security-audit"'
```

Verify entries for open, replacement, manual close, expiry, network warning,
setting change, crash recovery, and successful session connect/disconnect. Use
the window search with a username and source IP. A history-read failure is
non-blocking and never changes SSH enforcement. An audit-write failure prevents
OPEN; it must never leave an uncertain open state.

## Debug log

A separate, bounded, root-owned diagnostic log records the decision path
behind OPEN/CLOSE/reconcile attempts -- which health, installation, or
PF-verification check failed, and why -- to speed up live troubleshooting.
It is deliberately not part of the audit trail above: it carries no field
allowlist beyond never containing credentials, keys, or authorization
material, is capped at 1&nbsp;MB with self-truncation instead of rotation,
and its absence or failure never affects enforcement.

```bash
sudo /usr/bin/tail -n 100 "/Library/Application Support/ServerPCSSHControl/debug.log"
```

Useful when an OPEN attempt fails with a generic reason (for example
`Packet Filter enforcement is unavailable`) and the audit/Unified Logging
event alone doesn't say which internal check produced it -- the debug log
records the specific `ControlErrorCode`, the exact PF rule text written, and
the raw `pfctl` read-back, so a mismatch (including known `pfctl` rendering
quirks, such as it echoing `port 22` as `port = 22` and a `/32` destination
as a bare host address) is visible directly instead of needing to be
re-derived from source.

## Rollback

Rollback removes a security boundary and therefore is a separate local root
operation. Run it only at the attached console while the installed app is
intact:

```bash
sudo "/Applications/Mac SSH Manager.app/Contents/Resources/uninstall"
```

The uninstaller first loads and verifies CLOSED and terminates all established
port-22 sessions through the close-only hardened helper. It then removes the
exact launchd jobs, authorization right, managed PF block/anchor, active audit
file and exact rotations `.1` through `.5`,
package-owned SSH policy fragment, and application root. It never reads or
changes SSH keys. Its final warning—normal port 22 is no longer protected—is
literal.
Confirm the warning and independently reassess port-22 exposure before leaving
the machine.

## Non-goals

- Managing unrelated services or ports.
- Creating another remote-control port.
- Managing SSH keys or authorized keys.
- Adding password authentication to SSH.
- Providing generic root execution, Docker access, or application-data access.
- Centralized management of multiple Macs or a general-purpose firewall distribution.
- Claiming that audit-only network warnings are preventive controls.
