# Installation and acceptance

Install and remove Mac SSH Manager from the target Mac's attached display and keyboard, with administrator access. Installation changes PF, Remote Login, and SSH authentication policy. Do not perform it over the SSH connection being controlled.

## Verify a release installer

Experimental prebuilt packages are available in [GitHub Releases](https://github.com/chandanankush/MacSSHManager/releases). The first prerelease is **Apple Silicon (arm64) only**. The app and helpers use a local self-signed certificate; the package container is unsigned and the app is not notarized. Do not disable Gatekeeper or broadly trust a certificate to install it.

Download `MacSSHManager.pkg` and `SHA256SUMS.txt` from the same release. Read its notes for the expected signing-certificate fingerprint and build limitations. Before installation, compare the package hash:

```bash
cd "$HOME/Downloads"
/usr/bin/shasum -a 256 -c SHA256SUMS.txt
```

Both files must be from the intended release; a checksum file alone does not establish publisher identity. Record the certificate fingerprint from the trusted release notes, not from the downloaded app. Verify the payload without installing it:

```bash
PKG="$HOME/Downloads/MacSSHManager.pkg"
EXPECTED_CERTIFICATE_SHA1="<40-uppercase-hex-characters-from-release-notes>"
VERIFY_ROOT=$(/usr/bin/mktemp -d /tmp/macsshmanager-release-verify.XXXXXX)
/usr/sbin/pkgutil --expand-full "$PKG" "$VERIFY_ROOT/expanded"
APP="$VERIFY_ROOT/expanded/Payload/Library/Application Support/ServerPCSSHControl/.Incoming/Mac SSH Manager.app"
/usr/bin/codesign --verify --deep --strict "$APP"
for CODE in "$APP" \
  "$APP/Contents/Library/Helpers/serverpc-ssh-controller" \
  "$APP/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer"; do
  /usr/bin/codesign --verify --strict --check-expiration \
    -R="certificate leaf = H\"${EXPECTED_CERTIFICATE_SHA1}\"" "$CODE"
done
```

Stop if a hash, signature, certificate, or architecture check fails. Then follow the attached-console installation and full physical acceptance below. Prebuilt artifacts have passed build and package checks, which do not prove live enforcement on your Mac.

## Apple cannot verify the installer

The `v1.0.0-beta.1` package is unsigned and its locally signed payload is not Apple-notarized. Gatekeeper can show **Apple could not verify “MacSSHManager.pkg” is free of malware** when you open the downloaded package. Valid local code signatures and a matching checksum do not replace Apple's notarization check.

If you trust this experimental release, first complete the package and pinned-signature verification above. Then, at the target Mac's attached console:

1. Try opening the package in Finder, then dismiss the warning without deleting the package.
2. Open **System Settings > Privacy & Security**, scroll to **Security**, and find the blocked `MacSSHManager.pkg` entry.
3. Choose **Open Anyway**, authenticate if requested, and confirm **Open** to allow this specific installer.

This is a per-item exception; keep Gatekeeper enabled and do not remove quarantine attributes or broadly trust the local certificate. The app itself may need a separate per-item approval on first launch. Follow [Apple's guidance](https://support.apple.com/en-us/102445) and continue with the installation and physical acceptance checks below. This approval does not establish that Apple has scanned or notarized the software.

Removing this requirement for normal public distribution needs Developer ID Application signing for the app/helpers, Developer ID Installer signing for the PKG, secure signing timestamps, Apple notarization, and a stapled ticket. The current prerelease does not provide those.

## Prepare an installer

To build your own installer from source, use full Xcode (Swift 6 support), its command-line tools, and XcodeGen. Use the [development build instructions](../CONTRIBUTING.md#development) and [local signing guide](LOCAL_SIGNING.md) to create and verify `build/MacSSHManager.pkg` with your own signing identity. The local installer container is unsigned; its application and helpers must pass certificate-pinned verification.

Build and target Macs must use the same architecture. A universal build does not establish Intel acceptance. macOS 13 is the deployment target; each OS/architecture still needs the checks below.

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
7. Loads CLOSED and verifies the anchor read-back. Independent network probes are required below.

Upgrade repeats these checks and closes any active window first. Failure
leaves or restores the last verified CLOSED configuration. Uninstallation is a
separate administrator-authorized operation and must warn that removing the
controller also removes its port-22 boundary.

## Physical acceptance tests

Complete these checks for each target Mac. Automated tests cover policy logic; they do not replace live installation, reboot, XPC authentication, or independent network probes.

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

## Install from the attached console

Perform these steps with the target Mac's attached display and keyboard. Do not use
normal SSH for installation. First complete [release verification](#verify-a-release-installer) for a downloaded prerelease, or [certificate-pinned verification](LOCAL_SIGNING.md#verify-before-installing) against your own trusted build identity. Then verify the copied artifact and its embedded application without installing it:

```bash
PKG="$HOME/Downloads/MacSSHManager.pkg"
/usr/bin/shasum -a 256 "${PKG}"
/usr/sbin/pkgutil --check-signature "${PKG}"
VERIFY_ROOT=$(/usr/bin/mktemp -d /tmp/macsshmanager-verify.XXXXXX)
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

Before sharing diagnostics, redact usernames, source IPs, interface addresses, and other host-specific data. Do not attach unredacted production logs to public issues.

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

## Troubleshooting: prohibited remote-control service

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
