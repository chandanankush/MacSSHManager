<img src="docs/assets/MacSSHManager.png" alt="Mac SSH Manager icon" width="112">

# MacSSHManager

[![CI](https://github.com/chandanankush/MacSSHManager/actions/workflows/ci.yml/badge.svg)](https://github.com/chandanankush/MacSSHManager/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Mac SSH Manager** is a macOS menu-bar app for opening short, administrator-authorized SSH access windows. It controls this Mac's normal SSH service on TCP port 22, with separate LAN and Tailscale scopes.

The project is experimental. Automated checks do not replace installation and reboot testing on the target Mac. The source is available under the [MIT license](LICENSE). This project does not provide a generally supported, notarized binary release.

## Features

- SSH closed by default, with CLOSED restored after expiry or reboot.
- Access windows of 15 minutes, 30 minutes, 60 minutes, 3 hours, or 6 hours, each requiring fresh macOS administrator authorization.
- Explicit LAN, Tailscale, or combined scope for each window.
- Immediate closure and termination of active port-22 SSH sessions.
- An independent privileged expiry service when the menu app is unavailable.
- Searchable access and SSH session history without recording passwords, keys, commands, or terminal contents.
- Optional local-console-only restriction and launch at login.

The app controls inbound access to this Mac. It does not act as an outbound SSH client, manage SSH keys, or control other ports.

## Requirements and limits

- Deployment target: macOS 13 or later. This is not a claim that every OS version has completed physical acceptance testing.
- Building: full Xcode with Swift 6 support, Xcode command-line tools, and [XcodeGen](https://github.com/yonaskolb/XcodeGen).
- Installing: administrator access at the target Mac's attached display and keyboard. The installer changes PF, Remote Login, and SSH authentication policy.
- LAN access needs a resolvable physical interface. Tailscale access needs a running installation with a supported IPv4 route; Tailscale IPv6 SSH is blocked.
- The client policy stores one architecture's code hash. Build and target Macs must use the same architecture; a universal binary alone does not establish Intel acceptance.
- The Apple-signing path is pinned to the maintainer's team. For your own local installation, use the explicitly pinned certificate route in [Local signing](docs/LOCAL_SIGNING.md).

Apple describes PF as an administrator mechanism rather than a supported firewall-product API. This limits the distribution model. See [TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api).

## Build and test

Clone the repository and run these commands from its root:

```bash
git clone https://github.com/chandanankush/MacSSHManager.git
cd MacSSHManager
```

```bash
xcodegen generate
xcodebuild test \
  -project MacSSHManager.xcodeproj \
  -scheme MacSSHManager \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
```

To build the menu app for development:

```bash
xcodebuild build \
  -project MacSSHManager.xcodeproj \
  -scheme MacSSHManager \
  -configuration Debug \
  -derivedDataPath build/DerivedData \
  CODE_SIGNING_ALLOWED=NO
```

The app product is `build/DerivedData/Build/Products/Debug/Mac SSH Manager.app`. An unsigned development app does not satisfy the installed controller's trust policy. The package builder embeds and signs the privileged helpers and creates the installed client policy.

## Build an installer

Prepare your own code-signing identity and public DER certificate using [Local signing](docs/LOCAL_SIGNING.md). With that guide's example identity and location:

```bash
./Installer/build-package.sh \
  --signing-identity "Mac SSH Manager Local Signing" \
  --local-signing-certificate "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  --build-only
```

Outputs are `build/Mac SSH Manager.app`, `build/MacSSHManager.pkg`, and `build/MacSSHManager.dmg`. The local-signing route signs the application and helpers; its installer container is unsigned and the app is not notarized. The script builds and verifies artifacts without installing them.

## Install from the attached console

Follow the full [installation and acceptance procedure](docs/SECURITY_AND_OPERATIONS.md#install-from-the-attached-console), including artifact verification, helper state, and independent CLOSED probes before opening SSH. Use the installer package: dragging the app into Applications does not install the security controls.

The installed app is `/Applications/Mac SSH Manager.app`. For compatibility, service identifiers still use `com.serverpc.ssh-control`, and operational state remains under `/Library/Application Support/ServerPCSSHControl`.

When moving from **ServerPC SSH Control**, read the [upgrade guidance](docs/SECURITY_AND_OPERATIONS.md#installation-and-upgrade). The rename does not automatically remove the previously named app or its login item.

## Basic use

1. Open **Mac SSH Manager** from Applications.
2. Select LAN and/or Tailscale and an access duration.
3. Choose **Open SSH** and approve the macOS administrator prompt.
4. Choose **Close now** when finished; expiry also closes access and terminates active port-22 sessions.
5. Choose **View full history** to review recent activity.

Both scope checkboxes initially select ON. Check the selection before approving a window. OPEN stays unavailable while enforcement is recovering, unavailable, or degraded.

## Troubleshooting

- **Control unavailable or recovering:** inspect [PF reboot recovery](docs/PACKET_FILTER_REBOOT_RECOVERY.md), helper state, and logs at the attached console. A running helper alone is not proof of enforcement.
- **A prohibited remote-control service is active:** follow the [local-console troubleshooting procedure](docs/SECURITY_AND_OPERATIONS.md#troubleshooting-prohibited-remote-control-service).
- **No usable Tailscale scope:** check the [route requirements](docs/SECURITY_AND_OPERATIONS.md#tailscale); ambiguous or changed routes are rejected.
- **Signing fails:** check the identity, matching private key, DER certificate, and architecture requirements in [Local signing](docs/LOCAL_SIGNING.md). Ad-hoc signatures are rejected.

## Rollback

At the target Mac's attached console, with the installed app intact:

```bash
sudo "/Applications/Mac SSH Manager.app/Contents/Resources/uninstall"
```

Uninstalling removes the port-22 protection and can make SSH reachable again. Read the full [rollback procedure](docs/SECURITY_AND_OPERATIONS.md#rollback) first.

## Documentation

- [Security design, installation, and physical acceptance](docs/SECURITY_AND_OPERATIONS.md)
- [Local signing and package verification](docs/LOCAL_SIGNING.md)
- [PF startup and reboot recovery](docs/PACKET_FILTER_REBOOT_RECOVERY.md)
- [Contributing and validation](CONTRIBUTING.md)
- [Source publication and validation](docs/PUBLIC_RELEASE.md)
- [Security reporting policy](SECURITY.md)
- [MIT license](LICENSE)
- [Changelog](CHANGELOG.md)

The repository contains source, tests, installer scripts, and documentation. Generated installers, signing identities, operational logs, and private development history are not part of the source distribution.
