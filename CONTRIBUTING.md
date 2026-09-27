# Contributing

MacSSHManager is an experimental, security-sensitive macOS utility. Read the [architecture](docs/ARCHITECTURE.md) and [security model](docs/SECURITY_MODEL.md) before changing policy or installer behavior. Contributions are made under the [MIT license](LICENSE). Report suspected vulnerabilities using the [security policy](SECURITY.md).

## Development

Use full Xcode with Swift 6 support, its command-line tools, and [XcodeGen](https://github.com/yonaskolb/XcodeGen). Clone the repository and work from its root:

```bash
git clone https://github.com/chandanankush/MacSSHManager.git
cd MacSSHManager
```

The project is defined in `project.yml`. The generated `MacSSHManager.xcodeproj` is committed alongside the source. Regenerate after changing targets, resources, or build settings:

```bash
xcodegen generate
```

Check source metadata, documentation links, and icon entries with `python3 scripts/check-source.py`. Then run the existing test suite without installing anything:

```bash
xcodebuild test \
  -project MacSSHManager.xcodeproj \
  -scheme MacSSHManager \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
```

Individual test schemes are available for `SharedProtocolTests`, `SecurityCoreTests`, `ControllerTests`, `IntegrationTests`, and `MenuAppTests`.

Build an unsigned development app without installing it:

```bash
xcodebuild build \
  -project MacSSHManager.xcodeproj \
  -scheme MacSSHManager \
  -configuration Debug \
  -derivedDataPath build/DerivedData \
  CODE_SIGNING_ALLOWED=NO
```

The product is `build/DerivedData/Build/Products/Debug/Mac SSH Manager.app`. It cannot authenticate to an installed controller as an unsigned development build. For a signed installer with both privileged helpers and trusted-client policy, follow [Local signing](docs/LOCAL_SIGNING.md).

GitHub CI checks source metadata and installer syntax, runs the full test suite, builds Release, and verifies the built app's name and icon. Tests must use fakes for authorization prompts and privileged operations so they run without interaction.

## Security boundaries

- Preserve fresh administrator authorization for OPEN and replacement windows; CLOSE and expiry must not depend on authorization succeeding.
- Keep privileged commands fixed and bounded. XPC callers must never supply shell commands, executable paths, arbitrary arguments, or PF rules.
- Preserve signed-client validation, root-owned policy and state, the independent expiry enforcer, and exact PF read-back checks.
- Never disable PF or flush unrelated rules or states.
- Keep audit fields allowlisted; never record keys, credentials, authorization blobs, commands, or terminal contents.
- Test enforcement with fakes. Live installation, uninstallation, PF changes, and acceptance checks belong at the target Mac's attached console.

## Icons and documentation

The app icon is in `Resources/Assets.xcassets/AppIcon.appiconset`. Its ten PNG entries cover macOS 16, 32, 128, 256, and 512 point slots at 1x and 2x. `docs/assets/MacSSHManager.png` is the master, generated with OpenAI image generation. Keep exported assets free of personal or provider attestation metadata. The menu-bar symbols separately indicate SSH status.

Keep the README focused on using the app. Put implementation detail in `docs/ARCHITECTURE.md`, threat boundaries in `docs/SECURITY_MODEL.md`, and live procedures in `docs/INSTALLATION.md`. Do not include personal paths, private keys, certificate exports, real logs, or host-specific credentials in examples.

## Pull requests

Describe the concrete change and relevant validation. Keep behavior changes focused and explain any effect on authorization, PF, installed paths, or compatibility. Never attach signing identities, production audit logs, credentials, or authorization blobs to issues or pull requests.
