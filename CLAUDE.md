# Working in this repository

Mac SSH Manager is an experimental, security-sensitive macOS menu-bar utility. Before changing behavior, read [Architecture](docs/ARCHITECTURE.md) and the [Security model](docs/SECURITY_MODEL.md). Build/test commands and source conventions are in [Contributing](CONTRIBUTING.md).

## Boundaries to preserve

- OPEN and replacement windows require fresh macOS administrator authorization. CLOSE and expiry must remain independent of authorization and audit success.
- Accept only fixed, typed XPC requests. Never accept shell commands, arbitrary paths, argument lists, PF rules, or PIDs from clients.
- Preserve signed-client validation, root-owned state, the independent close-only enforcer, narrow PF anchor updates, and exact rule read-back checks.
- Do not disable PF, flush unrelated rules, alter SSH keys, or add remote activation APIs.
- Keep audit fields allowlisted. Never include credentials, authorization blobs, SSH keys, commands, terminal contents, or process arguments.
- Keep this repository standalone; do not import unrelated application services.

## Safe development

`project.yml` is the XcodeGen source; regenerate the committed project after target, resource, or build-setting changes. Use unsigned builds and fakes for automated tests, including authorization requests.

Installation, uninstallation, live PF/SSH changes, and physical acceptance require the target Mac's attached display and keyboard. Follow [Installation](docs/INSTALLATION.md); do not execute these operations through an agent or an SSH connection.

Keep user instructions in the README and technical details in the focused guides. Use generic paths and redact personal data from examples.
