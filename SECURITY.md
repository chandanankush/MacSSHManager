# Security policy

MacSSHManager is an experimental administrator-operated SSH access controller. Security fixes target the current `main` branch. There are no maintained binary release lines or security-support guarantees for older snapshots.

## Reporting a vulnerability

Email the maintainer at [chandan.ankush@gmail.com](mailto:chandan.ankush@gmail.com) for suspected authorization bypasses, unintended SSH exposure, privilege escalation, trust-policy bypasses, or sensitive-data disclosure. This is the maintainer contact already listed on the [public GitHub profile](https://github.com/chandanankush). Do not put exploit details or credentials in a public issue.

Include the affected commit, macOS version and architecture, expected and observed behavior, and a minimal reproduction using a disposable test Mac. Redact keys, passwords, authorization data, account names, network addresses, and production logs. Coordinate disclosure with the maintainer before publishing exploit details. No response-time or bounty commitment is made.

If you need another private contact method, open an issue titled **Private security contact requested** with no vulnerability details, logs, or attachments. The maintainer will arrange a private channel before you share the report.

## Scope and operational limits

The [security and operations guide](docs/SECURITY_AND_OPERATIONS.md) defines the trust boundaries and physical acceptance procedure. Root access and possession of an administrator credential are outside the threat model. Third-party remote-control detection is advisory.

Passing automated tests does not prove live parent PF ruleset traversal, CLOSED behavior before login, or enforcement on a particular Mac. Perform physical acceptance before relying on a local installation. Source publication is not a claim of a generally supported or notarized firewall product.
