# Source publication

The publication repository is [chandanankush/MacSSHManager](https://github.com/chandanankush/MacSSHManager). It is prepared as a private repository so its owner can make the final visibility change.

## Completed preparation

- Project and main scheme: `MacSSHManager`; app: **Mac SSH Manager**.
- Complete macOS app icon catalog and compiled icon integration.
- MIT license, README, contribution guidance, security policy with an existing public maintainer contact, issue forms, and pull request template.
- Detailed signing, installation, rollback, trust-boundary, and physical acceptance documentation.
- GitHub Actions builds Release and runs the full test suite without signing secrets or privileged installation. It also runs when repository visibility changes to public.
- Source checks for credential patterns, accidental signing/installer files, documentation links, icon sizes, and built app metadata.
- A new source history using a GitHub no-reply commit address. The original local development history and private historical planning notes are preserved outside the publication repository.

The source distribution excludes generated installers, live logs, signing identities, certificate exports, and private historical planning documents. Existing service identifiers, PF rules, trust checks, and root-owned state paths are deliberately retained for compatibility.

## Validation

The full local automated suite passed all 181 tests, and compiled Debug icon resources and bundle metadata were verified. Publication validation also checks a fresh source checkout, Release compilation, and the GitHub Actions run. Common credential-pattern scans do not prove the absence of every possible sensitive record.

## Final owner action

In the repository's [Settings](https://github.com/chandanankush/MacSSHManager/settings), use **Danger Zone > Change repository visibility > Make public**. The source, license, documentation, and automation are already included; no code or documentation change is required for this step.

## Source distribution and local installation

Source publication is separate from distributing a generally supported binary. The package builder has no notarization or stapling step; local signing produces an unsigned installer container, and Apple signing is pinned to the maintainer team. These are documented project limits, not unfinished source-publication tasks. See Apple's [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) for PF distribution constraints.

Live parent PF ruleset traversal, CLOSED before login, actual XPC authentication, network scope, and crash/expiry behavior require [physical acceptance](SECURITY_AND_OPERATIONS.md#physical-acceptance-tests) for each local installation. Health checks do not independently prove parent-ruleset traversal or provide an enforcer readiness heartbeat. Publishing source or passing CI does not establish those live properties.
