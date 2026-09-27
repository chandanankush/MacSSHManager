# Local signing

This route is for administrator-controlled builds installed on your own Mac. It does not require Apple Developer membership and does not produce an Apple-notarized application. The installer container is unsigned; the app and both helpers are signed with your explicitly supplied certificate. This route does not produce an Apple-trusted, notarized installer.

## Prepare your own identity

Use a dedicated code-signing identity whose private key remains in the build Mac's login keychain. The name and path below are examples, not credentials supplied by this repository.

In Keychain Access, choose **Certificate Assistant > Create a Certificate**, use **Self Signed Root** as the identity type and **Code Signing** as the certificate type, and name it `Mac SSH Manager Local Signing`. Complete creation in the login keychain, then export the public certificate in DER `.cer` format to:

```text
~/Library/Application Support/MacSSHManager/Signing/local-signing.cer
```

Export the public certificate, not a `.p12` signing identity or private key. A certificate without its matching private key on the build Mac cannot sign code. See Apple's [self-signed certificate instructions](https://support.apple.com/guide/keychain-access/create-self-signed-certificates-kyca8916/mac) and [code-signing identity guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html).

Check the identity and exported certificate:

```bash
/usr/bin/security find-identity -p codesigning
/usr/bin/openssl x509 -inform DER \
  -in "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  -checkend 0 -noout
```

The builder checks local identities without requiring global CA trust. It does not change trust-store entries or Gatekeeper settings. Keep private keys out of this repository, packages, logs, and the target Mac. Back up your signing identity securely if needed.

## Build

From the repository root:

```bash
./Installer/build-package.sh \
  --signing-identity "Mac SSH Manager Local Signing" \
  --local-signing-certificate "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  --build-only
```

Supply your actual identity name and certificate location if they differ. The identity's keychain private key must match the public certificate; package verification rejects a mismatch.

Outputs are `build/Mac SSH Manager.app`, `build/MacSSHManager.pkg`, and `build/MacSSHManager.dmg`. Use the package: installation configures root-owned policy, authorization rights, PF, and LaunchDaemons.

The app's own modules are statically linked for this route. All three executable dependency lists must contain only `/System/Library` or `/usr/lib` libraries. The hardened runtime remains enabled without a library-validation exception. Ordinary development builds use dynamic frameworks.

## Identity and architecture checks

The signed menu `Info.plist` carries the certificate pin under the compatibility key `ServerPCLocalSigningCertificateSHA1`. The XPC peer requirement combines the pin with `com.serverpc.ssh-control.controller`. Malformed pins fail closed. The controller independently validates the exact installed menu path, console identity, designated requirement, and code hash from root-owned policy. Ad-hoc signing is rejected.

SHA-1 is used as Apple's code-requirement certificate identifier; package integrity is checked with SHA-256. It is not a password or SSH key.

The installed policy stores one architecture's menu code hash. Build and target Macs must use the same architecture until policy supports multiple hashes. Do not infer Intel acceptance from a universal binary alone.

## Verify before installing

Record the package SHA-256 from the trusted build output. Separately record the certificate SHA-1 and compare it through a trusted channel before accepting an artifact:

```bash
/usr/bin/openssl x509 -inform DER \
  -in "$HOME/Library/Application Support/MacSSHManager/Signing/local-signing.cer" \
  -noout -fingerprint -sha1
```

On the target Mac, from the attached console, set `EXPECTED_CERTIFICATE_SHA1` to that independently verified fingerprint, without colons:

```bash
EXPECTED_CERTIFICATE_SHA1="<40-uppercase-hex-characters-from-your-certificate>"
PKG="$HOME/Downloads/MacSSHManager.pkg"
VERIFY_ROOT=$(/usr/bin/mktemp -d /tmp/macsshmanager-package-verify.XXXXXX)
/usr/bin/shasum -a 256 "$PKG"
/usr/sbin/pkgutil --expand-full "$PKG" "$VERIFY_ROOT/expanded"
APP="$VERIFY_ROOT/expanded/Payload/Library/Application Support/ServerPCSSHControl/.Incoming/Mac SSH Manager.app"
/usr/bin/codesign --verify --deep --strict "$APP"
/usr/bin/codesign --verify --strict --check-expiration \
  -R="certificate leaf = H\"${EXPECTED_CERTIFICATE_SHA1}\"" "$APP"
```

The `Payload` path above is for the default unsigned component package. Installer-signed product archives nest it under `MacSSHManager-component.pkg/Payload`; `Installer/package-payload.sh` accepts both supported layouts.

Do not derive the expected fingerprint only from the downloaded app: it must match the trusted build identity. Do not import the private key or broadly trust the certificate on the target. Certificate-pinned requirements do not require global CA trust.

Follow the [installation and acceptance procedure](INSTALLATION.md#install-from-the-attached-console) and [reboot checks](INSTALLATION.md#verify-closed-before-login). Local build and signature checks do not substitute for live XPC and PF testing.

## Apple signing

The Apple-signing route checks a fixed maintainer team in `Installer/build-package.sh` and `Sources/MenuApp/ControllerClient.swift`. It does not accept an arbitrary Apple Development or Developer ID team just because the identity is available in your keychain. Use the local route for your own build; changing the Apple team requires a reviewed trust-policy change.

The builder has no notarization or stapling step. An optional installer signature does not establish that a package is notarized or suitable for general distribution.
