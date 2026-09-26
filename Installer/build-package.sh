#!/bin/bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

SCRIPT_DIR="$(cd "$(dirname "$0")" && /bin/pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/.." && /bin/pwd -P)"
BUILD_ROOT="${REPOSITORY_ROOT}/build"
DERIVED_DATA="${BUILD_ROOT}/PackageDerivedData"
PRODUCTS="${DERIVED_DATA}/Build/Products/Release"
OUTPUT_APP="${BUILD_ROOT}/Mac SSH Manager.app"
PACKAGE_ROOT="${BUILD_ROOT}/PackageRoot"
COMPONENT_PLIST="${BUILD_ROOT}/MacSSHManager-components.plist"
OUTPUT_PACKAGE="${BUILD_ROOT}/MacSSHManager.pkg"
OUTPUT_DMG="${BUILD_ROOT}/MacSSHManager.dmg"
DMG_ROOT="${BUILD_ROOT}/DMGRoot"
SIGNING_IDENTITY=""
INSTALLER_SIGNING_IDENTITY=""
LOCAL_SIGNING_CERTIFICATE=""
LOCAL_CERTIFICATE_SHA1=""
FRAMEWORK_MACH_O_TYPE="mh_dylib"
BUILD_ONLY=0
EXPECTED_TEAM_ID="8ZBMSE6RLV"
XCODEGEN="/opt/homebrew/bin/xcodegen"

usage() {
    /bin/echo "Usage: $0 --signing-identity <identity> [--local-signing-certificate <DER certificate>] [--installer-signing-identity <identity>] --build-only"
}

fail() {
    /bin/echo "Package build failed: $1" >&2
    exit 1
}

reject_ad_hoc_identity() {
    case "$1" in
        -|""|*ad\ hoc*|*Ad\ Hoc*) fail "ad-hoc or empty signing identities are not accepted" ;;
        "Apple Development: "*|"Apple Distribution: "*|"Developer ID Application: "*) ;;
        *) [[ -n "${LOCAL_SIGNING_CERTIFICATE}" ]] || fail "an Apple identity or an explicitly pinned local certificate is required" ;;
    esac
}

identity_is_available() {
    purpose="$1"
    identity="$2"
    if [[ "${purpose}" == codesigning && -n "${LOCAL_SIGNING_CERTIFICATE}" ]]; then
        # A private self-signed certificate need not be a globally trusted CA.
        available_identities="$(/usr/bin/security find-identity -p "${purpose}")"
    else
        available_identities="$(/usr/bin/security find-identity -v -p "${purpose}")"
    fi
    /usr/bin/grep -Fq "\"${identity}\"" <<<"${available_identities}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --signing-identity)
            [[ $# -ge 2 ]] || fail "--signing-identity needs a value"
            SIGNING_IDENTITY="$2"
            shift 2
            ;;
        --installer-signing-identity)
            [[ $# -ge 2 ]] || fail "--installer-signing-identity needs a value"
            INSTALLER_SIGNING_IDENTITY="$2"
            shift 2
            ;;
        --local-signing-certificate)
            [[ $# -ge 2 ]] || fail "--local-signing-certificate needs a value"
            LOCAL_SIGNING_CERTIFICATE="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *) fail "unknown option: $1" ;;
    esac
done

[[ "${BUILD_ONLY}" -eq 1 ]] || fail "--build-only is required; this script never installs"
[[ "${#SIGNING_IDENTITY}" -le 200 && "${SIGNING_IDENTITY}" != *$'\n'* ]] || fail "invalid signing identity"
reject_ad_hoc_identity "${SIGNING_IDENTITY}"
identity_is_available codesigning "${SIGNING_IDENTITY}" || fail "application signing identity is unavailable"

if [[ -n "${LOCAL_SIGNING_CERTIFICATE}" ]]; then
    [[ -f "${LOCAL_SIGNING_CERTIFICATE}" ]] || fail "local signing certificate is missing"
    /usr/bin/openssl x509 -inform DER -in "${LOCAL_SIGNING_CERTIFICATE}" -checkend 0 -noout >/dev/null || \
        fail "local signing certificate is invalid or expired"
    LOCAL_CERTIFICATE_SHA1="$(/usr/bin/openssl x509 -inform DER -in "${LOCAL_SIGNING_CERTIFICATE}" -noout -fingerprint -sha1 | /usr/bin/awk -F= '{gsub(":", "", $2); print toupper($2)}')"
    [[ "${LOCAL_CERTIFICATE_SHA1}" =~ ^[0-9A-F]{40}$ ]] || fail "cannot read local certificate fingerprint"
    # Self-signed certificates have no Apple Team ID. Statically link our own
    # modules so hardened library validation needs only Apple system libraries.
    FRAMEWORK_MACH_O_TYPE="staticlib"
fi

if [[ -n "${INSTALLER_SIGNING_IDENTITY}" ]]; then
    [[ "${INSTALLER_SIGNING_IDENTITY}" == "Developer ID Installer: "* || \
       "${INSTALLER_SIGNING_IDENTITY}" == "Mac Installer Distribution: "* ]] || \
        fail "unsupported installer signing identity"
    identity_is_available basic "${INSTALLER_SIGNING_IDENTITY}" || fail "installer signing identity is unavailable"
fi

[[ -x "${XCODEGEN}" ]] || fail "required build tool is unavailable: ${XCODEGEN}"
for tool in /usr/bin/xcodebuild /usr/bin/codesign /usr/bin/pkgbuild \
    /usr/bin/productbuild /usr/bin/plutil /usr/bin/ditto /usr/bin/hdiutil; do
    [[ -x "${tool}" ]] || fail "required build tool is unavailable: ${tool}"
done

/bin/rm -rf "${DERIVED_DATA}" "${OUTPUT_APP}" "${PACKAGE_ROOT}" \
    "${OUTPUT_PACKAGE}" "${OUTPUT_DMG}" "${DMG_ROOT}" \
    "${BUILD_ROOT}/MacSSHManager-component.pkg" "${COMPONENT_PLIST}"
/bin/mkdir -p "${BUILD_ROOT}"

cd "${REPOSITORY_ROOT}"
"${XCODEGEN}" generate
/usr/bin/xcodebuild build \
    -quiet \
    -project MacSSHManager.xcodeproj \
    -scheme MacSSHManager \
    -configuration Release \
    -derivedDataPath "${DERIVED_DATA}" \
    CODE_SIGNING_ALLOWED=NO \
    ENABLE_HARDENED_RUNTIME=YES \
    SERVERPC_FRAMEWORK_MACH_O_TYPE="${FRAMEWORK_MACH_O_TYPE}"

SOURCE_APP="${PRODUCTS}/Mac SSH Manager.app"
[[ -d "${SOURCE_APP}" ]] || fail "menu application product is missing"
/usr/bin/ditto "${SOURCE_APP}" "${OUTPUT_APP}"
/bin/rm -rf "${OUTPUT_APP}/Contents/Frameworks"

/bin/mkdir -p \
    "${OUTPUT_APP}/Contents/Library/Helpers" \
    "${OUTPUT_APP}/Contents/Frameworks" \
    "${OUTPUT_APP}/Contents/Resources"

/usr/bin/ditto "${PRODUCTS}/serverpc-ssh-controller" \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller"
/usr/bin/ditto "${PRODUCTS}/serverpc-ssh-expiry-enforcer" \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer"

if [[ -z "${LOCAL_SIGNING_CERTIFICATE}" ]]; then
    for framework in SharedProtocol SecurityCore ControllerTransport MenuAppCore; do
        [[ -d "${PRODUCTS}/${framework}.framework" ]] || fail "missing framework: ${framework}"
        /usr/bin/ditto "${PRODUCTS}/${framework}.framework" \
            "${OUTPUT_APP}/Contents/Frameworks/${framework}.framework"
    done
else
    /usr/bin/plutil -insert ServerPCLocalSigningCertificateSHA1 -string "${LOCAL_CERTIFICATE_SHA1}" \
        "${OUTPUT_APP}/Contents/Info.plist"
    for executable in "${OUTPUT_APP}/Contents/MacOS/Mac SSH Manager" \
        "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller" \
        "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer"; do
        dependencies="$(/usr/bin/otool -L "${executable}" | /usr/bin/awk '/^[[:space:]]/ { print $1 }')"
        [[ -n "${dependencies}" ]] || fail "cannot inspect local-build dependencies"
        while IFS= read -r dependency; do
            case "${dependency}" in
                /System/Library/*|/usr/lib/*) ;;
                *) fail "local build must link only Apple system libraries: ${dependency}" ;;
            esac
        done <<<"${dependencies}"
    done
fi

/usr/bin/ditto "${REPOSITORY_ROOT}/Config/com.serverpc.ssh-control.controller.plist" \
    "${OUTPUT_APP}/Contents/Resources/controller-launchd.plist"
/usr/bin/ditto "${REPOSITORY_ROOT}/Config/com.serverpc.ssh-control.enforcer.plist" \
    "${OUTPUT_APP}/Contents/Resources/enforcer-launchd.plist"
/usr/bin/ditto "${REPOSITORY_ROOT}/Config/closed-anchor.conf" \
    "${OUTPUT_APP}/Contents/Resources/closed-anchor.conf"
/usr/bin/ditto "${REPOSITORY_ROOT}/Config/AuthorizationRight.plist" \
    "${OUTPUT_APP}/Contents/Resources/AuthorizationRight.plist"
/usr/bin/ditto "${REPOSITORY_ROOT}/Installer/resources/README.txt" \
    "${OUTPUT_APP}/Contents/Resources/README.txt"
/usr/bin/ditto "${REPOSITORY_ROOT}/Installer/scripts/uninstall" \
    "${OUTPUT_APP}/Contents/Resources/uninstall"
/bin/chmod 755 \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller" \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer" \
    "${OUTPUT_APP}/Contents/Resources/uninstall"

for framework in "${OUTPUT_APP}"/Contents/Frameworks/*.framework; do
    [[ -d "${framework}" ]] || continue
    /usr/bin/codesign --force --options runtime --timestamp=none \
        --sign "${SIGNING_IDENTITY}" "${framework}"
done
/usr/bin/codesign --force --options runtime --timestamp=none \
    --identifier com.serverpc.ssh-control.controller \
    --sign "${SIGNING_IDENTITY}" \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller"
/usr/bin/codesign --force --options runtime --timestamp=none \
    --identifier com.serverpc.ssh-control.enforcer \
    --sign "${SIGNING_IDENTITY}" \
    "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer"
/usr/bin/codesign --force --options runtime --timestamp=none \
    --identifier com.serverpc.ssh-control.menu \
    --sign "${SIGNING_IDENTITY}" \
    "${OUTPUT_APP}/Contents/MacOS/Mac SSH Manager"
/usr/bin/codesign --force --options runtime --timestamp=none \
    --sign "${SIGNING_IDENTITY}" "${OUTPUT_APP}"
/usr/bin/codesign --verify --deep --strict "${OUTPUT_APP}"
controller_details="$(/usr/bin/codesign -d --verbose=4 "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller" 2>&1)"
enforcer_details="$(/usr/bin/codesign -d --verbose=4 "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer" 2>&1)"
/usr/bin/grep -Fqx 'Identifier=com.serverpc.ssh-control.controller' <<<"${controller_details}" || \
    fail "controller signature has the wrong identifier"
/usr/bin/grep -Fqx 'Identifier=com.serverpc.ssh-control.enforcer' <<<"${enforcer_details}" || \
    fail "enforcer signature has the wrong identifier"

signature_details="$(/usr/bin/codesign -d --verbose=4 "${OUTPUT_APP}" 2>&1)"
expected_executable="${OUTPUT_APP}/Contents/MacOS/Mac SSH Manager"
/usr/bin/grep -Fqx "Executable=${expected_executable}" <<<"${signature_details}" || \
    fail "signed bundle is not bound to the expected menu executable"
team_id="$(/usr/bin/awk -F= '$1 == "TeamIdentifier" { print $2; exit }' <<<"${signature_details}")"
if [[ -z "${LOCAL_SIGNING_CERTIFICATE}" ]]; then
    [[ "${team_id}" == "${EXPECTED_TEAM_ID}" ]] || fail "application TeamIdentifier is not ${EXPECTED_TEAM_ID}"
else
    for signed_code in "${OUTPUT_APP}" \
        "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-controller" \
        "${OUTPUT_APP}/Contents/Library/Helpers/serverpc-ssh-expiry-enforcer"; do
        /usr/bin/codesign --verify --strict --check-expiration \
            -R="certificate leaf = H\"${LOCAL_CERTIFICATE_SHA1}\"" "${signed_code}"
    done
    /bin/echo "Local certificate pin: ${LOCAL_CERTIFICATE_SHA1} (no Apple enrollment or global trust changes)"
fi

menu_executable="${OUTPUT_APP}/Contents/MacOS/Mac SSH Manager"
requirement_line="$(/usr/bin/codesign -d -r- "${menu_executable}" 2>&1 | /usr/bin/awk '/^designated => / { sub(/^designated => /, ""); print }')"
cd_hash="$(/usr/bin/codesign -d --verbose=4 "${menu_executable}" 2>&1 | /usr/bin/awk -F= '$1 == "CDHash" { print toupper($2) }')"
[[ -n "${requirement_line}" && "${#requirement_line}" -le 4096 ]] || fail "cannot read designated requirement"
[[ "${cd_hash}" =~ ^[0-9A-F]{40}$|^[0-9A-F]{64}$ ]] || fail "cannot read application CDHash"

policy_plist="${BUILD_ROOT}/trusted-client.plist"
policy_json="${BUILD_ROOT}/trusted-client.json"
/usr/bin/plutil -create xml1 "${policy_plist}"
/usr/bin/plutil -insert applicationPath -string \
    "/Applications/Mac SSH Manager.app/Contents/MacOS/Mac SSH Manager" \
    "${policy_plist}"
/usr/bin/plutil -insert bundleIdentifier -string "com.serverpc.ssh-control.menu" "${policy_plist}"
/usr/bin/plutil -insert designatedRequirement -string "${requirement_line}" "${policy_plist}"
/usr/bin/plutil -insert cdHash -string "${cd_hash}" "${policy_plist}"
/usr/bin/plutil -convert json -o "${policy_json}" "${policy_plist}"
/bin/rm -f "${policy_plist}"

incoming_root="${PACKAGE_ROOT}/Library/Application Support/ServerPCSSHControl/.Incoming"
/bin/mkdir -p "${incoming_root}"
/usr/bin/ditto "${OUTPUT_APP}" "${incoming_root}/Mac SSH Manager.app"
/usr/bin/install -m 600 "${policy_json}" "${incoming_root}/trusted-client.json"

/usr/bin/pkgbuild --analyze --root "${PACKAGE_ROOT}" "${COMPONENT_PLIST}"
/usr/bin/plutil -replace '0.BundleIsRelocatable' -bool NO "${COMPONENT_PLIST}"

/usr/bin/pkgbuild \
    --root "${PACKAGE_ROOT}" \
    --component-plist "${COMPONENT_PLIST}" \
    --scripts "${REPOSITORY_ROOT}/Installer/scripts" \
    --identifier com.serverpc.ssh-control \
    --version 1.0.0 \
    --ownership recommended \
    "${BUILD_ROOT}/MacSSHManager-component.pkg"

if [[ -n "${INSTALLER_SIGNING_IDENTITY}" ]]; then
    /usr/bin/productbuild \
        --package "${BUILD_ROOT}/MacSSHManager-component.pkg" \
        --sign "${INSTALLER_SIGNING_IDENTITY}" \
        "${OUTPUT_PACKAGE}"
    /bin/echo "Package container signature: signed with explicitly supplied Installer identity."
else
    /bin/mv "${BUILD_ROOT}/MacSSHManager-component.pkg" "${OUTPUT_PACKAGE}"
    /bin/echo "Package container signature: unsigned (application payload is signed and verified)."
fi

verification_root="$(/usr/bin/mktemp -d "${BUILD_ROOT}/package-verification.XXXXXX")"
/usr/sbin/pkgutil --expand-full "${OUTPUT_PACKAGE}" "${verification_root}/expanded"
payload_root="$(/bin/bash "${SCRIPT_DIR}/package-payload.sh" "${verification_root}/expanded")"
packaged_app="${payload_root}/Library/Application Support/ServerPCSSHControl/.Incoming/Mac SSH Manager.app"
packaged_policy="${payload_root}/Library/Application Support/ServerPCSSHControl/.Incoming/trusted-client.json"
/usr/bin/codesign --verify --deep --strict "${packaged_app}"
/usr/bin/plutil -p "${packaged_policy}" >/dev/null
/bin/rm -rf "${verification_root}"

/usr/sbin/pkgutil --check-signature "${OUTPUT_PACKAGE}" || true
/bin/mkdir -p "${DMG_ROOT}"
/usr/bin/ditto "${OUTPUT_PACKAGE}" "${DMG_ROOT}/Install Mac SSH Manager.pkg"
/usr/bin/ditto "${REPOSITORY_ROOT}/Installer/resources/README.txt" "${DMG_ROOT}/README.txt"
/usr/bin/hdiutil create -quiet -volname "Mac SSH Manager Installer" \
    -srcfolder "${DMG_ROOT}" -ov -format UDZO "${OUTPUT_DMG}"
/bin/rm -rf "${DMG_ROOT}"
/usr/bin/shasum -a 256 "${OUTPUT_APP}/Contents/MacOS/Mac SSH Manager" "${OUTPUT_PACKAGE}"
/bin/echo "Built application: ${OUTPUT_APP}"
/bin/echo "Built package: ${OUTPUT_PACKAGE}"
/bin/echo "Built disk image: ${OUTPUT_DMG}"
/bin/echo "Nothing was installed."
