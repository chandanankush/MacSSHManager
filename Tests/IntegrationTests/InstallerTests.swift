import Foundation
import XCTest
@testable import SharedProtocol

final class InstallerTests: XCTestCase {
    func testPayloadLocatorHandlesRealComponentAndProductPackages() throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let root = temporary.appendingPathComponent("root")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try Data("verified payload".utf8).write(to: root.appendingPathComponent("sentinel.txt"))
        let component = temporary.appendingPathComponent("MacSSHManager-component.pkg")
        let product = temporary.appendingPathComponent("product.pkg")
        XCTAssertEqual(try runTool("/usr/bin/pkgbuild", ["--root", root.path, "--identifier", "com.serverpc.payload-test", "--version", "1", component.path]).status, 0)
        XCTAssertEqual(try runTool("/usr/bin/productbuild", ["--package", component.path, product.path]).status, 0)
        for (index, package) in [component, product].enumerated() {
            let expanded = temporary.appendingPathComponent("expanded-\(index)")
            XCTAssertEqual(try runTool("/usr/sbin/pkgutil", ["--expand-full", package.path, expanded.path]).status, 0)
            let located = try locatePayload(expanded)
            XCTAssertEqual(located.status, 0, located.output)
            guard located.status == 0 else { continue }
            let sentinel = URL(fileURLWithPath: located.output.trimmingCharacters(in: .whitespacesAndNewlines)).appendingPathComponent("sentinel.txt")
            XCTAssertEqual(try String(contentsOf: sentinel, encoding: .utf8), "verified payload")
        }
    }

    func testPayloadLocatorRejectsMissingAndAmbiguousPayloads() throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        XCTAssertNotEqual(try locatePayload(temporary).status, 0)
        for path in ["Payload", "MacSSHManager-component.pkg/Payload"] {
            try FileManager.default.createDirectory(at: temporary.appendingPathComponent(path), withIntermediateDirectories: true)
        }
        XCTAssertNotEqual(try locatePayload(temporary).status, 0)
    }

    private func locatePayload(_ expanded: URL) throws -> (status: Int32, output: String) {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try runTool("/bin/bash", [repository.appendingPathComponent("Installer/package-payload.sh").path, expanded.path])
    }

    private func runTool(_ executable: String, _ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    func testPackageDestinationIsRootProtected() {
        XCTAssertEqual(
            InstalledPaths.applicationBundle,
            "/Applications/Mac SSH Manager.app"
        )
    }

    func testInstallerMovesTheAppToApplicationsAndPreservesProtectedState() throws {
        let postinstall = try installerScript(named: "postinstall")
        let uninstall = try installerScript(named: "uninstall")

        XCTAssertTrue(postinstall.contains("FINAL_APP=\"/Applications/Mac SSH Manager.app\""))
        XCTAssertTrue(postinstall.contains("LEGACY_APP=\"${APP_ROOT}/ServerPC SSH Control.app\""))
        XCTAssertTrue(postinstall.contains("/bin/rm -rf \"${LEGACY_APP}\""))
        XCTAssertTrue(uninstall.contains("APP=\"/Applications/Mac SSH Manager.app\""))
        XCTAssertTrue(uninstall.contains("/bin/rm -rf \"${APP}\""))
    }

    func testPostinstallClosesBeforeMakingMenuAvailable() throws {
        let script = try installerScript(named: "postinstall")
        XCTAssertBefore("enforce_closed", "verify_closed", in: script)
        XCTAssertBefore("verify_closed", "make_menu_available", in: script)
        XCTAssertBefore("configure_managed_ssh_policy", "make_menu_available", in: script)
        XCTAssertBefore("make_menu_available", "install_privileged_services", in: script)
        XCTAssertTrue(script.contains("/etc/ssh/sshd_config.d/00-serverpc-ssh-control.conf"))
        XCTAssertTrue(script.contains("PasswordAuthentication no"))
        XCTAssertTrue(script.contains("KbdInteractiveAuthentication no"))
        XCTAssertTrue(script.contains("PubkeyAuthentication yes"))
        XCTAssertTrue(script.contains("PermitRootLogin no"))
        XCTAssertTrue(script.contains("launchctl bootstrap system"))
        XCTAssertTrue(script.contains("/Library/LaunchDaemons/com.serverpc.ssh-control.controller.plist"))
        XCTAssertTrue(script.contains("/Library/LaunchDaemons/com.serverpc.ssh-control.enforcer.plist"))
        XCTAssertTrue(script.contains("managed-ssh-policy-v2"))
        XCTAssertTrue(script.contains("write_legacy_managed_ssh_policy_v1"))
        XCTAssertTrue(script.contains("rollback_closed 1"))
        XCTAssertTrue(script.contains("set -o errtrace"))
        XCTAssertTrue(script.contains(
            "SSH_POLICY_UPGRADED=1\n            /usr/bin/install -o root -g wheel -m 600 \"${policy_source}\" \"${SSH_POLICY_FILE}\""
        ))
    }

    func testInstallerPreparesUsableSSHServerAndUninstallerRestoresRemoteLogin() throws {
        let postinstall = try installerScript(named: "postinstall")
        let uninstall = try installerScript(named: "uninstall")

        XCTAssertTrue(postinstall.contains("/usr/sbin/systemsetup -getremotelogin"))
        XCTAssertTrue(postinstall.contains("/usr/sbin/systemsetup -setremotelogin on"))
        XCTAssertTrue(postinstall.contains("/usr/bin/ssh-keygen -A"))
        XCTAssertTrue(postinstall.contains("verify_closed\nconfigure_managed_remote_login\nconfigure_managed_ssh_policy"))
        XCTAssertTrue(uninstall.contains("REMOTE_LOGIN_MARKER"))
        XCTAssertTrue(uninstall.contains("/usr/sbin/systemsetup -setremotelogin off"))
        XCTAssertBefore("remove_managed_ssh_policy", "remove_managed_remote_login", in: uninstall)
    }

    func testInstallerPlacesPlainLanguageReadmeInProtectedSupportFolder() throws {
        let buildScript = try repositoryFile("Installer/build-package.sh")
        let postinstall = try installerScript(named: "postinstall")
        let readme = try repositoryFile("Installer/resources/README.txt")

        XCTAssertTrue(buildScript.contains("Installer/resources/README.txt"))
        XCTAssertTrue(postinstall.contains("SUPPORT_README=\"${APP_ROOT}/README.txt\""))
        XCTAssertTrue(postinstall.contains("/usr/bin/install -o root -g wheel -m 644"))
        XCTAssertTrue(readme.contains("To remove Mac SSH Manager"))
        XCTAssertTrue(readme.contains("/Applications/Mac SSH Manager.app/Contents/Resources/uninstall"))
    }

    func testInstallerScriptsAreFailFastAndNeverDisableOrFlushPF() throws {
        for name in ["preinstall", "postinstall", "uninstall"] {
            let script = try installerScript(named: name)
            XCTAssertTrue(script.contains("set -euo pipefail"), name)
            XCTAssertFalse(script.contains("pfctl -d"), name)
            XCTAssertFalse(script.contains("-F all"), name)
        }
    }

    func testPackageBuildProducesInstallerDMGInsteadOfDragCopyDistribution() throws {
        let script = try repositoryFile("Installer/build-package.sh")
        XCTAssertTrue(script.contains("MacSSHManager.dmg"))
        XCTAssertTrue(script.contains("Install Mac SSH Manager.pkg"))
        XCTAssertTrue(script.contains("/usr/bin/hdiutil create"))
    }

    func testPreinstallChecksPFSyntaxWithoutRequiringExistingSSHPolicy() throws {
        let script = try installerScript(named: "preinstall")
        XCTAssertFalse(script.contains("/usr/sbin/sshd -T"))
        XCTAssertTrue(script.contains("/sbin/pfctl -nf /etc/pf.conf"))
    }

    func testUninstallClosesBeforeRemovingManagedArtifacts() throws {
        let script = try installerScript(named: "uninstall")
        XCTAssertBefore("enforce_closed", "remove_managed_artifacts", in: script)
        XCTAssertBefore("remove_managed_launch_daemons", "remove_managed_artifacts", in: script)
        XCTAssertTrue(script.contains("--close-once"))
        XCTAssertTrue(script.contains("Normal port 22 is no longer protected"))
        XCTAssertBefore("enforce_closed", "remove_managed_ssh_policy", in: script)
        XCTAssertBefore("remove_managed_ssh_policy", "remove_managed_artifacts", in: script)
        XCTAssertTrue(script.contains("/etc/ssh/sshd_config.d/00-serverpc-ssh-control.conf"))
        XCTAssertTrue(script.contains("SSH_POLICY_MARKER"))
        XCTAssertTrue(script.contains("/Library/LaunchDaemons/com.serverpc.ssh-control.controller.plist"))
        XCTAssertTrue(script.contains("/Library/LaunchDaemons/com.serverpc.ssh-control.enforcer.plist"))
        XCTAssertTrue(script.contains("was modified; refusing to remove it"))
        XCTAssertFalse(script.localizedCaseInsensitiveContains("authorized_keys"))
    }

    func testUninstallUnregistersAndTerminatesTheMenuAppBeforeDeletingIt() throws {
        let script = try installerScript(named: "uninstall")

        XCTAssertTrue(script.contains("--unregister-login-item"))
        XCTAssertTrue(script.contains("/usr/bin/sudo -u \"${console_user}\""))
        XCTAssertTrue(script.contains("/usr/bin/pkill -x \"Mac SSH Manager\""))
        XCTAssertBefore("remove_managed_login_item", "remove_managed_artifacts", in: script)
    }

    func testUninstallRemovesOnlyTheBoundedAuditRotations() throws {
        let script = try installerScript(named: "uninstall")

        XCTAssertTrue(script.contains("/var/log/serverpc-ssh-control.jsonl.1"))
        XCTAssertTrue(script.contains("/var/log/serverpc-ssh-control.jsonl.5"))
        XCTAssertFalse(script.contains("serverpc-ssh-control.jsonl.*"))
    }

    func testBuildScriptRequiresExplicitNonAdHocSigningIdentity() throws {
        let script = try repositoryFile("Installer/build-package.sh")
        XCTAssertTrue(script.contains("--signing-identity"))
        XCTAssertTrue(script.contains("reject_ad_hoc_identity"))
        XCTAssertTrue(script.contains("codesign --verify --deep --strict"))
        XCTAssertTrue(script.contains("designatedRequirement"))
        XCTAssertTrue(script.contains("cdHash"))
    }

    func testBuildScriptPinsTheIncomingAppAtItsPayloadPath() throws {
        let script = try repositoryFile("Installer/build-package.sh")
        XCTAssertTrue(script.contains("PackageDerivedData"))
        XCTAssertTrue(script.contains("pkgbuild --analyze --root"))
        XCTAssertTrue(script.contains("BundleIsRelocatable"))
        XCTAssertTrue(script.contains("--component-plist"))
    }

    private func installerScript(named name: String) throws -> String {
        try repositoryFile("Installer/scripts/\(name)")
    }

    private func repositoryFile(_ relativePath: String) throws -> String {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(contentsOf: repository.appendingPathComponent(relativePath), encoding: .utf8)
    }

    private func XCTAssertBefore(
        _ first: String,
        _ second: String,
        in text: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let firstRange = text.range(of: first), let secondRange = text.range(of: second) else {
            XCTFail("Expected both markers: \(first), \(second)", file: file, line: line)
            return
        }
        XCTAssertLessThan(firstRange.lowerBound, secondRange.lowerBound, file: file, line: line)
    }
}
