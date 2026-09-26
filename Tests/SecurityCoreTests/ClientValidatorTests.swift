import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class ClientValidatorTests: XCTestCase {
    private let policy = TrustedClientPolicy(
        consoleUserID: 501,
        consoleGroupID: 20,
        applicationPath: InstalledPaths.applicationBundle + "/Contents/MacOS/Mac SSH Manager",
        bundleIdentifier: InstalledPaths.menuBundleIdentifier,
        designatedRequirement: "identifier com.serverpc.ssh-control.menu and anchor apple generic",
        cdHash: "ABCDEF0123456789"
    )

    func testExactTrustedClientEvidenceIsAccepted() throws {
        XCTAssertNoThrow(try ClientValidator(policy: policy).validate(.fixture))
    }

    func testWrongIdentityFieldsAreRejected() {
        let variants = [
            ClientIdentityEvidence.fixture.replacing(effectiveUserID: 502),
            ClientIdentityEvidence.fixture.replacing(auditSessionID: 0),
            ClientIdentityEvidence.fixture.replacing(executablePath: "/tmp/copy"),
            ClientIdentityEvidence.fixture.replacing(bundleIdentifier: "other"),
            ClientIdentityEvidence.fixture.replacing(cdHash: "WRONG"),
            ClientIdentityEvidence.fixture.replacing(codeSignatureValid: false)
        ]

        for evidence in variants {
            XCTAssertThrowsError(try ClientValidator(policy: policy).validate(evidence))
        }
    }
}

private extension ClientIdentityEvidence {
    static let fixture = ClientIdentityEvidence(
        effectiveUserID: 501,
        effectiveGroupID: 20,
        auditSessionID: 42,
        executablePath: InstalledPaths.applicationBundle + "/Contents/MacOS/Mac SSH Manager",
        bundleIdentifier: InstalledPaths.menuBundleIdentifier,
        designatedRequirement: "identifier com.serverpc.ssh-control.menu and anchor apple generic",
        cdHash: "ABCDEF0123456789",
        codeSignatureValid: true
    )

    func replacing(
        effectiveUserID: uid_t? = nil,
        auditSessionID: UInt32? = nil,
        executablePath: String? = nil,
        bundleIdentifier: String? = nil,
        cdHash: String? = nil,
        codeSignatureValid: Bool? = nil
    ) -> Self {
        Self(
            effectiveUserID: effectiveUserID ?? self.effectiveUserID,
            effectiveGroupID: effectiveGroupID,
            auditSessionID: auditSessionID ?? self.auditSessionID,
            executablePath: executablePath ?? self.executablePath,
            bundleIdentifier: bundleIdentifier ?? self.bundleIdentifier,
            designatedRequirement: designatedRequirement,
            cdHash: cdHash ?? self.cdHash,
            codeSignatureValid: codeSignatureValid ?? self.codeSignatureValid
        )
    }
}
