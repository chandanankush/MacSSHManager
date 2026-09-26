import Foundation
import Security
import SecurityCore
import SharedProtocol

public protocol ClientIdentityEvidenceProviding: Sendable {
    func evidence(
        for connection: NSXPCConnection,
        codePolicy: InstalledClientCodePolicy
    ) throws -> ClientIdentityEvidence
}

public final class ControllerListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let controller: any AccessControlling
    private let history: any AuditHistoryReading
    private let codePolicy: InstalledClientCodePolicy
    private let consoleIdentity: any ConsoleIdentityProviding
    private let evidenceProvider: any ClientIdentityEvidenceProviding

    public init(
        controller: any AccessControlling,
        history: any AuditHistoryReading = AuditHistoryReader(),
        codePolicy: InstalledClientCodePolicy,
        consoleIdentity: any ConsoleIdentityProviding = SystemConsoleIdentityProvider(),
        evidenceProvider: any ClientIdentityEvidenceProviding = SystemClientIdentityEvidenceProvider()
    ) {
        self.controller = controller
        self.history = history
        self.codePolicy = codePolicy
        self.consoleIdentity = consoleIdentity
        self.evidenceProvider = evidenceProvider
    }

    public func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.setCodeSigningRequirement(codePolicy.designatedRequirement)
        let attribution: AuditAttribution
        do {
            let console = try consoleIdentity.activeConsoleIdentity()
            let policy = TrustedClientPolicy(
                consoleUserID: console.userID,
                consoleGroupID: console.groupID,
                applicationPath: codePolicy.applicationPath,
                bundleIdentifier: codePolicy.bundleIdentifier,
                designatedRequirement: codePolicy.designatedRequirement,
                cdHash: codePolicy.cdHash
            )
            let evidence = try evidenceProvider.evidence(for: connection, codePolicy: codePolicy)
            try ClientValidator(policy: policy).validate(evidence)
            attribution = AuditAttribution(
                userID: evidence.effectiveUserID,
                auditSessionID: evidence.auditSessionID
            )
        } catch {
            connection.invalidate()
            return false
        }

        connection.exportedInterface = NSXPCInterface(with: SSHControlXPCProtocol.self)
        connection.exportedObject = ControllerXPCService(
            controller: controller,
            history: history,
            attribution: attribution
        )
        connection.activate()
        return true
    }
}

public struct SystemClientIdentityEvidenceProvider: ClientIdentityEvidenceProviding, Sendable {
    public init() {}

    public func evidence(
        for connection: NSXPCConnection,
        codePolicy: InstalledClientCodePolicy
    ) throws -> ClientIdentityEvidence {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)]
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess,
              let code
        else {
            throw ControlErrorCode.untrustedClient
        }

        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            codePolicy.designatedRequirement as CFString,
            [],
            &requirement
        ) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(
                code,
                SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
                requirement
              ) == errSecSuccess
        else {
            throw ControlErrorCode.untrustedClient
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode
        else {
            throw ControlErrorCode.untrustedClient
        }
        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
            &signingInformation
        ) == errSecSuccess,
              let information = signingInformation as? [String: Any],
              let identifier = information[kSecCodeInfoIdentifier as String] as? String,
              let executableURL = information[kSecCodeInfoMainExecutable as String] as? URL,
              let hash = information[kSecCodeInfoUnique as String] as? Data
        else {
            throw ControlErrorCode.untrustedClient
        }
        var actualRequirement: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(staticCode, [], &actualRequirement) == errSecSuccess,
              let actualRequirement
        else {
            throw ControlErrorCode.untrustedClient
        }
        var requirementText: CFString?
        guard SecRequirementCopyString(actualRequirement, [], &requirementText) == errSecSuccess,
              let requirementString = requirementText as String?
        else {
            throw ControlErrorCode.untrustedClient
        }

        return ClientIdentityEvidence(
            effectiveUserID: connection.effectiveUserIdentifier,
            effectiveGroupID: connection.effectiveGroupIdentifier,
            auditSessionID: UInt32(bitPattern: connection.auditSessionIdentifier),
            executablePath: executableURL.path,
            bundleIdentifier: identifier,
            designatedRequirement: requirementString,
            cdHash: hash.map { String(format: "%02X", $0) }.joined(),
            codeSignatureValid: true
        )
    }
}
