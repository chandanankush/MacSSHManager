import Foundation
import SharedProtocol

public struct SSHPolicyEvaluation: Equatable, Sendable {
    public let isSafe: Bool
    public let reason: ControlErrorCode?

    public init(isSafe: Bool, reason: ControlErrorCode?) {
        self.isSafe = isSafe
        self.reason = reason
    }
}

public protocol SSHPolicyValidating: Sendable {
    func validate() async throws -> SSHPolicyEvaluation
}

public struct SSHPolicyValidator: SSHPolicyValidating, Sendable {
    private static let requiredValues = [
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "pubkeyauthentication": "yes",
        "permitrootlogin": "no",
        "port": "22"
    ]

    private let runner: any CommandRunning

    public init(runner: any CommandRunning) {
        self.runner = runner
    }

    public func validate() async throws -> SSHPolicyEvaluation {
        let result = try await runner.run(.sshdEffectiveConfiguration)
        guard result.terminationStatus == 0, !result.outputWasTruncated else {
            return unsafe
        }

        var values: [String: String] = [:]
        for line in String(decoding: result.standardOutput, as: UTF8.self).split(separator: "\n") {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 2 else { continue }
            let key = fields[0].lowercased()
            guard Self.requiredValues[key] != nil else { continue }
            guard values[key] == nil else { return unsafe }
            values[key] = fields.dropFirst().joined(separator: " ").lowercased()
        }

        guard values == Self.requiredValues else { return unsafe }
        return SSHPolicyEvaluation(isSafe: true, reason: nil)
    }

    private var unsafe: SSHPolicyEvaluation {
        SSHPolicyEvaluation(isSafe: false, reason: .unsafeSSHPolicy)
    }
}
