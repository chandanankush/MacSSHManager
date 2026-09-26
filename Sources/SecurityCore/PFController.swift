import Darwin
import Foundation
import OSLog
import SharedProtocol

public enum FirewallMode: String, Codable, Equatable, Sendable {
    case closed
    case open
}

public struct FirewallHealth: Equatable, Sendable {
    public let pfEnabled: Bool
    public let mode: FirewallMode?

    public init(pfEnabled: Bool, mode: FirewallMode?) {
        self.pfEnabled = pfEnabled
        self.mode = mode
    }
}

/// The exact per-path interface/CIDR fields the PF anchor currently
/// enforces, shaped to match `Lease`'s own flattened fields so callers can
/// compare the two directly. `nil` means CLOSED (no pass rules at all).
public struct EffectiveNetworkRules: Equatable, Sendable {
    public let lanInterfaceName: String?
    public let lanSourceCIDR: String?
    public let tailscaleInterfaceName: String?
    public let tailscaleAddressCIDR: String?

    public init(
        lanInterfaceName: String?,
        lanSourceCIDR: String?,
        tailscaleInterfaceName: String?,
        tailscaleAddressCIDR: String?
    ) {
        self.lanInterfaceName = lanInterfaceName
        self.lanSourceCIDR = lanSourceCIDR
        self.tailscaleInterfaceName = tailscaleInterfaceName
        self.tailscaleAddressCIDR = tailscaleAddressCIDR
    }
}

public protocol FirewallControlling: Sendable {
    func health() async -> FirewallHealth
    func enforceClosed() async throws
    func open(for snapshot: SSHAccessNetworkSnapshot) async throws
    func effectiveMode() async throws -> FirewallMode
    func effectiveNetworkRules() async throws -> EffectiveNetworkRules?
    func startupState() async -> FirewallStartupState
    func recoverAtStartup() async
}

public enum FirewallStartupState: Equatable, Sendable {
    case idle
    case recovering
    case ready
    case failed(ControlErrorCode)
}

public extension FirewallControlling {
    func startupState() async -> FirewallStartupState { .ready }
    func recoverAtStartup() async {}
}

public protocol PFPolicyWriting: Sendable {
    func write(_ rules: String, to policyFile: PolicyFile) throws
}

public actor PFController: FirewallControlling {
    private let runner: any CommandRunning
    private let writer: any PFPolicyWriting
    private let policyFile: PolicyFile
    private let ruleBuilder: PFRuleBuilder
    private let installation: any PFInstallationValidating

    private let debug: any DebugLogging
    private let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "packet-filter")
    private let rulesLogger = Logger(subsystem: "com.serverpc.ssh-control", category: "rules")
    private var recoveryState: FirewallStartupState = .idle
    // A pfctl enable reference remains owned for this helper's lifetime. It is
    // deliberately never released with -X or -d during ordinary shutdown.
    private var enableReference: String?
    private let startupRetryDelays: [UInt64]

    public init(
        runner: any CommandRunning,
        writer: any PFPolicyWriting = FilePFPolicyWriter(),
        policyFile: PolicyFile,
        installation: any PFInstallationValidating = FilePFInstallationValidator(),
        ruleBuilder: PFRuleBuilder = PFRuleBuilder(),
        debug: any DebugLogging = NoopDebugLog(),
        startupRetryDelays: [UInt64] = [0, 1, 2, 4, 8, 15]
    ) {
        self.runner = runner
        self.writer = writer
        self.policyFile = policyFile
        self.installation = installation
        self.ruleBuilder = ruleBuilder
        self.debug = debug
        self.startupRetryDelays = startupRetryDelays.isEmpty ? [0] : startupRetryDelays
    }

    public func startupState() async -> FirewallStartupState { recoveryState }

    public func recoverAtStartup() async {
        guard recoveryState != .recovering else { return }
        recoveryState = .recovering
        var lastError: ControlErrorCode = .pfUnavailable
        for (index, delay) in startupRetryDelays.enumerated() {
            if delay > 0 {
                try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
            }
            guard !Task.isCancelled else { return }
            logger.notice("initialization attempt=\(index + 1, privacy: .public) executable=/sbin/pfctl")
            do {
                try await initializeClosedEnforcement()
                recoveryState = .ready
                logger.notice("initialization verified attempt=\(index + 1, privacy: .public)")
                return
            } catch {
                lastError = error as? ControlErrorCode ?? .pfUnavailable
                logger.error("initialization failed attempt=\(index + 1, privacy: .public) reason=\(lastError.rawValue, privacy: .public)")
            }
        }
        recoveryState = .failed(lastError)
    }

    private func initializeClosedEnforcement() async throws {
        guard installation.isValid() else { throw ControlErrorCode.permissionFailure }
        let initialStatus = try await runner.run(.pfStatus)
        guard commandSucceeded(initialStatus) else {
            logFailure("status", result: initialStatus)
            throw ControlErrorCode.permissionFailure
        }
        if !isPFEnabled(initialStatus) {
            let enable = try await runner.run(.pfEnable)
            guard commandSucceeded(enable) else {
                logFailure("enable", result: enable)
                throw ControlErrorCode.pfEnableFailed
            }
            enableReference = parseEnableReference(enable.standardOutput)
            let verified = try await runner.run(.pfStatus)
            guard commandSucceeded(verified), isPFEnabled(verified) else {
                logFailure("enable-verification", result: verified)
                throw ControlErrorCode.pfEnableUnverified
            }
        }
        _ = try await installAndVerify(ruleBuilder.closedRules())
        let verifiedHealth = await health()
        guard verifiedHealth.pfEnabled, verifiedHealth.mode == .closed else {
            throw ControlErrorCode.pfAnchorValidationFailed
        }
    }

    public func health() async -> FirewallHealth {
        guard installation.isValid() else {
            debug.log("health(): installation.isValid() == false")
            return FirewallHealth(pfEnabled: false, mode: nil)
        }
        do {
            let status = try await runner.run(.pfStatus)
            let text = String(decoding: status.standardOutput, as: UTF8.self).lowercased()
            guard commandSucceeded(status), text.contains("status: enabled") else {
                debug.log("health(): pfStatus status=\(status.terminationStatus) output=\(text.debugDescription)")
                return FirewallHealth(pfEnabled: false, mode: nil)
            }
            return FirewallHealth(pfEnabled: true, mode: try await effectiveMode())
        } catch {
            debug.log("health(): threw \(error)")
            return FirewallHealth(pfEnabled: false, mode: nil)
        }
    }

    public func enforceClosed() async throws {
        try await initializeClosedEnforcement()
    }

    public func open(for snapshot: SSHAccessNetworkSnapshot) async throws {
        guard installation.isValid() else {
            debug.log("open(for:): installation.isValid() == false")
            throw ControlErrorCode.pfUnavailable
        }
        do {
            let rules = try ruleBuilder.openRules(snapshot)
            debug.log("open(for:) scope=\(snapshot.scope) lan=\(describe(snapshot.lan)) tailscale=\(describe(snapshot.tailscale)) rules=\(rules.debugDescription)")
            let confirmed = try await installAndVerify(rules)
            // Independently compare what PF actually now enforces against the
            // caller's original typed snapshot -- not merely against the string
            // this method itself asked PFRuleBuilder to write. This is what
            // catches a rule-generation defect, not just write/read-back drift.
            guard case .open(let lan, let tailscale) = confirmed,
                  lan?.interfaceName == snapshot.lan?.interfaceName,
                  lan?.sourceCIDR == snapshot.lan?.sourceCIDR,
                  tailscale?.interfaceName == snapshot.tailscale?.interfaceName,
                  tailscale?.destinationCIDR == snapshot.tailscale?.addressCIDR
            else {
                debug.log("open(for:) post-verification mismatch, confirmed=\(confirmed)")
                throw ControlErrorCode.pfUnavailable
            }
            debug.log("open(for:) succeeded")
        } catch {
            debug.log("open(for:) failed: \(error) -- restoring CLOSED")
            try? await enforceClosed()
            throw ControlErrorCode.pfUnavailable
        }
    }

    private func describe(_ lan: LANSnapshot?) -> String {
        lan.map { "\($0)" } ?? "nil"
    }

    private func describe(_ tailscale: TailscaleSnapshot?) -> String {
        tailscale.map { "\($0)" } ?? "nil"
    }

    public func effectiveMode() async throws -> FirewallMode {
        switch try await readEffectiveSemantics() {
        case .closed: return .closed
        case .open: return .open
        }
    }

    public func effectiveNetworkRules() async throws -> EffectiveNetworkRules? {
        switch try await readEffectiveSemantics() {
        case .closed:
            return nil
        case .open(let lan, let tailscale):
            return EffectiveNetworkRules(
                lanInterfaceName: lan?.interfaceName,
                lanSourceCIDR: lan?.sourceCIDR,
                tailscaleInterfaceName: tailscale?.interfaceName,
                tailscaleAddressCIDR: tailscale?.destinationCIDR
            )
        }
    }

    private func readEffectiveSemantics() async throws -> RuleSemantics {
        let result = try await runner.run(.pfReadAnchor)
        guard commandSucceeded(result) else { throw ControlErrorCode.pfUnavailable }
        guard let semantics = parsedRules(String(decoding: result.standardOutput, as: UTF8.self)) else {
            throw ControlErrorCode.pfUnavailable
        }
        return semantics
    }

    @discardableResult
    private func installAndVerify(_ rules: String) async throws -> RuleSemantics {
        try writer.write(rules, to: policyFile)
        let syntax = try await runner.run(.pfSyntax(policyFile))
        guard commandSucceeded(syntax) else {
            logFailure("rules-syntax", result: syntax)
            throw ControlErrorCode.pfRulesLoadFailed
        }
        let load = try await runner.run(.pfLoad(policyFile))
        guard commandSucceeded(load) else {
            logFailure("rules-load", result: load)
            throw ControlErrorCode.pfRulesLoadFailed
        }
        rulesLogger.notice("application anchor load completed status=\(load.terminationStatus, privacy: .public)")
        let readback = try await runner.run(.pfReadAnchor)
        let readbackText = String(decoding: readback.standardOutput, as: UTF8.self)
        let expected = parsedRules(rules)
        let actual = parsedRules(readbackText)
        guard commandSucceeded(readback),
              let expected,
              let actual,
              actual == expected
        else {
            debug.log("""
                installAndVerify mismatch status=\(readback.terminationStatus) \
                written=\(rules.debugDescription) readback=\(readbackText.debugDescription) \
                expectedParsed=\(expected.map { "\($0)" } ?? "nil") actualParsed=\(actual.map { "\($0)" } ?? "nil")
                """)
            throw ControlErrorCode.pfAnchorValidationFailed
        }
        return actual
    }

    private func isPFEnabled(_ result: BoundedCommandResult) -> Bool {
        String(decoding: result.standardOutput, as: UTF8.self)
            .lowercased().contains("status: enabled")
    }

    private func parseEnableReference(_ data: Data) -> String? {
        let output = String(decoding: data, as: UTF8.self)
        guard let range = output.range(of: #"(?i)token\s*:\s*([0-9]+)"#, options: .regularExpression) else {
            return nil
        }
        return String(output[range]).split(separator: ":").last.map { String($0).trimmingCharacters(in: .whitespaces) }
    }

    private func logFailure(_ operation: String, result: BoundedCommandResult) {
        let stderr = String(decoding: result.standardError, as: UTF8.self).prefix(500)
        logger.error("operation=\(operation, privacy: .public) status=\(result.terminationStatus, privacy: .public) stderr=\(stderr, privacy: .public)")
    }

    private func commandSucceeded(_ result: BoundedCommandResult) -> Bool {
        result.terminationStatus == 0 && !result.outputWasTruncated
    }

    private struct PassRuleDescriptor: Equatable {
        let interfaceName: String
        let sourceCIDR: String
        /// `nil` means the rule's destination is `any`.
        let destinationCIDR: String?
    }

    private enum RuleSemantics: Equatable {
        case closed
        case open(lan: PassRuleDescriptor?, tailscale: PassRuleDescriptor?)
    }

    /// Accepts exactly: the fixed CLOSED line alone, or zero-to-two pass
    /// rules (LAN then Tailscale, in that order) followed by the fixed
    /// CLOSED line. Each pass rule is independently classified as the LAN
    /// slot or the Tailscale slot by its own shape -- never by position
    /// alone -- so a duplicated, reordered, or unrecognizable line fails to
    /// parse and the whole anchor is rejected as ambiguous.
    private func parsedRules(_ rules: String) -> RuleSemantics? {
        let lines = rules
            .split(separator: "\n")
            .map { $0.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init) }
            .filter { !$0.isEmpty }
        guard let last = lines.last, isClosedRule(last) else { return nil }
        let passLines = lines.dropLast()
        guard (0...2).contains(passLines.count) else { return nil }
        guard !passLines.isEmpty else { return .closed }

        var lan: PassRuleDescriptor?
        var tailscale: PassRuleDescriptor?
        for line in passLines {
            guard let descriptor = parsePassRule(line) else { return nil }
            if isLANDescriptor(descriptor) {
                guard lan == nil, tailscale == nil else { return nil }
                lan = descriptor
            } else if isTailscaleDescriptor(descriptor) {
                guard tailscale == nil else { return nil }
                tailscale = descriptor
            } else {
                return nil
            }
        }
        return .open(lan: lan, tailscale: tailscale)
    }

    private func isLANDescriptor(_ descriptor: PassRuleDescriptor) -> Bool {
        descriptor.destinationCIDR == nil &&
            descriptor.sourceCIDR != PFRuleBuilder.tailscaleSourceCIDR &&
            PhysicalLANResolver.isSafeInterfaceName(descriptor.interfaceName) &&
            !PhysicalLANResolver.isKnownVirtualName(descriptor.interfaceName) &&
            IPv4Network(cidr: descriptor.sourceCIDR) != nil
    }

    private func isTailscaleDescriptor(_ descriptor: PassRuleDescriptor) -> Bool {
        descriptor.sourceCIDR == PFRuleBuilder.tailscaleSourceCIDR &&
            TailscaleRouteResolver.isTailscaleInterfaceName(descriptor.interfaceName) &&
            (descriptor.destinationCIDR.flatMap { IPv4Network(cidr: $0) }?.prefixLength == 32)
    }

    private func isClosedRule(_ original: [String]) -> Bool {
        var fields = original
        if let equalsIndex = fields.firstIndex(of: "="), equalsIndex > 0, fields[equalsIndex - 1] == "port" {
            fields.remove(at: equalsIndex)
        }
        return fields == ["block", "drop", "in", "quick", "proto", "tcp", "from", "any", "to", "any", "port", "22"]
    }

    private func parsePassRule(_ original: [String]) -> PassRuleDescriptor? {
        var fields = original
        if let equalsIndex = fields.firstIndex(of: "="), equalsIndex > 0, fields[equalsIndex - 1] == "port" {
            fields.remove(at: equalsIndex)
        }
        guard fields.count == 18,
              Array(fields[0...3]) == ["pass", "in", "quick", "on"],
              Array(fields[5...8]) == ["inet", "proto", "tcp", "from"],
              fields[10] == "to",
              Array(fields[12...17]) == ["port", "22", "flags", "S/SA", "keep", "state"],
              PhysicalLANResolver.isSafeInterfaceName(fields[4]),
              let sourceCIDR = normalizedCIDR(fields[9])
        else {
            return nil
        }
        let destinationField = fields[11]
        let destinationCIDR: String?
        if destinationField == "any" {
            destinationCIDR = nil
        } else if let normalized = normalizedCIDR(destinationField) {
            destinationCIDR = normalized
        } else {
            return nil
        }
        return PassRuleDescriptor(interfaceName: fields[4], sourceCIDR: sourceCIDR, destinationCIDR: destinationCIDR)
    }

    /// Accepts an explicit `address/prefix` CIDR, and separately a bare
    /// `address` with no prefix -- `pfctl -sr` renders a `/32` destination as
    /// a bare host address, without the mask, when it echoes a loaded rule
    /// back. Both forms are normalized to the same canonical `address/32` (or
    /// wider-prefix) string so a written CIDR and its pfctl-rendered
    /// read-back compare equal.
    private func normalizedCIDR(_ field: String) -> String? {
        if let network = IPv4Network(cidr: field) { return network.cidr }
        if let host = IPv4Network(address: field, netmask: "255.255.255.255") { return host.cidr }
        return nil
    }
}

public final class FilePFPolicyWriter: PFPolicyWriting, @unchecked Sendable {
    private let expectedOwnerUID: uid_t
    private let lock = NSLock()

    public init(expectedOwnerUID: uid_t = 0) {
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func write(_ rules: String, to policyFile: PolicyFile) throws {
        guard let data = rules.data(using: .utf8), data.count <= 16 * 1_024 else {
            throw ControlErrorCode.pfUnavailable
        }
        try lock.withLock {
            try ensureStateDirectory(policyFile: policyFile)
            try writeAtomically(data, policyFile: policyFile)
        }
    }

    private func ensureStateDirectory(policyFile: PolicyFile) throws {
        let directory = URL(fileURLWithPath: policyFile.path).deletingLastPathComponent().path
        if mkdir(directory, 0o700) != 0, errno != EEXIST {
            throw ControlErrorCode.pfUnavailable
        }
        var metadata = stat()
        guard lstat(directory, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_uid == expectedOwnerUID,
              chmod(directory, 0o700) == 0
        else {
            throw ControlErrorCode.pfUnavailable
        }
    }

    private func writeAtomically(_ data: Data, policyFile: PolicyFile) throws {
        let directory = URL(fileURLWithPath: policyFile.path).deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".pf-policy-\(UUID().uuidString).tmp").path
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw ControlErrorCode.pfUnavailable }
        var removeTemporary = true
        defer {
            close(descriptor)
            if removeTemporary { unlink(temporary) }
        }
        guard fchmod(descriptor, 0o600) == 0,
              fchown(descriptor, expectedOwnerUID, gid_t.max) == 0
        else {
            throw ControlErrorCode.pfUnavailable
        }
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(descriptor, base.advanced(by: offset), buffer.count - offset)
                guard written > 0 else { throw ControlErrorCode.pfUnavailable }
                offset += written
            }
        }
        guard fsync(descriptor) == 0,
              rename(temporary, policyFile.path) == 0
        else {
            throw ControlErrorCode.pfUnavailable
        }
        removeTemporary = false
    }
}
