import Darwin
import Foundation
import SharedProtocol

public enum RemoteControlEnforcement: String, Equatable, Sendable {
    case none
    case auditOnly
    case denyOpen
}

public struct RemoteControlDetection: Equatable, Sendable {
    public let detectedIdentifiers: [String]
    public let enforcement: RemoteControlEnforcement

    public init(detectedIdentifiers: [String], enforcement: RemoteControlEnforcement) {
        self.detectedIdentifiers = detectedIdentifiers
        self.enforcement = enforcement
    }
}

public protocol RemoteControlDetecting: Sendable {
    func detect(localConsoleOnly: Bool) async throws -> RemoteControlDetection
}

public protocol RemoteProcessSourcing: Sendable {
    func runningExecutablePaths() -> [String]
}

public struct RemoteControlDetector: RemoteControlDetecting, Sendable {
    public static let reviewedExecutablePaths = [
        "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk",
        "/Applications/RustDesk.app/Contents/MacOS/RustDesk",
        "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer",
        "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent"
    ]

    private let runner: any CommandRunning
    private let processes: any RemoteProcessSourcing

    public init(
        runner: any CommandRunning,
        processes: any RemoteProcessSourcing = SystemRemoteProcessSource()
    ) {
        self.runner = runner
        self.processes = processes
    }

    public func detect(localConsoleOnly: Bool) async throws -> RemoteControlDetection {
        var detected = Set<String>()
        for service in KnownLaunchService.allCases {
            let result = try await runner.run(.launchctlPrint(service))
            guard !result.outputWasTruncated else { throw ControlErrorCode.remoteControlActive }
            if result.terminationStatus == 0 {
                guard let isRunning = Self.isRunningLaunchService(result.standardOutput) else {
                    throw ControlErrorCode.remoteControlActive
                }
                if isRunning {
                    detected.insert(service.rawValue)
                }
            } else if result.terminationStatus != 113 {
                throw ControlErrorCode.remoteControlActive
            }
        }

        let reviewed = Set(Self.reviewedExecutablePaths)
        for path in processes.runningExecutablePaths() where reviewed.contains(path) {
            detected.insert(path)
        }

        let identifiers = detected.sorted()
        let enforcement: RemoteControlEnforcement
        if identifiers.isEmpty {
            enforcement = .none
        } else {
            enforcement = localConsoleOnly ? .denyOpen : .auditOnly
        }
        return RemoteControlDetection(detectedIdentifiers: identifiers, enforcement: enforcement)
    }

    private static func isRunningLaunchService(_ output: Data) -> Bool? {
        let lines = String(decoding: output, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        if lines.contains("state = running") { return true }
        if lines.contains("state = not running") { return false }
        return nil
    }
}

public struct SystemRemoteProcessSource: RemoteProcessSourcing, Sendable {
    private static let maximumProcesses = 65_536

    public init() {}

    public func runningExecutablePaths() -> [String] {
        var capacity = 4_096
        while capacity <= Self.maximumProcesses {
            var pids = [pid_t](repeating: 0, count: capacity)
            let count = pids.withUnsafeMutableBytes { buffer in
                proc_listallpids(buffer.baseAddress, Int32(buffer.count))
            }
            guard count >= 0 else { return [] }
            if count < capacity {
                return Set(pids.prefix(Int(count)).compactMap(executablePath)).sorted()
            }
            capacity *= 2
        }
        return []
    }

    private func executablePath(pid: pid_t) -> String? {
        guard pid > 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
