import Darwin
import Foundation
import SharedProtocol

public enum FixedCommandError: Error, Equatable, Sendable {
    case invalidPolicyPath
    case launchFailed
    case timedOut
}

public struct PolicyFile: Equatable, Sendable {
    public let path: String

    public init(path: String) throws {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        let stateRoot = URL(fileURLWithPath: InstalledPaths.stateRoot).standardizedFileURL.path
        let basename = URL(fileURLWithPath: standardized).lastPathComponent
        guard path.hasPrefix("/"),
              standardized.hasPrefix(stateRoot + "/"),
              !standardized.hasSuffix("/"),
              !standardized.contains("/../"),
              !basename.isEmpty,
              basename.utf8.allSatisfy({ byte in
                  (48...57).contains(byte) || (65...90).contains(byte) ||
                      (97...122).contains(byte) || byte == 45 || byte == 46
              })
        else {
            throw FixedCommandError.invalidPolicyPath
        }
        self.path = standardized
    }
}

public enum KnownLaunchService: String, CaseIterable, Sendable {
    case screenSharing = "com.apple.screensharing"
    case remoteManagement = "com.apple.RemoteDesktop.PrivilegeProxy"
}

public struct CommandSpecification: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }
}

public enum FixedCommand: Equatable, Sendable {
    case pfSyntax(PolicyFile)
    case pfLoad(PolicyFile)
    case pfReadAnchor
    case pfStatus
    case pfEnable
    case sshdEffectiveConfiguration
    case lsofEstablishedSSH
    case launchctlPrint(KnownLaunchService)
    case enforcerStatus

    public func specification() throws -> CommandSpecification {
        switch self {
        case .pfSyntax(let policy):
            CommandSpecification(
                executable: "/sbin/pfctl",
                arguments: ["-n", "-a", InstalledPaths.pfAnchorName, "-f", policy.path]
            )
        case .pfLoad(let policy):
            CommandSpecification(
                executable: "/sbin/pfctl",
                arguments: ["-a", InstalledPaths.pfAnchorName, "-f", policy.path]
            )
        case .pfReadAnchor:
            CommandSpecification(
                executable: "/sbin/pfctl",
                arguments: ["-a", InstalledPaths.pfAnchorName, "-sr"]
            )
        case .pfStatus:
            CommandSpecification(executable: "/sbin/pfctl", arguments: ["-s", "info"])
        case .pfEnable:
            CommandSpecification(executable: "/sbin/pfctl", arguments: ["-E"])
        case .sshdEffectiveConfiguration:
            CommandSpecification(executable: "/usr/sbin/sshd", arguments: ["-T"])
        case .lsofEstablishedSSH:
            CommandSpecification(
                executable: "/usr/sbin/lsof",
                arguments: ["-nP", "-a", "-iTCP:22", "-sTCP:ESTABLISHED", "-Fpcnt"]
            )
        case .launchctlPrint(let service):
            CommandSpecification(
                executable: "/bin/launchctl",
                arguments: ["print", "system/\(service.rawValue)"]
            )
        case .enforcerStatus:
            CommandSpecification(
                executable: "/bin/launchctl",
                arguments: ["print", "system/\(InstalledPaths.enforcerBundleIdentifier)"]
            )
        }
    }
}

public struct BoundedCommandResult: Equatable, Sendable {
    public let terminationStatus: Int32
    public let standardOutput: Data
    public let standardError: Data
    public let outputWasTruncated: Bool

    public init(
        terminationStatus: Int32,
        standardOutput: Data,
        standardError: Data,
        outputWasTruncated: Bool
    ) {
        self.terminationStatus = terminationStatus
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.outputWasTruncated = outputWasTruncated
    }
}

public protocol CommandRunning: Sendable {
    func run(_ command: FixedCommand) async throws -> BoundedCommandResult
}

public final class SystemFixedCommandRunner: CommandRunning, @unchecked Sendable {
    public static let maximumOutputBytes = 64 * 1_024
    public static let timeout: TimeInterval = 10
    public static let fixedEnvironment = [
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"
    ]

    public init() {}

    public func run(_ command: FixedCommand) async throws -> BoundedCommandResult {
        let specification = try command.specification()
        let standardOutput = try AnonymousTemporaryFile()
        let standardError = try AnonymousTemporaryFile()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: specification.executable)
        process.arguments = specification.arguments
        process.environment = Self.fixedEnvironment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = standardOutput.handle
        process.standardError = standardError.handle

        do {
            try process.run()
        } catch {
            throw FixedCommandError.launchFailed
        }

        let timeoutState = ProcessTimeoutState(process: process)
        let timeoutItem = DispatchWorkItem { timeoutState.expire() }
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + Self.timeout,
            execute: timeoutItem
        )
        process.waitUntilExit()
        timeoutItem.cancel()

        if timeoutState.didExpire {
            throw FixedCommandError.timedOut
        }

        let output = try standardOutput.read(maximumBytes: Self.maximumOutputBytes)
        let errors = try standardError.read(maximumBytes: Self.maximumOutputBytes)
        return BoundedCommandResult(
            terminationStatus: process.terminationStatus,
            standardOutput: output.data,
            standardError: errors.data,
            outputWasTruncated: output.wasTruncated || errors.wasTruncated
        )
    }
}

private final class ProcessTimeoutState: @unchecked Sendable {
    private let lock = NSLock()
    private let process: Process
    private var expired = false

    init(process: Process) {
        self.process = process
    }

    var didExpire: Bool {
        lock.withLock { expired }
    }

    func expire() {
        lock.withLock {
            guard process.isRunning else { return }
            expired = true
            kill(process.processIdentifier, SIGKILL)
        }
    }
}

private final class AnonymousTemporaryFile {
    let handle: FileHandle

    init() throws {
        var template = Array("/private/var/tmp/serverpc-ssh-control.XXXXXX".utf8CString)
        let descriptor = template.withUnsafeMutableBufferPointer { buffer in
            mkstemp(buffer.baseAddress!)
        }
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let path = String(
            decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
        guard fchmod(descriptor, 0o600) == 0 else {
            let savedError = errno
            close(descriptor)
            unlink(path)
            throw POSIXError(POSIXErrorCode(rawValue: savedError) ?? .EIO)
        }
        unlink(path)
        handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    func read(maximumBytes: Int) throws -> (data: Data, wasTruncated: Bool) {
        try handle.seek(toOffset: 0)
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        return (Data(data.prefix(maximumBytes)), data.count > maximumBytes)
    }
}
