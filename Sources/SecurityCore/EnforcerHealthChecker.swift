import SharedProtocol

public protocol EnforcerHealthChecking: Sendable {
    func isHealthy() async -> Bool
}

public struct LaunchdEnforcerHealthChecker: EnforcerHealthChecking, Sendable {
    private let runner: any CommandRunning

    public init(runner: any CommandRunning) {
        self.runner = runner
    }

    public func isHealthy() async -> Bool {
        guard let result = try? await runner.run(.enforcerStatus) else { return false }
        return result.terminationStatus == 0 && !result.outputWasTruncated
    }
}
