import Darwin
import Foundation
import SharedProtocol

public protocol PFInstallationValidating: Sendable {
    func isValid() -> Bool
}

public struct FilePFInstallationValidator: PFInstallationValidating, Sendable {
    public static let maximumConfigurationBytes = 1_048_576
    public static let maximumAnchorBytes = 16 * 1_024

    private let pfConfigurationURL: URL
    private let anchorURL: URL
    private let expectedOwnerUID: uid_t
    private let debug: any DebugLogging

    public init(
        pfConfigurationURL: URL = URL(fileURLWithPath: "/etc/pf.conf"),
        anchorURL: URL = URL(fileURLWithPath: InstalledPaths.pfAnchorFile),
        expectedOwnerUID: uid_t = 0,
        debug: any DebugLogging = NoopDebugLog()
    ) {
        self.pfConfigurationURL = pfConfigurationURL
        self.anchorURL = anchorURL
        self.expectedOwnerUID = expectedOwnerUID
        self.debug = debug
    }

    public func isValid() -> Bool {
        guard let configuration = readRootOwnedFile(
            pfConfigurationURL,
            maximumBytes: Self.maximumConfigurationBytes
        ) else {
            debug.log("isValid: \(pfConfigurationURL.path) unreadable or failed ownership/permission check")
            return false
        }
        guard let anchor = readRootOwnedFile(anchorURL, maximumBytes: Self.maximumAnchorBytes) else {
            debug.log("isValid: \(anchorURL.path) unreadable or failed ownership/permission check")
            return false
        }

        let declaration = "anchor \"\(InstalledPaths.pfAnchorName)\""
        let load = "load anchor \"\(InstalledPaths.pfAnchorName)\" from \"\(InstalledPaths.pfAnchorFile)\""
        let lines = configuration.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let declarationCount = lines.filter { $0 == declaration }.count
        let loadCount = lines.filter { $0 == load }.count
        guard declarationCount == 1, loadCount == 1 else {
            debug.log("isValid: pf.conf anchor linkage count wrong (declaration=\(declarationCount) load=\(loadCount))")
            return false
        }

        guard anchor == PFRuleBuilder().closedRules() else {
            debug.log("isValid: persistent anchor content mismatch, on-disk=\(anchor.debugDescription)")
            return false
        }
        return true
    }

    private func readRootOwnedFile(_ url: URL, maximumBytes: Int) -> String? {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == expectedOwnerUID,
              metadata.st_mode & 0o022 == 0,
              metadata.st_size > 0,
              metadata.st_size <= maximumBytes,
              let data = try? handle.readToEnd(),
              data.count <= maximumBytes
        else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
