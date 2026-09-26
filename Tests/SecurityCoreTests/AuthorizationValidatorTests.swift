import Darwin
import Foundation
import Security
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class AuthorizationValidatorTests: XCTestCase {
    private var temporaryDirectories: [URL] = []

    override func tearDownWithError() throws {
        for directory in temporaryDirectories { try? FileManager.default.removeItem(at: directory) }
        temporaryDirectories.removeAll()
    }

    func testAuthorizationCannotBeReplayedByNonceOrForm() throws {
        let checker = RecordingAuthorizationChecker(result: true)
        let validator = OneUseAuthorizationValidator(checker: checker)
        let form = Data(repeating: 7, count: MemoryLayout<AuthorizationExternalForm>.size)

        XCTAssertNoThrow(try validator.consume(form: form, nonce: UUID(), action: .open))
        XCTAssertThrowsError(try validator.consume(form: form, nonce: UUID(), action: .open))

        let secondForm = Data(repeating: 8, count: MemoryLayout<AuthorizationExternalForm>.size)
        let nonce = UUID()
        XCTAssertNoThrow(try validator.consume(form: secondForm, nonce: nonce, action: .open))
        XCTAssertThrowsError(try validator.consume(
            form: Data(repeating: 9, count: MemoryLayout<AuthorizationExternalForm>.size),
            nonce: nonce,
            action: .open
        ))
    }

    func testMalformedFormNeverReachesAuthorizationServices() {
        let checker = RecordingAuthorizationChecker(result: true)
        let validator = OneUseAuthorizationValidator(checker: checker)

        XCTAssertThrowsError(try validator.consume(form: Data([1]), nonce: UUID(), action: .open))
        XCTAssertEqual(checker.calls, [])
    }

    func testAuthorizationUsesOnlyConfiguredRight() throws {
        let checker = RecordingAuthorizationChecker(result: true)
        let validator = OneUseAuthorizationValidator(checker: checker)
        let form = Data(repeating: 1, count: MemoryLayout<AuthorizationExternalForm>.size)

        try validator.consume(form: form, nonce: UUID(), action: .disableLocalConsoleOnly)

        XCTAssertEqual(checker.calls.map(\.rightName), [InstalledPaths.authorizationRight])
        XCTAssertEqual(AuthorizationRightPolicy.requiredDefinition["shared"] as? Bool, false)
        XCTAssertEqual(AuthorizationRightPolicy.requiredDefinition["timeout"] as? Int, 10)
        XCTAssertEqual(AuthorizationRightPolicy.requiredDefinition["group"] as? String, "admin")
        XCTAssertTrue(AuthorizationRightPolicy.matches(AuthorizationRightPolicy.requiredDefinition))
        var weakened = AuthorizationRightPolicy.requiredDefinition
        weakened["shared"] = true
        XCTAssertFalse(AuthorizationRightPolicy.matches(weakened))
    }

    func testLocalConsoleSettingDefaultsOffAndPersistsModeSixHundred() throws {
        let directory = try temporaryDirectory()
        let file = directory.appendingPathComponent("settings.json")
        let store = FileSecuritySettingsStore(fileURL: file, expectedOwnerUID: getuid())

        XCTAssertFalse(try store.load().localConsoleOnly)
        try store.save(SecuritySettings(localConsoleOnly: true))
        XCTAssertTrue(try store.load().localConsoleOnly)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testSettingsStoreRejectsSymlink() throws {
        let directory = try temporaryDirectory()
        let file = directory.appendingPathComponent("settings.json")
        let target = directory.appendingPathComponent("target.json")
        try Data("{}".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        let store = FileSecuritySettingsStore(fileURL: file, expectedOwnerUID: getuid())

        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.save(SecuritySettings(localConsoleOnly: true)))
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serverpc-settings-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        temporaryDirectories.append(directory)
        return directory
    }
}

private final class RecordingAuthorizationChecker: AuthorizationChecking, @unchecked Sendable {
    struct Call: Equatable { let rightName: String }
    private let lock = NSLock()
    private let result: Bool
    private var storedCalls: [Call] = []

    init(result: Bool) { self.result = result }
    var calls: [Call] { lock.withLock { storedCalls } }

    func check(externalForm: Data, rightName: String) -> Bool {
        lock.withLock { storedCalls.append(Call(rightName: rightName)) }
        return result
    }
}
