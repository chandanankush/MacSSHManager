import Darwin
import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class LeaseStoreTests: XCTestCase {
    private var temporaryDirectories: [URL] = []

    override func tearDownWithError() throws {
        for directory in temporaryDirectories {
            try? FileManager.default.removeItem(at: directory)
        }
        temporaryDirectories.removeAll()
    }

    func testExpiredLeaseIsReportedAsExpired() throws {
        let clock = FakeContinuousClock(bootSessionID: "boot-a", uptimeIncludingSleep: 200)
        let store = try makeStore(clock: clock)
        try store.save(makeLease(bootID: "boot-a", deadline: 199))

        XCTAssertEqual(try store.currentState(), .expired(makeLease(bootID: "boot-a", deadline: 199)))
    }

    func testPreviousBootLeaseIsInvalid() throws {
        let store = try makeStore(
            clock: FakeContinuousClock(bootSessionID: "boot-b", uptimeIncludingSleep: 10)
        )
        try store.save(makeLease(bootID: "boot-a", deadline: 100))

        XCTAssertEqual(try store.currentState(), .invalid)
    }

    func testLeaseWriteUsesRestrictivePermissions() throws {
        let store = try makeStore(
            clock: FakeContinuousClock(bootSessionID: "boot-a", uptimeIncludingSleep: 10)
        )
        try store.save(makeLease(bootID: "boot-a", deadline: 100))

        let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testMalformedAndOversizedLeaseFilesAreInvalid() throws {
        let store = try makeStore(
            clock: FakeContinuousClock(bootSessionID: "boot-a", uptimeIncludingSleep: 10)
        )
        try Data(repeating: 0x41, count: FileLeaseStore.maximumLeaseBytes + 1)
            .write(to: store.fileURL)

        XCTAssertEqual(try store.currentState(), .invalid)
    }

    func testSymlinkLeaseIsRejected() throws {
        let store = try makeStore(
            clock: FakeContinuousClock(bootSessionID: "boot-a", uptimeIncludingSleep: 10)
        )
        let target = store.fileURL.deletingLastPathComponent().appendingPathComponent("target")
        try Data("{}".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: target)

        XCTAssertEqual(try store.currentState(), .invalid)
    }

    private func makeStore(clock: FakeContinuousClock) throws -> FileLeaseStore {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serverpc-lease-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        temporaryDirectories.append(directory)
        return FileLeaseStore(
            fileURL: directory.appendingPathComponent("lease.json"),
            clock: clock,
            expectedOwnerUID: getuid()
        )
    }

    private func makeLease(bootID: String, deadline: TimeInterval) -> Lease {
        Lease(
            requestID: UUID(uuidString: "75948C79-1EF8-4497-A048-33C307893B2A")!,
            duration: .minutes30,
            deadlineUptime: deadline,
            openedAt: Date(timeIntervalSince1970: 1_000),
            expiresAt: Date(timeIntervalSince1970: 2_800),
            bootSessionID: bootID,
            scope: .lan,
            lanInterfaceName: "en0",
            lanSourceCIDR: "192.168.1.0/24",
            tailscaleInterfaceName: nil,
            tailscaleAddressCIDR: nil,
            localConsoleOnly: false
        )
    }
}

private struct FakeContinuousClock: ContinuousTimeProviding {
    let bootSessionID: String
    let uptimeIncludingSleep: TimeInterval
    let wallNow = Date(timeIntervalSince1970: 1_000)
}
