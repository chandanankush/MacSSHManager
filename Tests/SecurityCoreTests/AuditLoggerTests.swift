import Darwin
import Foundation
import XCTest
@testable import SecurityCore
@testable import SharedProtocol

final class AuditLoggerTests: XCTestCase {
    private var temporaryDirectories: [URL] = []

    override func tearDownWithError() throws {
        for directory in temporaryDirectories {
            try? FileManager.default.removeItem(at: directory)
        }
        temporaryDirectories.removeAll()
    }

    func testAuditEncodingContainsOnlyAllowlistedFields() throws {
        let event = AuditEvent(
            kind: .openFailed,
            timestamp: Date(timeIntervalSince1970: 1_000),
            requestID: UUID(uuidString: "75948C79-1EF8-4497-A048-33C307893B2A"),
            reason: .pfUnavailable,
            duration: .minutes30,
            userID: 501,
            auditSessionID: 7,
            interfaceName: "en0",
            sourceCIDR: "192.168.1.0/24",
            outcome: .failure
        )

        let line = try AuditEncoder().encodeLine(event)

        XCTAssertFalse(line.contains("password"))
        XCTAssertFalse(line.contains("authorizationExternalForm"))
        XCTAssertFalse(line.contains("command"))
        XCTAssertLessThan(line.utf8.count, AuditEncoder.maximumEventBytes)
        XCTAssertTrue(line.hasSuffix("\n"))
    }

    func testFileWriterCreatesModeSixHundredLog() throws {
        let writer = try makeWriter(maximumBytes: 1_024)
        try writer.append(try AuditEncoder().encodeLine(.fixture))

        let attributes = try FileManager.default.attributesOfItem(atPath: writer.fileURL.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testFileWriterRotatesWithinBound() throws {
        let writer = try makeWriter(maximumBytes: 160, retainedFiles: 2)
        let line = try AuditEncoder().encodeLine(.fixture)
        for _ in 0..<8 { try writer.append(line) }

        XCTAssertTrue(FileManager.default.fileExists(atPath: writer.fileURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: writer.fileURL.path + ".1"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: writer.fileURL.path + ".3"))
    }

    func testSymlinkAuditFileIsRejected() throws {
        let writer = try makeWriter(maximumBytes: 1_024)
        let target = writer.fileURL.deletingLastPathComponent().appendingPathComponent("target")
        try Data().write(to: target)
        try FileManager.default.createSymbolicLink(at: writer.fileURL, withDestinationURL: target)

        XCTAssertThrowsError(try writer.append(try AuditEncoder().encodeLine(.fixture)))
    }

    func testHistoryReturnsNewestEntriesWithinThirtyDays() throws {
        let writer = try makeWriter(maximumBytes: 4_096)
        try writer.append(try AuditEncoder().encodeLine(.fixture))
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 1_000 + 30 * 24 * 60 * 60) },
            expectedOwnerUID: getuid()
        )

        XCTAssertEqual(try reader.recent(query: nil).entries.map(\.kind), [.opened])
    }

    func testHistorySearchFiltersAcrossAllowlistedFields() throws {
        let writer = try makeWriter(maximumBytes: 4_096)
        try writer.append(try AuditEncoder().encodeLine(.session(user: "deploy", source: "192.168.8.20")))
        try writer.append(try AuditEncoder().encodeLine(.session(user: "admin", source: "192.168.8.21")))
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid()
        )

        let entries = try reader.recent(query: "DEPLOY").entries

        XCTAssertEqual(entries.map(\.sshUser), ["deploy"])
    }

    func testHistoryReadsActiveFileAndExactRotations() throws {
        let writer = try makeWriter(maximumBytes: 4_096)
        try writer.append(try AuditEncoder().encodeLine(.session(user: "active", source: "192.168.8.20")))
        let fifthRotation = URL(fileURLWithPath: writer.fileURL.path + ".5")
        try Data(try AuditEncoder().encodeLine(.session(user: "rotated", source: "192.168.8.21")).utf8)
            .write(to: fifthRotation)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fifthRotation.path)
        let reader = AuditHistoryReader(
            auditFileURL: writer.fileURL,
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid()
        )

        XCTAssertEqual(Set(try reader.recent(query: nil).entries.compactMap(\.sshUser)), ["active", "rotated"])
    }

    func testHistoryRejectsSymlinkInsteadOfFollowingIt() throws {
        let writer = try makeWriter(maximumBytes: 4_096)
        let target = writer.fileURL.deletingLastPathComponent().appendingPathComponent("target.jsonl")
        try Data(try AuditEncoder().encodeLine(.fixture).utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: writer.fileURL, withDestinationURL: target)
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid()
        )

        XCTAssertThrowsError(try reader.recent(query: nil))
    }

    func testHistorySkipsMalformedAndExpiredRecordsAndSortsNewestFirst() throws {
        let writer = try makeWriter(maximumBytes: 16_384)
        try writer.append("not-json\n")
        try writer.append(try AuditEncoder().encodeLine(.session(
            user: "expired",
            source: "192.168.8.19",
            timestamp: Date(timeIntervalSince1970: 1_000)
        )))
        try writer.append(try AuditEncoder().encodeLine(.session(
            user: "newer",
            source: "192.168.8.20",
            timestamp: Date(timeIntervalSince1970: 4_000_000)
        )))
        try writer.append(try AuditEncoder().encodeLine(.session(
            user: "older",
            source: "192.168.8.21",
            timestamp: Date(timeIntervalSince1970: 3_999_000)
        )))
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 4_000_100) },
            expectedOwnerUID: getuid()
        )

        XCTAssertEqual(try reader.recent(query: nil).entries.compactMap(\.sshUser), ["newer", "older"])
    }

    func testHistoryCapsNewestResultsAndRejectsOversizedQuery() throws {
        let writer = try makeWriter(maximumBytes: 512 * 1_024)
        for index in 0..<300 {
            try writer.append(try AuditEncoder().encodeLine(.session(
                user: "user-\(index)",
                source: "192.168.8.20",
                timestamp: Date(timeIntervalSince1970: TimeInterval(10_000 + index))
            )))
        }
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 20_000) },
            expectedOwnerUID: getuid()
        )

        let entries = try reader.recent(query: nil).entries
        XCTAssertEqual(entries.count, 250)
        XCTAssertEqual(entries.first?.sshUser, "user-299")
        XCTAssertThrowsError(try reader.recent(query: String(repeating: "a", count: 129)))
    }

    func testHistoryRejectsWrongModeAndWrongOwnerExpectation() throws {
        let writer = try makeWriter(maximumBytes: 4_096)
        try writer.append(try AuditEncoder().encodeLine(.fixture))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: writer.fileURL.path)
        let wrongMode = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid()
        )
        XCTAssertThrowsError(try wrongMode.recent(query: nil))

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: writer.fileURL.path)
        let wrongOwner = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid() &+ 1
        )
        XCTAssertThrowsError(try wrongOwner.recent(query: nil))
    }

    func testHistorySkipsOverlongRecordWithoutLosingFollowingValidRecord() throws {
        let writer = try makeWriter(maximumBytes: 16_384)
        let validLine = try AuditEncoder().encodeLine(.fixture)
        let data = Data((String(repeating: "x", count: AuditEncoder.maximumEventBytes + 1) + "\n" + validLine).utf8)
        try data.write(to: writer.fileURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: writer.fileURL.path)
        let reader = AuditHistoryReader(
            fileURLs: [writer.fileURL],
            now: { Date(timeIntervalSince1970: 2_000) },
            expectedOwnerUID: getuid()
        )

        XCTAssertEqual(try reader.recent(query: nil).entries.count, 1)
    }

    func testAuditEncodingAllowsSSHSessionIdentityFieldsOnly() throws {
        let event = AuditEvent(
            kind: .sshConnected,
            timestamp: Date(timeIntervalSince1970: 1_000),
            requestID: nil,
            reason: nil,
            duration: nil,
            userID: nil,
            auditSessionID: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            outcome: .success,
            sshUser: "deploy",
            sourceAddress: "192.168.8.20"
        )

        let line = try AuditEncoder().encodeLine(event)

        XCTAssertTrue(line.contains("deploy"))
        XCTAssertTrue(line.contains("192.168.8.20"))
        XCTAssertFalse(line.contains("privateKey"))
    }

    private func makeWriter(maximumBytes: Int, retainedFiles: Int = 5) throws -> RotatingAuditFileWriter {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serverpc-audit-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        temporaryDirectories.append(directory)
        return RotatingAuditFileWriter(
            fileURL: directory.appendingPathComponent("audit.jsonl"),
            maximumBytes: maximumBytes,
            retainedFiles: retainedFiles,
            expectedOwnerUID: getuid()
        )
    }
}

private extension AuditEvent {
    static let fixture = AuditEvent(
        kind: .opened,
        timestamp: Date(timeIntervalSince1970: 1_000),
        requestID: UUID(uuidString: "75948C79-1EF8-4497-A048-33C307893B2A"),
        reason: nil,
        duration: .minutes30,
        userID: 501,
        auditSessionID: 7,
        interfaceName: "en0",
        sourceCIDR: "192.168.1.0/24",
        outcome: .success
    )

    static func session(
        user: String,
        source: String,
        timestamp: Date = Date(timeIntervalSince1970: 1_000)
    ) -> AuditEvent {
        AuditEvent(
            kind: .sshConnected,
            timestamp: timestamp,
            requestID: nil,
            reason: nil,
            duration: nil,
            userID: nil,
            auditSessionID: nil,
            interfaceName: nil,
            sourceCIDR: nil,
            outcome: .success,
            sshUser: user,
            sourceAddress: source
        )
    }
}
