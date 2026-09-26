import Darwin
import Foundation

public protocol ContinuousTimeProviding: Sendable {
    var bootSessionID: String { get }
    var uptimeIncludingSleep: TimeInterval { get }
    var wallNow: Date { get }
}

public struct SystemContinuousClock: ContinuousTimeProviding {
    public let bootSessionID: String

    private let timebaseNumerator: UInt64
    private let timebaseDenominator: UInt64

    public init() throws {
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS,
              timebase.numer > 0,
              timebase.denom > 0
        else {
            throw ControlClockError.timebaseUnavailable
        }

        timebaseNumerator = UInt64(timebase.numer)
        timebaseDenominator = UInt64(timebase.denom)
        bootSessionID = try Self.readBootSessionID()
    }

    public var uptimeIncludingSleep: TimeInterval {
        let ticks = mach_continuous_time()
        let nanoseconds = Double(ticks) * Double(timebaseNumerator) / Double(timebaseDenominator)
        return nanoseconds / 1_000_000_000
    }

    public var wallNow: Date { Date() }

    private static func readBootSessionID() throws -> String {
        var byteCount = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &byteCount, nil, 0) == 0,
              byteCount > 1,
              byteCount <= 256
        else {
            throw ControlClockError.bootSessionUnavailable
        }

        var buffer = [CChar](repeating: 0, count: byteCount)
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &byteCount, nil, 0) == 0 else {
            throw ControlClockError.bootSessionUnavailable
        }

        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let value = String(decoding: bytes, as: UTF8.self)
        guard !value.isEmpty else {
            throw ControlClockError.bootSessionUnavailable
        }
        return value
    }
}

public enum ControlClockError: Error, Equatable {
    case timebaseUnavailable
    case bootSessionUnavailable
}
