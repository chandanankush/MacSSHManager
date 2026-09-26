import Foundation

public enum AccessDuration: Int, Codable, CaseIterable, Sendable {
    case minutes15 = 900
    case minutes30 = 1_800
    case minutes60 = 3_600
    case hours3 = 10_800
    case hours6 = 21_600

    public static let `default`: Self = .minutes30

    public var seconds: Int { rawValue }

    public var label: String {
        switch self {
        case .minutes15: "15 minutes"
        case .minutes30: "30 minutes"
        case .minutes60: "60 minutes"
        case .hours3: "3 hours"
        case .hours6: "6 hours"
        }
    }

    public init?(seconds: Int) {
        self.init(rawValue: seconds)
    }
}
