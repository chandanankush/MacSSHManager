import Foundation
import Security
import SharedProtocol

public enum AuthorizationActionRequest: Equatable, Sendable {
    case open
    case disableLocalConsoleOnly

    var rightName: String { InstalledPaths.authorizationRight }
}

@MainActor
public protocol AuthorizationRequesting: AnyObject {
    func request(_ action: AuthorizationActionRequest) async throws -> AuthorizationGrant
}

public final class AuthorizationGrant: @unchecked Sendable {
    public private(set) var form: Data
    public let nonce: UUID

    private let lock = NSLock()
    private var cleanup: (() -> Void)?

    public init(form: Data, nonce: UUID, cleanup: (() -> Void)? = nil) {
        self.form = form
        self.nonce = nonce
        self.cleanup = cleanup
    }

    public func destroy() {
        lock.withLock {
            guard let cleanup else { return }
            form.resetBytes(in: form.indices)
            self.cleanup = nil
            cleanup()
        }
    }

    deinit { destroy() }
}

@MainActor
public final class SystemAuthorizationRequester: AuthorizationRequesting {
    static let requestFlags: AuthorizationFlags = [.interactionAllowed, .extendRights]

    public init() {}

    public func request(_ action: AuthorizationActionRequest) async throws -> AuthorizationGrant {
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization
        else {
            throw ControlErrorCode.invalidAuthorization
        }

        let status = action.rightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(
                    authorization,
                    &rights,
                    nil,
                    Self.requestFlags,
                    nil
                )
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            throw ControlErrorCode.invalidAuthorization
        }

        var externalForm = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(authorization, &externalForm) == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            throw ControlErrorCode.invalidAuthorization
        }
        let data = withUnsafeBytes(of: &externalForm) { Data($0) }
        _ = withUnsafeMutableBytes(of: &externalForm) {
            $0.initializeMemory(as: UInt8.self, repeating: 0)
        }
        return AuthorizationGrant(form: data, nonce: UUID()) {
            AuthorizationFree(authorization, [.destroyRights])
        }
    }
}
