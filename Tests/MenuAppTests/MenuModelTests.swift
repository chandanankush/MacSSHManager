import Foundation
import XCTest
@testable import MenuAppCore
@testable import SharedProtocol

@MainActor
final class MenuModelTests: XCTestCase {
    func testLoginItemRegistrationTreatsNotFoundAsNeedingRegistration() {
        XCTAssertEqual(
            SystemServiceRegistration.loginItemAction(requestedEnabled: true, status: .notFound),
            .register
        )
    }

    func testControllerRequirementPinsActualSigningTeamOU() {
        XCTAssertTrue(XPCControllerClient.controllerRequirement.contains("8ZBMSE6RLV"))
        XCTAssertFalse(XPCControllerClient.controllerRequirement.contains("3ZFLB83693"))
    }

    func testDefaultDurationIsThirtyMinutes() {
        XCTAssertEqual(MenuModel(client: StubController()).selectedDuration, .minutes30)
    }

    func testDefaultNetworkScopeIsLANAndTailscaleBoth() {
        let model = MenuModel(client: StubController())
        XCTAssertTrue(model.scopeLAN)
        XCTAssertTrue(model.scopeTailscale)
        XCTAssertTrue(model.canOpen)
    }

    func testOpenIsUnavailableWhenNeitherScopeIsSelected() async {
        let client = StubController()
        let model = MenuModel(client: client)
        model.scopeLAN = false
        model.scopeTailscale = false

        XCTAssertFalse(model.canOpen)
        await model.open(.minutes30)

        XCTAssertEqual(client.openCalls, 0)
        XCTAssertNotNil(model.message)
    }

    func testOpenRemainsUnavailableUntilEnforcementIsReady() async {
        let model = MenuModel(client: StubController(status: .recovering(localConsoleOnly: false)))
        await model.refresh()
        XCTAssertFalse(model.canOpen)
    }

    func testRetryActionInvokesPrivilegedRecovery() async {
        let client = StubController(status: .unavailable(reason: .pfEnableFailed, localConsoleOnly: false))
        let model = MenuModel(client: client)

        await model.retrySecurityService()

        XCTAssertEqual(client.retryCalls, 1)
        XCTAssertEqual(model.accessStatus.mode, .closed)
    }

    func testOpenPassesSelectedScopeToTheClient() async {
        let client = StubController()
        let model = MenuModel(client: client)
        model.scopeLAN = false
        model.scopeTailscale = true

        await model.open(.minutes30)

        XCTAssertEqual(client.openScopes, [.tailscale])
    }

    func testAuthorizationRequestKeepsTheGrantedRightInItsExternalForm() {
        XCTAssertFalse(SystemAuthorizationRequester.requestFlags.contains(.preAuthorize))
        XCTAssertTrue(SystemAuthorizationRequester.requestFlags.contains(.extendRights))
        XCTAssertTrue(SystemAuthorizationRequester.requestFlags.contains(.interactionAllowed))
    }

    func testCloseNeverRequestsAuthorization() async {
        let authorization = RecordingAuthorizationRequester()
        let client = StubController(status: .open(
            expiresAt: Date().addingTimeInterval(60),
            lastTransition: Date(),
            localConsoleOnly: false
        ))
        let model = MenuModel(client: client, authorization: authorization)

        await model.closeNow()

        XCTAssertEqual(authorization.actions, [])
        XCTAssertEqual(client.closeCalls, 1)
    }

    func testExtensionRequestsFreshAuthorization() async {
        let authorization = RecordingAuthorizationRequester()
        let model = MenuModel(client: StubController(), authorization: authorization)

        await model.open(.hours3)
        await model.open(.hours3)

        XCTAssertEqual(authorization.actions, [.open, .open])
    }

    func testFirstLaunchDoesNotTreatLoginLaunchAsARequiredService() async {
        let services = RecordingServiceRegistration()
        let model = MenuModel(client: StubController(), services: services)

        await model.prepareServices()

        XCTAssertEqual(services.registered, [])
    }

    func testEnablingLaunchAtLoginAlsoPreparesRequiredServices() async {
        let services = RecordingServiceRegistration()
        let model = MenuModel(client: StubController(), services: services)

        await model.setLaunchAtLogin(true)

        XCTAssertTrue(model.launchAtLogin)
        XCTAssertEqual(services.registered, [])
        XCTAssertEqual(services.loginLaunchValues, [true])
    }

    func testTurningOnNeedsNoAuthorizationButTurningOffDoes() async {
        let authorization = RecordingAuthorizationRequester()
        let client = StubController()
        let model = MenuModel(client: client, authorization: authorization)

        await model.setLocalConsoleOnly(true)
        await model.setLocalConsoleOnly(false)

        XCTAssertEqual(authorization.actions, [.disableLocalConsoleOnly])
        XCTAssertEqual(client.settingValues, [true, false])
    }
}

@MainActor
private final class StubController: ControllerRequesting {
    private(set) var closeCalls = 0
    private(set) var openCalls = 0
    private(set) var openScopes: [SSHNetworkScope] = []
    private(set) var settingValues: [Bool] = []
    private(set) var retryCalls = 0
    private var currentStatus: AccessStatus

    init(status: AccessStatus = .closed(lastTransition: nil, localConsoleOnly: false)) {
        currentStatus = status
    }

    func open(
        duration: AccessDuration,
        scope: SSHNetworkScope,
        authorization: Data,
        nonce: UUID
    ) async throws -> AccessStatus {
        openCalls += 1
        openScopes.append(scope)
        currentStatus = .open(
            expiresAt: Date().addingTimeInterval(TimeInterval(duration.seconds)),
            lastTransition: Date(),
            localConsoleOnly: currentStatus.localConsoleOnly,
            networkScope: scope
        )
        return currentStatus
    }
    func close() async throws -> AccessStatus {
        closeCalls += 1
        currentStatus = .closed(lastTransition: Date(), localConsoleOnly: currentStatus.localConsoleOnly)
        return currentStatus
    }
    func setLocalConsoleOnly(_ enabled: Bool, authorization: Data?, nonce: UUID?) async throws -> AccessStatus {
        settingValues.append(enabled)
        currentStatus = .closed(lastTransition: Date(), localConsoleOnly: enabled)
        return currentStatus
    }
    func status() async throws -> AccessStatus { currentStatus }
    func retrySecurityService() async throws -> AccessStatus {
        retryCalls += 1
        currentStatus = .closed(lastTransition: Date(), localConsoleOnly: currentStatus.localConsoleOnly)
        return currentStatus
    }
}

@MainActor
private final class RecordingAuthorizationRequester: AuthorizationRequesting {
    private(set) var actions: [AuthorizationActionRequest] = []
    func request(_ action: AuthorizationActionRequest) async throws -> AuthorizationGrant {
        actions.append(action)
        return AuthorizationGrant(form: Data(repeating: 1, count: 32), nonce: UUID())
    }
}

@MainActor
private final class RecordingServiceRegistration: ServiceRegistering {
    private(set) var registered: [ManagedService] = []
    private(set) var loginLaunchValues: [Bool] = []
    private(set) var launchAtLogin = false
    func prepare() async throws -> ServicePreparation {
        return .ready
    }
    func setLaunchAtLogin(_ enabled: Bool) throws {
        loginLaunchValues.append(enabled)
        launchAtLogin = enabled
    }
    func openApprovalSettings() {}
}
