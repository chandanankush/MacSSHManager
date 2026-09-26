import ControllerTransport
import Foundation
import OSLog
import SecurityCore
import SharedProtocol

do {
    let logger = Logger(subsystem: "com.serverpc.ssh-control", category: "startup")
    let controller = try ProductionComposition.makeAccessController()
    Task {
        logger.notice("controller starting bounded packet-filter recovery")
        _ = await controller.recoverSecurityService()
    }
    let codePolicy = try FileInstalledClientPolicyStore().load()
    let delegate = ControllerListenerDelegate(
        controller: controller,
        history: AuditHistoryReader(),
        codePolicy: codePolicy
    )
    let listener = NSXPCListener(machServiceName: InstalledPaths.controllerMachService)
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
} catch {
    exit(EXIT_FAILURE)
}
