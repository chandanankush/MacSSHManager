import AppKit
import Combine
import Darwin
import MenuAppCore
import SwiftUI

@main
struct MacSSHManagerApp: App {
    @NSApplicationDelegateAdaptor(MenuBarAppDelegate.self) private var appDelegate

    var body: some Scene {
        Settings { EmptyView() }
    }
}

@MainActor
private final class MenuBarAppDelegate: NSObject, NSApplicationDelegate {
    private let model = MenuModel()
    private let popover = NSPopover()
    private var statusItem: NSStatusItem?
    private var statusObservation: AnyCancellable?
    private var historyWindowController: AuditHistoryWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if Array(CommandLine.arguments.dropFirst()) == ["--unregister-login-item"] {
            do {
                try SystemServiceRegistration.unregisterLoginItemForUninstall()
                exit(EXIT_SUCCESS)
            } catch {
                exit(EXIT_FAILURE)
            }
        }
        NSApp.setActivationPolicy(.accessory)

        popover.behavior = .transient
        popover.contentViewController = NSHostingController(
            rootView: MenuContentView(model: model) { [weak self] in
                self?.showHistory()
            }
        )

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.target = self
        item.button?.action = #selector(togglePopover(_:))
        statusItem = item
        updateStatusImage()

        statusObservation = model.objectWillChange.sink { [weak self] _ in
            self?.updateStatusImage()
        }
    }

    @objc private func togglePopover(_ sender: Any?) {
        guard let button = statusItem?.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func updateStatusImage() {
        let image = NSImage(systemSymbolName: model.menuSymbol, accessibilityDescription: "Mac SSH Manager")
        image?.isTemplate = true
        statusItem?.button?.image = image
    }

    private func showHistory() {
        popover.performClose(nil)
        if historyWindowController == nil {
            historyWindowController = AuditHistoryWindowController()
        }
        historyWindowController?.present()
    }
}
