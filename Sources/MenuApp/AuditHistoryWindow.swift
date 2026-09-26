import AppKit
import SharedProtocol
import SwiftUI

@MainActor
public final class AuditHistoryWindowController: NSWindowController {
    private let historyModel: AuditHistoryModel

    public init(client: any ControllerRequesting = XPCControllerClient()) {
        historyModel = AuditHistoryModel(client: client)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 590),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "SSH Audit History"
        window.minSize = NSSize(width: 620, height: 440)
        window.isReleasedWhenClosed = false
        window.titlebarAppearsTransparent = true
        window.contentViewController = NSHostingController(
            rootView: AuditHistoryView(model: historyModel)
        )
        super.init(window: window)
        window.center()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    public func present() {
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        Task { await historyModel.load(query: historyModel.searchText.isEmpty ? nil : historyModel.searchText) }
    }
}

public struct AuditHistoryView: View {
    @ObservedObject private var model: AuditHistoryModel

    public init(model: AuditHistoryModel) {
        self.model = model
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(apertureAmber.opacity(0.14))
                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(apertureAmber)
            }
            .frame(width: 44, height: 44)

            VStack(alignment: .leading, spacing: 2) {
                Text("SSH AUDIT HISTORY")
                    .font(.caption2.weight(.bold))
                    .tracking(1.2)
                    .foregroundStyle(.secondary)
                Text("Access and session timeline")
                    .font(.system(.title3, design: .rounded, weight: .semibold))
            }

            Spacer()

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.tertiary)
                TextField("Search user, IP, or event", text: $model.searchText)
                    .textFieldStyle(.plain)
                    .onChange(of: model.searchText) { _ in model.scheduleSearch() }
                if !model.searchText.isEmpty {
                    Button {
                        model.searchText = ""
                        model.scheduleSearch()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.tertiary)
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 11)
            .frame(width: 270, height: 32)
            .background(.quaternary.opacity(0.55), in: RoundedRectangle(cornerRadius: 9, style: .continuous))

            Button {
                Task { await model.load(query: model.searchText.isEmpty ? nil : model.searchText) }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Reload history")
            .disabled(model.isLoading)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 16)
    }

    @ViewBuilder
    private var content: some View {
        if model.isLoading && model.entries.isEmpty {
            VStack(spacing: 12) {
                ProgressView()
                Text("Reading local history…").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let message = model.message {
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.shield")
                    .font(.system(size: 30, weight: .medium))
                    .foregroundStyle(.red)
                Text(message).font(.headline)
                Text("SSH access controls continue to work even when history cannot be read.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("Try again") {
                    Task { await model.load(query: model.searchText.isEmpty ? nil : model.searchText) }
                }
            }
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if model.entries.isEmpty {
            VStack(spacing: 10) {
                Image(systemName: "clock.badge.checkmark")
                    .font(.system(size: 30, weight: .medium))
                    .foregroundStyle(.secondary)
                Text(model.searchText.isEmpty ? "No history yet" : "No matching events")
                    .font(.headline)
                Text(model.searchText.isEmpty ? "Access changes and successful SSH sessions will appear here." : "Try a username, IP address, or event name.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(model.entries.enumerated()), id: \.offset) { index, entry in
                        AuditHistoryRow(entry: entry, isLast: index == model.entries.count - 1)
                    }
                }
                .padding(.horizontal, 22)
                .padding(.vertical, 10)
            }
            .overlay(alignment: .topTrailing) {
                if model.isLoading { ProgressView().controlSize(.small).padding(12) }
            }
        }
    }

    private var footer: some View {
        HStack {
            Label("Stored locally · 30-day rolling history", systemImage: "lock.shield")
            Spacer()
            Text("\(model.entries.count) event\(model.entries.count == 1 ? "" : "s")")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 22)
        .padding(.vertical, 11)
    }

    private var apertureAmber: Color { Color(red: 0.82, green: 0.43, blue: 0.08) }
}

private struct AuditHistoryRow: View {
    let entry: AuditHistoryEntry
    let isLast: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(accent.opacity(0.15))
                    Image(systemName: symbol)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(accent)
                }
                .frame(width: 30, height: 30)
                if !isLast {
                    Rectangle().fill(Color.secondary.opacity(0.18)).frame(width: 1, height: 48)
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title)
                        .font(.system(.body, design: .rounded, weight: .semibold))
                    Text(outcomeLabel)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(outcomeColor)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(outcomeColor.opacity(0.11), in: Capsule())
                    Spacer()
                    Text(entry.timestamp.formatted(date: .abbreviated, time: .standard))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                ForEach(details, id: \.self) { detail in
                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if let context {
                    Text(context)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }
            .padding(.top, 3)
            .padding(.bottom, isLast ? 10 : 15)
        }
    }

    private var title: String {
        switch entry.kind {
        case .sshConnected: "SSH session connected"
        case .sshDisconnected: "SSH session disconnected"
        case .openRequested: "SSH access requested"
        case .opened: "SSH access opened"
        case .openFailed: "SSH access failed to open"
        case .closed: "SSH access closed"
        case .closeDegraded: "SSH close completed with warnings"
        case .expired: "Access window expired"
        case .recoveredClosed: "Closed state recovered"
        case .settingChanged: "Security setting changed"
        case .networkChanged: "LAN interface changed"
        case .publicNetwork: "Public network detected"
        }
    }

    private var details: [String] {
        var values: [String] = []
        if let user = entry.sshUser, let source = entry.sourceAddress {
            values.append("\(user) from \(source)")
        }
        if let reason = entry.reason?.errorDescription { values.append("Reason: \(reason)") }
        if let duration = entry.duration { values.append("Access window: \(duration.label)") }
        return values
    }

    private var context: String? {
        let values = [
            entry.interfaceName.map { "Interface \($0)" },
            entry.sourceCIDR.map { "LAN \($0)" },
            entry.localConsoleOnly.map { $0 ? "Local-console-only on" : "Local-console-only off" },
        ].compactMap { $0 }
        return values.isEmpty
            ? nil
            : values.joined(separator: " · ")
    }

    private var outcomeLabel: String {
        switch entry.outcome {
        case .success: "Success"
        case .failure: "Failed"
        case .degraded: "Degraded"
        }
    }

    private var outcomeColor: Color {
        switch entry.outcome {
        case .success: Color(red: 0.31, green: 0.54, blue: 0.38)
        case .failure: .red
        case .degraded: .orange
        }
    }

    private var symbol: String {
        switch entry.kind {
        case .sshConnected: "arrow.down.left"
        case .sshDisconnected: "arrow.up.right"
        case .opened, .openRequested: "lock.open"
        case .openFailed, .closeDegraded, .publicNetwork: "exclamationmark"
        case .settingChanged: "slider.horizontal.3"
        case .networkChanged: "network"
        default: "lock"
        }
    }

    private var accent: Color {
        switch entry.kind {
        case .sshConnected, .opened: Color(red: 0.82, green: 0.43, blue: 0.08)
        case .openFailed, .closeDegraded, .publicNetwork: .red
        default: Color(red: 0.30, green: 0.40, blue: 0.48)
        }
    }
}
