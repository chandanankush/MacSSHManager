import SwiftUI
import SharedProtocol

public struct MenuContentView: View {
    @ObservedObject private var model: MenuModel
    @State private var now = Date()
    private let onShowHistory: () -> Void

    public init(model: MenuModel, onShowHistory: @escaping () -> Void = {}) {
        self.model = model
        self.onShowHistory = onShowHistory
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusHeader
            if model.servicePreparation == .approvalRequired {
                setupRequired
            } else {
                durationControls
                actionControls
            }
            preferences
            if let message = model.message {
                issueMessage(message)
            }
            if model.accessStatus.mode == .unavailable {
                Button("Retry security service") {
                    Task { await model.retrySecurityService() }
                }
                .buttonStyle(.bordered)
                .disabled(model.isBusy)
            }
            Button(action: onShowHistory) {
                HStack(spacing: 9) {
                    Image(systemName: "clock.arrow.circlepath")
                        .foregroundStyle(apertureAmber)
                    Text("View full history")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                    Image(systemName: "arrow.up.forward.app")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 2)
            .accessibilityHint("Opens the searchable SSH audit history window")
            Divider()
            HStack {
                Label("Port 22 · \(effectiveScopeLabel)", systemImage: "network")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(width: 360)
        .task { await model.prepareServices() }
        .task { await model.poll() }
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { now = $0 }
    }

    private var statusHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: model.menuSymbol)
                .font(.system(size: 18, weight: .bold))
                .foregroundStyle(statusColor)
                .frame(width: 38, height: 38)
                .background(statusColor.opacity(0.14), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                Text("SSH ACCESS")
                    .font(.caption2.weight(.bold))
                    .tracking(1.1)
                    .foregroundStyle(.secondary)
                Text(statusTitle)
                    .font(.system(.headline, design: .rounded, weight: .bold))
                Text(statusDetail)
                    .font(.caption.monospaced())
                    .foregroundStyle(statusColor)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
                .shadow(color: statusColor.opacity(0.6), radius: 4)
        }
        .padding(13)
        .background(.quaternary.opacity(0.55), in: RoundedRectangle(cornerRadius: 15, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var durationControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(model.accessStatus.mode == .open ? "Replace access window" : "Access window")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Text(pendingScopeLabel)
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(.quaternary, in: Capsule())
            }
                .foregroundStyle(.secondary)
            networkScopeControls
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 3), spacing: 6) {
                ForEach(AccessDuration.allCases, id: \.rawValue) { duration in
                    Button(shortLabel(duration)) { model.selectedDuration = duration }
            .buttonStyle(.bordered)
            .tint(model.selectedDuration == duration ? apertureAmber : .secondary)
                        .controlSize(.small)
                }
            }
        }
    }

    private var networkScopeControls: some View {
        HStack(spacing: 16) {
            Toggle("LAN", isOn: $model.scopeLAN)
                .toggleStyle(.checkbox)
            Toggle("Tailscale", isOn: $model.scopeTailscale)
                .toggleStyle(.checkbox)
            Spacer()
        }
        .font(.caption.weight(.medium))
    }

    private var actionControls: some View {
        HStack(spacing: 8) {
            Button {
                Task { await model.open(model.selectedDuration) }
            } label: {
                Label(
                    model.accessStatus.mode == .open ? "Replace window" : "Open SSH",
                    systemImage: "lock.open"
                )
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(apertureAmber)
            .disabled(model.isBusy || !model.canOpen)

            closeControl
        }
    }

    private var closeControl: some View {
        Button("Close now") { Task { await model.closeNow() } }
            .buttonStyle(.bordered)
            .keyboardShortcut(.cancelAction)
            .disabled(model.isBusy)
    }

    private var preferences: some View {
        VStack(spacing: 0) {
            preferenceRow(
                title: "Launch at login",
                detail: "Start this control panel after you sign in.",
                isOn: Binding(
                    get: { model.launchAtLogin },
                    set: { value in Task { await model.setLaunchAtLogin(value) } }
                )
            )
            Divider().padding(.leading, 31)
            preferenceRow(
                title: "Local-console-only",
                detail: "Close SSH if remote-control activity is detected.",
                isOn: Binding(
                    get: { model.accessStatus.localConsoleOnly },
                    set: { value in Task { await model.setLocalConsoleOnly(value) } }
                )
            )
        }
        .background(.quaternary.opacity(0.42), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .disabled(model.isBusy)
    }

    private var setupRequired: some View {
        VStack(alignment: .leading, spacing: 9) {
            Label("One-time setup required", systemImage: "person.badge.key.fill")
                .font(.subheadline.weight(.bold))
            Text("Approve Mac SSH Manager in Login Items. SSH stays closed until macOS accepts the background services.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Open Login Items") { model.openApprovalSettings() }
                .buttonStyle(.borderedProminent)
        }
        .padding(12)
        .background(statusColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 13, style: .continuous))
    }

    private func preferenceRow(title: String, detail: String, isOn: Binding<Bool>) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: title == "Launch at login" ? "power" : "display.and.arrow.down")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 20, height: 20)
                .background(.tertiary, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.medium))
                Text(detail).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: isOn)
                .toggleStyle(.checkbox)
                .labelsHidden()
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 10)
    }

    private func issueMessage(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.caption)
            .foregroundStyle(.red)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var statusTitle: String {
        switch model.accessStatus.mode {
        case .closed: "SSH CLOSED"
        case .opening: "OPENING SSH"
        case .open: "SSH OPEN"
        case .closing: "CLOSING SSH"
        case .recovering: "RECOVERING SECURITY SERVICE…"
        case .degradedClosed: "DEGRADED CLOSED"
        case .unavailable: "CONTROL UNAVAILABLE"
        }
    }

    private var statusDetail: String {
        guard model.accessStatus.mode == .open, let expiry = model.accessStatus.expiresAt else {
            if model.accessStatus.mode == .recovering { return "Verifying Packet Filter enforcement" }
            return model.accessStatus.reason?.localizedDescription ?? "Inbound access is blocked"
        }
        let remaining = max(0, Int(expiry.timeIntervalSince(now)))
        return String(format: "%02d:%02d remaining", remaining / 60, remaining % 60)
    }

    private var statusColor: Color {
        switch model.accessStatus.mode {
        case .open, .opening, .recovering: apertureAmber
        case .degradedClosed, .unavailable: .red
        default: closedSlate
        }
    }

    private var pendingScopeLabel: String {
        switch (model.scopeLAN, model.scopeTailscale) {
        case (true, true): "LAN + Tailscale"
        case (true, false): "LAN only"
        case (false, true): "Tailscale only"
        case (false, false): "No network selected"
        }
    }

    private var effectiveScopeLabel: String {
        if model.accessStatus.mode == .open, let scope = model.accessStatus.networkScope {
            return scopeLabel(scope)
        }
        return pendingScopeLabel
    }

    private func scopeLabel(_ scope: SSHNetworkScope) -> String {
        switch scope {
        case .lan: "LAN only"
        case .tailscale: "Tailscale only"
        case .lanAndTailscale: "LAN + Tailscale"
        }
    }

    private var apertureAmber: Color { Color(red: 0.82, green: 0.43, blue: 0.08) }
    private var closedSlate: Color { Color(red: 0.25, green: 0.32, blue: 0.38) }

    private func shortLabel(_ duration: AccessDuration) -> String {
        switch duration {
        case .minutes15: "15m"
        case .minutes30: "30m"
        case .minutes60: "60m"
        case .hours3: "3h"
        case .hours6: "6h"
        }
    }
}
