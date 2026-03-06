import SwiftUI

enum TabSelection {
    case status, records, policy, logs
}

struct DashboardView: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var currentTab: TabSelection = .status
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Codex 安全守卫")
                    .font(.headline)
                Spacer()
                
                HStack(spacing: 4) {
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(
                                    viewModel.guardRunning
                                        ? (viewModel.isSilentMode
                                            ? ApplePalette.info
                                            : (viewModel.hasUnacknowledgedRecords ? ApplePalette.warning : ApplePalette.success))
                                        : ApplePalette.danger
                                )
                                .frame(width: 8, height: 8)
                            Text(
                                viewModel.guardRunning
                                    ? (viewModel.isSilentMode
                                        ? "静默采集"
                                        : (viewModel.hasUnacknowledgedRecords ? "有新拦截" : "守护中"))
                                    : "守护已停止"
                            )
                            .font(.caption)
                            .foregroundColor(
                                viewModel.guardRunning
                                    ? (viewModel.isSilentMode
                                        ? ApplePalette.info
                                        : (viewModel.hasUnacknowledgedRecords ? ApplePalette.warning : .secondary))
                                    : ApplePalette.danger
                            )
                        }

                        Text(actionOrStateHint)
                            .font(.caption2)
                            .foregroundColor(viewModel.daemonActionInProgress ? ApplePalette.warning : .secondary)
                    }
                }

                HStack(spacing: 8) {
                    DaemonCapsuleControl(
                        guardRunning: viewModel.guardRunning,
                        silentMode: viewModel.isSilentMode,
                        actionInProgress: viewModel.daemonActionInProgress,
                        currentAction: viewModel.daemonCurrentAction,
                        onStart: { viewModel.activateGuardMode() },
                        onSilent: { viewModel.activateSilentMode() },
                        onStop: { viewModel.stopDaemon() }
                    )
                    .help("模式切换：开启=拦截，静默=仅记录不阻断，关闭=停止守护")

                    Button(action: {
                        viewModel.restartDaemon()
                    }) {
                        Group {
                            if viewModel.daemonCurrentAction == .restarting {
                                ProgressView()
                                    .progressViewStyle(.circular)
                                    .controlSize(.small)
                            } else {
                                Image(systemName: "arrow.clockwise")
                            }
                        }
                        .frame(width: 14, height: 14)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.plain)
                    .background(
                        Capsule()
                            .fill(ApplePalette.panelBackground)
                    )
                    .overlay(
                        Capsule()
                            .stroke(ApplePalette.border, lineWidth: 1)
                    )
                    .disabled(viewModel.daemonActionInProgress)
                    .help("重启守护进程")
                }
            }
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 8)
            
            // Picker
            Picker("", selection: $currentTab) {
                Text("看板").tag(TabSelection.status)
                Text("记录").tag(TabSelection.records)
                Text("策略").tag(TabSelection.policy)
                Text("日志").tag(TabSelection.logs)
            }
            .pickerStyle(SegmentedPickerStyle())
            .padding(.horizontal)
            .padding(.bottom, 8)
            
            Divider()
            
            // Content
            Group {
                switch currentTab {
                case .status:
                    StatusPanel(viewModel: viewModel)
                case .records:
                    RecordsPanel(viewModel: viewModel)
                case .policy:
                    PolicyPanel(viewModel: viewModel)
                case .logs:
                    LogsPanel(viewModel: viewModel)
                }
            }
            .frame(height: 380)
            
            Divider()
            
            // Footer
            HStack {
                Button(action: {
                    viewModel.refresh()
                }) {
                    Image(systemName: "arrow.triangle.2.circlepath")
                    Text("手动更新")
                }
                .buttonStyle(.borderless)
                
                Spacer()
                
                Button("完全退出前端") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.borderless)
                .foregroundColor(ApplePalette.danger)
                .help("这只会退出监控界面，底层安全守护进程将继续运行")
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(ApplePalette.panelBackground)
        }
        .frame(width: 420)
        .tint(ApplePalette.accent)
        .onAppear {
            viewModel.acknowledgeRecords() // 用户打开了面板，清除警报
        }
        .onChange(of: currentTab) { _ in
            viewModel.acknowledgeRecords() // 切换 Tab 也算已读
        }
    }
}

private extension DashboardView {
    var actionOrStateHint: String {
        if let action = viewModel.daemonCurrentAction {
            switch action {
            case .starting:
                return "正在启动守护进程..."
            case .stopping:
                return "正在停止守护进程..."
            case .restarting:
                return "正在重启守护进程..."
            }
        }
        return viewModel.daemonStateHint
    }
}

private struct DaemonCapsuleControl: View {
    let guardRunning: Bool
    let silentMode: Bool
    let actionInProgress: Bool
    let currentAction: DaemonActionKind?
    let onStart: () -> Void
    let onSilent: () -> Void
    let onStop: () -> Void

    var body: some View {
        HStack(spacing: 4) {
            capsuleButton(
                title: "开启",
                isActive: guardRunning && !silentMode,
                tint: ApplePalette.success,
                showProgress: actionInProgress && currentAction == .starting,
                disabled: (guardRunning && !silentMode) || actionInProgress,
                action: onStart
            )

            capsuleButton(
                title: "静默",
                isActive: guardRunning && silentMode,
                tint: ApplePalette.info,
                showProgress: false,
                disabled: (guardRunning && silentMode) || actionInProgress,
                action: onSilent
            )

            capsuleButton(
                title: "关闭",
                isActive: !guardRunning,
                tint: ApplePalette.danger,
                showProgress: actionInProgress && currentAction == .stopping,
                disabled: !guardRunning || actionInProgress,
                action: onStop
            )
        }
        .padding(3)
        .background(
            Capsule()
                .fill(ApplePalette.panelBackground)
        )
        .overlay(
            Capsule()
                .stroke(ApplePalette.border, lineWidth: 1)
        )
    }

    private func capsuleButton(
        title: String,
        isActive: Bool,
        tint: Color,
        showProgress: Bool,
        disabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if showProgress {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .controlSize(.small)
                } else {
                    Text(title)
                        .font(.caption.weight(.semibold))
                        .foregroundColor(isActive ? .white : tint.opacity(disabled ? 0.45 : 1.0))
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .frame(minWidth: 48)
            .background(
                Capsule()
                    .fill(isActive ? tint.opacity(disabled ? 0.55 : 1.0) : Color.clear)
            )
        }
        .buttonStyle(.plain)
        .disabled(disabled)
    }
}
