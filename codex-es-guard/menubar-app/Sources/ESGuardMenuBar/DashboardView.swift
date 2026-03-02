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
                    Circle()
                        .fill(
                            viewModel.guardRunning
                                ? (viewModel.hasUnacknowledgedRecords ? Color.orange : Color.green)
                                : Color.red
                        )
                        .frame(width: 8, height: 8)
                    Text(
                        viewModel.guardRunning
                            ? (viewModel.hasUnacknowledgedRecords ? "有新拦截" : "守护中")
                            : "守护已停止"
                    )
                    .font(.caption)
                    .foregroundColor(
                        viewModel.guardRunning
                            ? (viewModel.hasUnacknowledgedRecords ? .orange : .secondary)
                            : .red
                    )
                }

                Button("开启") {
                    viewModel.startDaemon()
                }
                .buttonStyle(.borderless)
                .disabled(viewModel.guardRunning || viewModel.daemonActionInProgress)
                .help("启动 launchd 中的 codex-es-guard")

                Button("关闭") {
                    viewModel.stopDaemon()
                }
                .buttonStyle(.borderless)
                .disabled(!viewModel.guardRunning || viewModel.daemonActionInProgress)
                .foregroundColor(.red)
                .help("临时停止 launchd 中的 codex-es-guard")

                Button(action: {
                    viewModel.restartDaemon()
                }) {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .disabled(viewModel.daemonActionInProgress)
                .help("重启守护进程")
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
                .foregroundColor(.red)
                .help("这只会退出监控界面，底层安全守护进程将继续运行")
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(Color(NSColor.controlBackgroundColor))
        }
        .frame(width: 420)
        .onAppear {
            viewModel.acknowledgeRecords() // 用户打开了面板，清除警报
        }
        .onChange(of: currentTab) { _ in
            viewModel.acknowledgeRecords() // 切换 Tab 也算已读
        }
    }
}
