import SwiftUI
import AppKit

struct PolicyPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var manualOverridePath: String = ""
    @State private var showEnableTrustedToolsAlert: Bool = false
    @State private var showClearOverridesAlert: Bool = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("安全防护策略")
                    .font(.headline)
                Spacer()
                
                Button(action: {
                    let url = URL(fileURLWithPath: viewModel.policyPath)
                    NSWorkspace.shared.open(url)
                }) {
                    Label("编辑器打开 JSON", systemImage: "pencil.and.outline")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .foregroundColor(.blue)
            }
            .padding(.horizontal)

            Text("建议流程：先“隔离到 temp”，仅在确认要永久删除时再做临时放行。")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.horizontal)
            
            // 手动添加 Override 的输入框
            HStack {
                TextField("输入绝对路径...", text: $manualOverridePath)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 11, design: .monospaced))
                    .onSubmit {
                        submitManualOverride()
                    }
                
                Button(action: submitManualOverride) {
                    Text("添加放行")
                }
                .disabled(manualOverridePath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(.horizontal)

            Text("仅允许受保护目录内的绝对路径；禁止对根目录/家目录/保护目录根做整段放行。")
                .font(.caption2)
                .foregroundColor(.secondary)
                .padding(.horizontal)
            
            List {
                Section(header: Text("受保护目录 (\(viewModel.policy.protectedZones.count))")) {
                    if viewModel.policy.protectedZones.isEmpty {
                        Text("当前系统尚未配置任何保护目录")
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(viewModel.policy.protectedZones, id: \.self) { zone in
                            Text(zone)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.primary)
                        }
                    }
                }
                
                Section(header: HStack {
                    Text("临时放行路径 (\(viewModel.policy.temporaryOverrides.count))")
                    Spacer()
                    if !viewModel.policy.temporaryOverrides.isEmpty {
                        Button("一键清空 temporary_overrides") {
                            showClearOverridesAlert = true
                        }
                        .font(.caption)
                        .foregroundColor(.red)
                        .buttonStyle(PlainButtonStyle())
                    }
                }) {
                    if viewModel.policy.temporaryOverrides.isEmpty {
                        Text("当前没有任何放行策略")
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(viewModel.policy.temporaryOverrides) { override in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(override.path)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundColor(.orange)

                                    TimelineView(.periodic(from: .now, by: 1.0)) { _ in
                                        Text(overrideStatusText(override))
                                            .font(.caption2)
                                            .foregroundColor(override.isExpired ? .red : .secondary)
                                    }

                                    if let meta = overrideMetaText(override) {
                                        Text(meta)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                }
                                Spacer()
                                Button(action: {
                                    viewModel.removeOverride(path: override.path)
                                }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundColor(.red)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                }
                
                Section(header: Text("受信白名单 (内置)")) {
                    let tools = viewModel.policy.trustedTools ?? ["git", "jj", "cargo", "rustup", "rustc", "swift", "swiftc", "xcodebuild", "xcrun", "nix", "nix-build", "nix-store", "nix-env", "nix-daemon", "brew", "make", "cmake", "ninja", "go", "docker"]
                    Text("工具: " + tools.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    let agents = viewModel.policy.aiAgentPatterns ?? ["codex", "claude", "claude-code"]
                    Text("AI Agent: " + agents.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)

                    let vcsMetaInAI = viewModel.policy.allowVCSMetadataInAIContext ?? true
                    Text("AI 上下文 Git/JJ 元数据维护(.git/.jj): " + (vcsMetaInAI ? "开启 (推荐)" : "关闭 (更严格)"))
                        .font(.caption)
                        .foregroundColor(vcsMetaInAI ? .secondary : .orange)

                    let autoProtectHomeDigitChildren = viewModel.policy.autoProtectHomeDigitChildren ?? true
                    Text("HOME 数字前缀目录自动保护: " + (autoProtectHomeDigitChildren ? "开启 (推荐)" : "关闭"))
                        .font(.caption)
                        .foregroundColor(autoProtectHomeDigitChildren ? .secondary : .orange)

                    let trustedInAI = viewModel.policy.allowTrustedToolsInAIContext ?? false
                    Text("AI 上下文信任工具放行: " + (trustedInAI ? "开启 (兼容模式)" : "关闭 (推荐更安全)"))
                        .font(.caption)
                        .foregroundColor(trustedInAI ? .orange : .secondary)
                }

                Section(header: Text("高级安全开关")) {
                    let autoProtectHomeDigitChildren = viewModel.policy.autoProtectHomeDigitChildren ?? true
                    let vcsMetaInAI = viewModel.policy.allowVCSMetadataInAIContext ?? true
                    let trustedInAI = viewModel.policy.allowTrustedToolsInAIContext ?? false

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("自动保护 HOME 下数字前缀目录")
                                .font(.caption)
                            Text("例如 ~/01-agent、~/0x-lab。可覆盖新建目录，避免 /Users/you/0 与 /Users/you/01-* 边界不匹配。")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { autoProtectHomeDigitChildren },
                            set: { enabled in
                                viewModel.updateAutoProtectHomeDigitChildren(enabled)
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                    }

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("AI 上下文允许 Git/JJ 维护 .git/.jj 元数据")
                                .font(.caption)
                            Text("推荐开启：保留 git commit 等元数据写入能力，但仍拦截 git rm 工作区删除。")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { vcsMetaInAI },
                            set: { enabled in
                                viewModel.updateAllowVCSMetadataInAIContext(enabled)
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                    }

                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("AI 上下文允许 trusted_tools 放行")
                                .font(.caption)
                            Text("默认应关闭。开启后 AI 可借助 trusted tools 删除保护区文件。")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { trustedInAI },
                            set: { enabled in
                                if enabled {
                                    showEnableTrustedToolsAlert = true
                                } else {
                                    viewModel.updateAllowTrustedToolsInAIContext(false)
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                    }
                }

                Section(header: Text("策略维护")) {
                    Button(role: .destructive) {
                        showClearOverridesAlert = true
                    } label: {
                        Label("一键清空 temporary_overrides（经 root helper）", systemImage: "trash")
                    }
                    .disabled(viewModel.policy.temporaryOverrides.isEmpty)

                    Text("调用 es-guard-override --clear 清空运行时放行，不会修改 protected_zones。")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                
                Section(header: Text("UI 偏好设置 (Preferences)")) {
                    Picker("放行路径的自动过期时间", selection: $viewModel.autoRevokeMinutes) {
                        Text("1 分钟").tag(1)
                        Text("3 分钟 (默认)").tag(3)
                        Text("5 分钟").tag(5)
                        Text("10 分钟").tag(10)
                        Text("30 分钟 (上限)").tag(30)
                    }
                    .pickerStyle(MenuPickerStyle())
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
            }
            .listStyle(.sidebar)
        }
        .padding(.top, 8)
        .alert("开启兼容模式会降低安全性", isPresented: $showEnableTrustedToolsAlert) {
            Button("取消", role: .cancel) {}
            Button("仍然开启", role: .destructive) {
                viewModel.updateAllowTrustedToolsInAIContext(true)
            }
        } message: {
            Text("开启后，AI 上下文里的 git/cargo 等 trusted_tools 也可能通过删除校验。仅在兼容旧工作流时临时启用。")
        }
        .alert("确认清空 temporary_overrides？", isPresented: $showClearOverridesAlert) {
            Button("取消", role: .cancel) {}
            Button("确认清空", role: .destructive) {
                viewModel.clearAllOverrides()
            }
        } message: {
            Text("这会通过 root helper 清空 runtime temporary_overrides，用于重置临时放行状态。")
        }
    }
    
    private func submitManualOverride() {
        let path = manualOverridePath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !path.isEmpty {
            viewModel.requestOverride(for: path)
            manualOverridePath = ""
        }
    }

    private func overrideStatusText(_ override: TemporaryOverride) -> String {
        guard let expiresAt = override.expiresAt else {
            return "不过期（legacy/manual，建议清理）"
        }

        let now = Int(Date().timeIntervalSince1970)
        if expiresAt <= now {
            return "已过期，等待守护进程清理"
        }

        let remaining = expiresAt - now
        if remaining < 60 {
            return "剩余 \(remaining) 秒"
        }
        if remaining < 3600 {
            return "剩余 \(remaining / 60) 分钟"
        }

        let formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss"
        let date = Date(timeIntervalSince1970: TimeInterval(expiresAt))
        return "到期时间 \(formatter.string(from: date))"
    }

    private func overrideMetaText(_ override: TemporaryOverride) -> String? {
        let createdBy = override.createdBy?.trimmingCharacters(in: .whitespacesAndNewlines)
        let createdAt = override.createdAt

        let byText = createdBy.flatMap { value in
            value.isEmpty ? nil : "来源: \(value)"
        }
        let atText: String? = {
            guard let createdAt else { return nil }
            let formatter = DateFormatter()
            formatter.dateFormat = "MM-dd HH:mm:ss"
            let date = Date(timeIntervalSince1970: TimeInterval(createdAt))
            return "创建: \(formatter.string(from: date))"
        }()

        if let byText, let atText {
            return "\(byText) · \(atText)"
        }
        return byText ?? atText
    }
}
