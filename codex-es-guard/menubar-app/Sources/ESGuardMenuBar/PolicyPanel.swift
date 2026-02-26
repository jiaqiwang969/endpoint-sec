import SwiftUI
import AppKit

struct PolicyPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var manualOverridePath: String = ""
    
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
                        Button("清除所有放行") {
                            viewModel.clearAllOverrides()
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
                        ForEach(viewModel.policy.temporaryOverrides, id: \.self) { override in
                            HStack {
                                Text(override)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundColor(.orange)
                                Spacer()
                                Button(action: {
                                    viewModel.removeOverride(path: override)
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
                    let tools = viewModel.policy.trustedTools ?? ["git", "cargo", "npm", "node", "python3", "swift", "jj", "rustup", "rustc", "go"]
                    Text("工具: " + tools.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    let agents = viewModel.policy.aiAgentPatterns ?? ["codex", "claude", "claude-code"]
                    Text("AI Agent: " + agents.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Section(header: Text("UI 偏好设置 (Preferences)")) {
                    Picker("放行路径的自动过期时间", selection: $viewModel.autoRevokeMinutes) {
                        Text("从不过期 (不推荐)").tag(0)
                        Text("1 分钟").tag(1)
                        Text("3 分钟 (默认)").tag(3)
                        Text("5 分钟").tag(5)
                        Text("10 分钟").tag(10)
                    }
                    .pickerStyle(MenuPickerStyle())
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
            }
            .listStyle(.sidebar)
        }
        .padding(.top, 8)
    }
    
    private func submitManualOverride() {
        let path = manualOverridePath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !path.isEmpty {
            viewModel.requestOverride(for: path)
            manualOverridePath = ""
        }
    }
}
