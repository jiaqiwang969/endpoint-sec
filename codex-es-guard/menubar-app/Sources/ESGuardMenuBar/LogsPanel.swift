import SwiftUI

struct LogsPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var showOnlyErrors = false
    
    var filteredLogs: [LogLine] {
        var logs = viewModel.logLines
        if viewModel.suppressNoiseRecords {
            logs = logs.filter { !$0.isNoise }
        }
        if showOnlyErrors {
            return logs.filter { $0.isError }
        }
        return logs
    }
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("系统守护进程日志")
                    .font(.headline)
                Spacer()
                
                Toggle("仅查看错误", isOn: $showOnlyErrors)
                    .toggleStyle(SwitchToggleStyle(tint: ApplePalette.danger))
                    .controlSize(.small)

                Toggle("隐藏噪声", isOn: Binding(
                    get: { viewModel.suppressNoiseRecords },
                    set: { viewModel.setSuppressNoiseRecords($0) }
                ))
                .toggleStyle(SwitchToggleStyle(tint: ApplePalette.accent))
                .controlSize(.small)
                
                Button(action: {
                    let text = viewModel.logLines.map { $0.text }.joined(separator: "\n")
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(text, forType: .string)
                }) {
                    Image(systemName: "doc.on.clipboard")
                }
                .buttonStyle(PlainButtonStyle())
                .padding(.leading, 8)
                .help("复制日志到剪贴板")
            }
            .padding(.horizontal)
            .padding(.bottom, 8)

            if viewModel.suppressNoiseRecords {
                Text("降噪已开启：已隐藏噪声型读根目录/设备文件事件")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
                    .padding(.bottom, 4)
            }
            
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(filteredLogs) { line in
                            Text(line.text)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(line.isError ? ApplePalette.danger : .primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                    .background(ApplePalette.textBackground)
                    .cornerRadius(4)
                }
                .padding(.horizontal)
                .onChange(of: filteredLogs.count) { _ in
                    if let lastId = filteredLogs.last?.id {
                        withAnimation {
                            proxy.scrollTo(lastId, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .padding(.top, 8)
    }
}
