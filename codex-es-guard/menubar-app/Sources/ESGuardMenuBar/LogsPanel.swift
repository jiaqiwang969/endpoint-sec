import SwiftUI

struct LogsPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var showOnlyErrors = false
    
    var filteredLogs: [LogLine] {
        if showOnlyErrors {
            return viewModel.logLines.filter { $0.isError }
        }
        return viewModel.logLines
    }
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("系统守护进程日志")
                    .font(.headline)
                Spacer()
                
                Toggle("仅查看错误", isOn: $showOnlyErrors)
                    .toggleStyle(SwitchToggleStyle(tint: .red))
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
            
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(filteredLogs) { line in
                            Text(line.text)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(line.isError ? .red : .primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                    .background(Color(NSColor.textBackgroundColor))
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
