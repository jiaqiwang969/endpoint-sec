import SwiftUI
import AppKit

struct RecordsPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var filterOp: String = "All"
    @State private var searchText: String = ""
    
    var filteredRecords: [DenialRecord] {
        var result = viewModel.records
        
        // 1. 类型过滤
        if filterOp != "All" {
            result = result.filter {
                if filterOp == "DELETE" { return $0.op == "unlink" }
                if filterOp == "MOVE" { return $0.op == "rename" }
                return true
            }
        }
        
        // 2. 文本搜索过滤
        if !searchText.isEmpty {
            let lowerSearch = searchText.lowercased()
            result = result.filter { record in
                record.path.lowercased().contains(lowerSearch) ||
                record.ancestor.lowercased().contains(lowerSearch) ||
                record.process.lowercased().contains(lowerSearch)
            }
        }
        
        return result
    }
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("历史拦截记录")
                    .font(.headline)
                Spacer()
                
                Picker("", selection: $filterOp) {
                    Text("全部").tag("All")
                    Text("仅删除 (DELETE)").tag("DELETE")
                    Text("仅移动 (MOVE)").tag("MOVE")
                }
                .pickerStyle(MenuPickerStyle())
                .frame(width: 140)
            }
            .padding(.horizontal)
            .padding(.bottom, 8)
            
            // 搜索框
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("搜索文件名、路径或 Agent...", text: $searchText)
                    .textFieldStyle(PlainTextFieldStyle())
                    .disableAutocorrection(true)
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(6)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(6)
            .padding(.horizontal)
            .padding(.bottom, 8)
            
            if filteredRecords.isEmpty {
                VStack {
                    Spacer()
                    Image(systemName: "shield.checkmark.fill")
                        .font(.largeTitle)
                        .foregroundColor(.green)
                    Text("未查询到匹配的拦截记录")
                        .foregroundColor(.secondary)
                        .padding(.top, 8)
                    Spacer()
                }
            } else {
                List(filteredRecords) { record in
                    RecordRow(record: record, viewModel: viewModel)
                }
                .listStyle(.plain)
            }
        }
        .padding(.top, 8)
    }
}

struct RecordRow: View {
    let record: DenialRecord
    @ObservedObject var viewModel: ESGuardViewModel
    
    private func getAgentColor(for name: String) -> Color {
        let nameLower = name.lowercased()
        if nameLower.contains("codex") {
            return .purple
        } else if nameLower.contains("claude") {
            return .orange
        } else if nameLower.contains("copilot") {
            return .teal
        } else {
            return .gray
        }
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(record.op == "unlink" ? "DELETE" : "MOVE")
                    .font(.system(.caption, design: .monospaced).bold())
                    .foregroundColor(record.op == "unlink" ? .red : .blue)
                
                Text(URL(fileURLWithPath: record.path).lastPathComponent)
                    .font(.callout.bold())
                
                Spacer()
                
                Text(record.ancestor)
                    .font(.system(size: 9, design: .monospaced).bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(getAgentColor(for: record.ancestor))
                    .cornerRadius(4)
            }
            
            Text(record.path)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled) // 允许复制路径
            
            if record.op == "rename", let dest = record.dest {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.right")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(dest)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            
            HStack {
                Text(Date(timeIntervalSince1970: TimeInterval(record.ts)).formatted(date: .omitted, time: .standard))
                    .font(.caption2)
                    .foregroundColor(.gray)
                Spacer()
            }
        }
        .padding(.vertical, 4)
        // 右键上下文菜单
        .contextMenu {
            Button("复制文件路径") {
                let pasteboard = NSPasteboard.general
                pasteboard.clearContents()
                pasteboard.setString(record.path, forType: .string)
            }
            Button("在 Finder 中显示") {
                NSWorkspace.shared.selectFile(record.path, inFileViewerRootedAtPath: "")
            }
            Divider()
            Button("临时放行此文件 (\(viewModel.autoRevokeMinutes)分钟)") {
                viewModel.requestOverride(for: record.path)
            }
        }
    }
}
