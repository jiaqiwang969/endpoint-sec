import SwiftUI
import Charts

struct StatusPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                
                // ----------------------------------------------------
                // 统计卡片模块
                // ----------------------------------------------------
                VStack(alignment: .leading, spacing: 8) {
                    Text("拦截统计")
                        .font(.headline)
                    
                    HStack {
                        StatBox(title: "总计拦截", value: "\(viewModel.records.count)", color: .orange)
                        StatBox(title: "删除 (DELETE)", value: "\(viewModel.records.filter{$0.op == "unlink"}.count)", color: .red)
                        StatBox(title: "移动 (MOVE)", value: "\(viewModel.records.filter{$0.op == "rename"}.count)", color: .blue)
                    }
                }
                .padding(.horizontal)
                
                Divider()
                
                // ----------------------------------------------------
                // 最新拦截模块 - 最重要，放中间
                // ----------------------------------------------------
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("最新拦截记录")
                            .font(.headline)
                        Spacer()
                        
                        if let lastRecord = viewModel.records.first {
                            // "复制给 AI" 按钮
                            Button(action: {
                                let action = lastRecord.op == "unlink" ? "DELETE" : "MOVE"
                                let prompt = """
                                【系统拦截警报 (ES Guard)】
                                刚才我尝试让您执行的文件操作被 macOS 内核安全策略阻止：
                                • 操作类型: \(action)
                                • 目标文件: `\(lastRecord.path)`
                                • 发起进程: \(lastRecord.ancestor)
                                
                                该目录属于「受保护安全区」。请重新评估是否确实需要\(action)该文件。如果确有必要，请告诉我，我会为您进行临时放行。
                                """
                                let pasteboard = NSPasteboard.general
                                pasteboard.clearContents()
                                pasteboard.setString(prompt, forType: .string)
                            }) {
                                Label("复制指令给AI", systemImage: "doc.on.clipboard")
                                    .font(.caption)
                            }
                            .buttonStyle(.plain)
                            .foregroundColor(.blue)
                            .help("一键生成喂给 AI Agent 的报错提示词")
                        }
                    }
                    
                    if let lastRecord = viewModel.records.first {
                        HStack {
                            Text(lastRecord.op.uppercased())
                                .font(.system(.caption, design: .monospaced).bold())
                                .foregroundColor(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(lastRecord.op == "unlink" ? Color.red : Color.blue)
                                .cornerRadius(4)
                            
                            Text(lastRecord.process)
                                .font(.system(.caption, design: .monospaced))
                            
                            Text("来自 \(lastRecord.ancestor)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Text(URL(fileURLWithPath: lastRecord.path).lastPathComponent)
                            .font(.callout.bold())
                        
                        Text(lastRecord.path)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        
                        HStack {
                            let date = Date(timeIntervalSince1970: TimeInterval(lastRecord.ts))
                            Text(date.formatted(date: .omitted, time: .standard))
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            Spacer()
                            
                            Button(action: {
                                viewModel.requestOverride(for: lastRecord.path)
                            }) {
                                Text("临时放行此文件 (3分钟)")
                                    .bold()
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.orange)
                        }
                        .padding(.top, 4)
                    } else {
                        Text("近期暂无拦截记录。")
                            .foregroundColor(.secondary)
                            .padding()
                    }
                    
                    if !viewModel.overrideMessage.isEmpty {
                        Text(viewModel.overrideMessage)
                            .font(.caption)
                            .foregroundColor(viewModel.overrideSuccess ? .green : .red)
                            .padding(.top, 4)
                    }
                }
                .padding(.horizontal)
                
                Divider()
                
                // ----------------------------------------------------
                // 数据图表模块
                // ----------------------------------------------------
                VStack(alignment: .leading, spacing: 8) {
                    Text("AI Agent 行为画像")
                        .font(.headline)
                    
                    if viewModel.agentStats.isEmpty {
                        Text("没有足够的数据来生成图表")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .padding()
                    } else {
                        // 使用 SwiftUI Charts 绘制横向条形图
                        Chart(viewModel.agentStats) { stat in
                            // 删除操作 (红色)
                            BarMark(
                                x: .value("Count", stat.deleteCount),
                                y: .value("Agent", stat.agentName)
                            )
                            .foregroundStyle(.red)
                            .annotation(position: .overlay, alignment: .center) {
                                if stat.deleteCount > 0 {
                                    Text("\(stat.deleteCount)")
                                        .font(.system(size: 9))
                                        .foregroundColor(.white)
                                }
                            }
                            
                            // 移动操作 (蓝色)
                            BarMark(
                                x: .value("Count", stat.moveCount),
                                y: .value("Agent", stat.agentName)
                            )
                            .foregroundStyle(.blue)
                            .annotation(position: .overlay, alignment: .center) {
                                if stat.moveCount > 0 {
                                    Text("\(stat.moveCount)")
                                        .font(.system(size: 9))
                                        .foregroundColor(.white)
                                }
                            }
                        }
                        .chartLegend(.hidden)
                        // 让图表高度跟随 Agent 数量自适应
                        .frame(height: max(CGFloat(viewModel.agentStats.count * 30), 80))
                        .padding(.top, 4)
                        
                        // 图例
                        HStack {
                            Circle().fill(Color.red).frame(width: 6, height: 6)
                            Text("尝试删除").font(.system(size: 10)).foregroundColor(.secondary)
                            Circle().fill(Color.blue).frame(width: 6, height: 6)
                            Text("尝试移动").font(.system(size: 10)).foregroundColor(.secondary)
                        }
                    }
                }
                .padding(.horizontal)
                
                Spacer()
            }
            .padding(.top, 8)
        }
    }
}

struct StatBox: View {
    let title: String
    let value: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading) {
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.title2.bold())
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(6)
    }
}
