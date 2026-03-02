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
                        StatBox(title: "总计拦截", value: "\(viewModel.totalIntercepts)", color: ApplePalette.warning)
                        StatBox(title: "删除 (DELETE)", value: "\(viewModel.totalDeletes)", color: ApplePalette.danger)
                        StatBox(title: "移动 (MOVE)", value: "\(viewModel.totalMoves)", color: ApplePalette.info)
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
                                
                                该目录属于「受保护安全区」。请重新评估是否确实需要\(action)该文件。建议先执行隔离（移动到 ./temp），仅在必须永久删除时再申请临时放行。
                                """
                                let pasteboard = NSPasteboard.general
                                pasteboard.clearContents()
                                pasteboard.setString(prompt, forType: .string)
                            }) {
                                Label("复制指令给AI", systemImage: "doc.on.clipboard")
                                    .font(.caption)
                            }
                            .buttonStyle(.plain)
                            .foregroundColor(ApplePalette.accent)
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
                                .background(lastRecord.op == "unlink" ? ApplePalette.danger : ApplePalette.info)
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
                                viewModel.requestQuarantine(for: lastRecord.path)
                            }) {
                                Text("先隔离到 temp")
                                    .bold()
                            }
                            .buttonStyle(.bordered)

                            Button(action: {
                                viewModel.requestOverride(for: lastRecord.path)
                            }) {
                                Text(
                                    viewModel.autoRevokeMinutes > 0
                                        ? "临时放行此文件 (\(viewModel.autoRevokeMinutes)分钟)"
                                        : "放行此文件（不过期，危险）"
                                )
                                    .bold()
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(ApplePalette.warning)
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
                            .foregroundColor(viewModel.overrideSuccess ? ApplePalette.success : ApplePalette.danger)
                            .padding(.top, 4)
                    }
                }
                .padding(.horizontal)
                
                Divider()

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("拦截反馈 (last_denial.txt)")
                            .font(.headline)
                        Spacer()
                        if let feedbackPath = viewModel.lastDeniedPath {
                            Button("隔离该文件") {
                                viewModel.requestQuarantine(for: feedbackPath)
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(ApplePalette.warning)
                        }
                    }

                    Text(viewModel.lastDenial)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(10)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(ApplePalette.panelBackground)
                        .cornerRadius(6)
                }
                .padding(.horizontal)

                Divider()
                
                // ----------------------------------------------------
                // 数据图表模块
                // ----------------------------------------------------
                VStack(alignment: .leading, spacing: 8) {
                    Text("AI Agent 行为画像 (全局)")
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
                            .foregroundStyle(ApplePalette.danger)
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
                            .foregroundStyle(ApplePalette.info)
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
                            Circle().fill(ApplePalette.danger).frame(width: 6, height: 6)
                            Text("尝试删除").font(.system(size: 10)).foregroundColor(.secondary)
                            Circle().fill(ApplePalette.info).frame(width: 6, height: 6)
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
        .background(ApplePalette.panelBackground)
        .cornerRadius(6)
    }
}
