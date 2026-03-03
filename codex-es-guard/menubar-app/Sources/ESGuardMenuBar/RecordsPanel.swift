import SwiftUI
import AppKit

private enum RecordFilter: String, CaseIterable, Identifiable {
    case all
    case delete
    case move
    case sensitiveRead
    case sensitiveTransfer
    case taintWrite
    case execExfil

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all:
            return "全部"
        case .delete:
            return "仅删除 (DELETE)"
        case .move:
            return "仅移动 (MOVE)"
        case .sensitiveRead:
            return "敏感读取"
        case .sensitiveTransfer:
            return "敏感外传"
        case .taintWrite:
            return "污点写出"
        case .execExfil:
            return "外传执行"
        }
    }
}

struct RecordsPanel: View {
    @ObservedObject var viewModel: ESGuardViewModel
    @State private var filterOp: RecordFilter = .all
    @State private var searchText: String = ""

    var filteredRecords: [DenialRecord] {
        var result = viewModel.records

        if filterOp != .all {
            result = result.filter(matchesFilter)
        }

        if !searchText.isEmpty {
            let lowerSearch = searchText.lowercased()
            result = result.filter { record in
                record.path.lowercased().contains(lowerSearch)
                || (record.dest?.lowercased().contains(lowerSearch) ?? false)
                || record.zone.lowercased().contains(lowerSearch)
                || record.ancestor.lowercased().contains(lowerSearch)
                || record.process.lowercased().contains(lowerSearch)
                || record.op.lowercased().contains(lowerSearch)
                || record.reason.lowercased().contains(lowerSearch)
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
                    ForEach(RecordFilter.allCases) { filter in
                        Text(filter.title).tag(filter)
                    }
                }
                .pickerStyle(MenuPickerStyle())
                .frame(width: 190)
            }
            .padding(.horizontal)
            .padding(.bottom, 8)

            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("搜索路径、原因码、进程或 Agent...", text: $searchText)
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
            .background(ApplePalette.panelBackground)
            .cornerRadius(6)
            .padding(.horizontal)
            .padding(.bottom, 8)

            if filteredRecords.isEmpty {
                VStack {
                    Spacer()
                    Image(systemName: "shield.checkmark.fill")
                        .font(.largeTitle)
                        .foregroundColor(ApplePalette.success)
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

    private func matchesFilter(_ record: DenialRecord) -> Bool {
        switch filterOp {
        case .all:
            return true
        case .delete:
            return record.op == "unlink"
        case .move:
            return record.op == "rename"
        case .sensitiveRead:
            return record.reason == "SENSITIVE_READ_NON_AI"
        case .sensitiveTransfer:
            return record.reason == "SENSITIVE_TRANSFER_OUT"
        case .taintWrite:
            return record.reason == "TAINT_WRITE_OUT"
        case .execExfil:
            return record.reason == "EXEC_EXFIL_TOOL"
        }
    }
}

private struct BadgeVisual {
    let text: String
    let tint: Color
    let fill: Color
}

struct RecordRow: View {
    let record: DenialRecord
    @ObservedObject var viewModel: ESGuardViewModel

    private func getAgentColor(for name: String) -> Color {
        let nameLower = name.lowercased()
        if nameLower.contains("codex") {
            return .indigo
        } else if nameLower.contains("claude") {
            return ApplePalette.warning
        } else if nameLower.contains("copilot") {
            return .teal
        } else {
            return .secondary
        }
    }

    private func operationBadge(for op: String) -> BadgeVisual {
        switch op {
        case "unlink":
            return BadgeVisual(text: "DELETE", tint: ApplePalette.danger, fill: ApplePalette.subtleDanger)
        case "rename":
            return BadgeVisual(text: "MOVE", tint: ApplePalette.info, fill: ApplePalette.subtleInfo)
        case "open":
            return BadgeVisual(text: "OPEN", tint: .purple, fill: Color.purple.opacity(0.18))
        case "copyfile":
            return BadgeVisual(text: "COPY", tint: .blue, fill: Color.blue.opacity(0.18))
        case "clone":
            return BadgeVisual(text: "CLONE", tint: .blue, fill: Color.blue.opacity(0.18))
        case "link":
            return BadgeVisual(text: "LINK", tint: .blue, fill: Color.blue.opacity(0.18))
        case "exchangedata":
            return BadgeVisual(text: "EXCHANGE", tint: .blue, fill: Color.blue.opacity(0.18))
        case "create":
            return BadgeVisual(text: "CREATE", tint: .orange, fill: Color.orange.opacity(0.18))
        case "truncate":
            return BadgeVisual(text: "TRUNCATE", tint: .orange, fill: Color.orange.opacity(0.18))
        case "exec":
            return BadgeVisual(text: "EXEC", tint: .red, fill: Color.red.opacity(0.18))
        default:
            return BadgeVisual(text: op.uppercased(), tint: .secondary, fill: Color.secondary.opacity(0.18))
        }
    }

    private func reasonBadge(for reason: String) -> BadgeVisual {
        switch reason {
        case "SENSITIVE_READ_NON_AI":
            return BadgeVisual(text: "敏感读取", tint: .purple, fill: Color.purple.opacity(0.18))
        case "SENSITIVE_TRANSFER_OUT":
            return BadgeVisual(text: "敏感外传", tint: .blue, fill: Color.blue.opacity(0.18))
        case "TAINT_WRITE_OUT":
            return BadgeVisual(text: "污点写出", tint: .orange, fill: Color.orange.opacity(0.18))
        case "EXEC_EXFIL_TOOL":
            return BadgeVisual(text: "外传执行", tint: .red, fill: Color.red.opacity(0.18))
        case "PROTECTED_ZONE_AI_DELETE":
            return BadgeVisual(text: "保护区删除", tint: ApplePalette.danger, fill: ApplePalette.subtleDanger)
        default:
            return BadgeVisual(text: reason, tint: .secondary, fill: Color.secondary.opacity(0.18))
        }
    }

    var body: some View {
        let opBadge = operationBadge(for: record.op)
        let reasonBadge = reasonBadge(for: record.reason)
        let agentTint = getAgentColor(for: record.ancestor)

        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                TagBadge(text: opBadge.text, tint: opBadge.tint, fill: opBadge.fill)
                TagBadge(text: reasonBadge.text, tint: reasonBadge.tint, fill: reasonBadge.fill)

                Text(URL(fileURLWithPath: record.path).lastPathComponent)
                    .font(.callout.bold())

                Spacer()

                TagBadge(
                    text: record.ancestor,
                    tint: agentTint,
                    fill: agentTint.opacity(0.18)
                )
            }

            Text(record.path)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if let dest = record.dest, !dest.isEmpty {
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
                    .foregroundColor(.secondary)
                Spacer()
            }
        }
        .padding(.vertical, 4)
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
            Button("先隔离到 temp") {
                viewModel.requestQuarantine(for: record.path)
            }
            Button(
                viewModel.autoRevokeMinutes > 0
                    ? "临时放行此文件 (\(viewModel.autoRevokeMinutes)分钟)"
                    : "放行此文件（不过期，危险）"
            ) {
                viewModel.requestOverride(for: record.path)
            }
        }
    }
}
