import Foundation
import SwiftUI
import Combine

private struct ProcessExecutionResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

private struct RecordsSnapshot {
    let totalIntercepts: Int
    let totalDeletes: Int
    let totalMoves: Int
    let records: [DenialRecord]
    let agentStats: [AgentStats]
}

private func runProcessSync(
    launchPath: String,
    arguments: [String],
    currentDirectory: String? = nil,
    environment: [String: String]? = nil
) -> ProcessExecutionResult? {
    let task = Process()
    task.launchPath = launchPath
    task.arguments = arguments
    if let currentDirectory {
        task.currentDirectoryURL = URL(fileURLWithPath: currentDirectory)
    }
    if let environment {
        var merged = ProcessInfo.processInfo.environment
        for (key, value) in environment {
            merged[key] = value
        }
        task.environment = merged
    }

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    task.standardOutput = stdoutPipe
    task.standardError = stderrPipe

    do {
        try task.run()
        task.waitUntilExit()
    } catch {
        return nil
    }

    let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
    let stdout = String(data: stdoutData, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let stderr = String(data: stderrData, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

    return ProcessExecutionResult(
        status: task.terminationStatus,
        stdout: stdout,
        stderr: stderr
    )
}

private func parseDenialsSnapshot(from data: Data) -> RecordsSnapshot {
    let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
    let decoder = JSONDecoder()
    var allParsed: [DenialRecord] = []
    allParsed.reserveCapacity(lines.count)

    var deletes = 0
    var moves = 0
    var statsDict: [String: (del: Int, mov: Int)] = [:]

    for line in lines {
        guard let lineData = String(line).data(using: .utf8),
              let record = try? decoder.decode(DenialRecord.self, from: lineData) else {
            continue
        }

        allParsed.append(record)
        let key = record.ancestor
        let current = statsDict[key] ?? (0, 0)
        if record.op == "unlink" {
            deletes += 1
            statsDict[key] = (current.del + 1, current.mov)
        } else if record.op == "rename" {
            moves += 1
            statsDict[key] = (current.del, current.mov + 1)
        }
    }

    let uiRecords = Array(allParsed.reversed().prefix(500))
    let agentStats = statsDict.map { key, value in
        AgentStats(agentName: key, deleteCount: value.del, moveCount: value.mov)
    }.sorted(by: { $0.total > $1.total })

    return RecordsSnapshot(
        totalIntercepts: allParsed.count,
        totalDeletes: deletes,
        totalMoves: moves,
        records: uiRecords,
        agentStats: agentStats
    )
}

private func shellQuote(_ value: String) -> String {
    if value.isEmpty {
        return "''"
    }
    let escaped = value.replacingOccurrences(of: "'", with: "'\"'\"'")
    return "'\(escaped)'"
}

private func escapeForAppleScript(_ value: String) -> String {
    value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
}

private func runPrivilegedShellSync(command: String) -> ProcessExecutionResult? {
    let appleScriptCommand = "do shell script \"\(escapeForAppleScript(command))\" with administrator privileges"
    return runProcessSync(
        launchPath: "/usr/bin/osascript",
        arguments: ["-e", appleScriptCommand]
    )
}

private func bestProcessDetail(_ result: ProcessExecutionResult?) -> String {
    if let result {
        if !result.stderr.isEmpty { return result.stderr }
        if !result.stdout.isEmpty { return result.stdout }
    }
    return ""
}

private func isPermissionDeniedMessage(_ message: String) -> Bool {
    let lowered = message.lowercased()
    return lowered.contains("operation not permitted")
        || lowered.contains("not permitted")
        || lowered.contains("could not enable service")
        || lowered.contains("could not disable service")
        || lowered.contains("boot-out failed: 1")
        || lowered.contains("try re-running the command as root")
        || lowered.contains("requires administrator privileges")
}

private func isUserCanceledMessage(_ message: String) -> Bool {
    let lowered = message.lowercased()
    return lowered.contains("user canceled")
        || lowered.contains("user cancelled")
        || lowered.contains("execution error: -128")
        || lowered.contains("cancel")
}

private func shouldRetryLaunchctlWithPrivilege(
    _ result: ProcessExecutionResult?,
    arguments: [String]
) -> Bool {
    guard let result else { return true }
    guard result.status != 0 else { return false }
    let detail = bestProcessDetail(result)
    if isPermissionDeniedMessage(detail) {
        return true
    }

    let lowered = detail.lowercased()
    let targetsSystemDomain = arguments.contains("system")
        || arguments.contains(where: { $0.hasPrefix("system/") })

    if targetsSystemDomain && lowered.contains("input/output error") {
        return true
    }

    return false
}

private func runLaunchctlCommand(arguments: [String]) -> (result: ProcessExecutionResult?, usedPrivilege: Bool) {
    let direct = runProcessSync(launchPath: "/bin/launchctl", arguments: arguments)
    guard shouldRetryLaunchctlWithPrivilege(direct, arguments: arguments) else {
        return (direct, false)
    }

    let shellCommand = (["/bin/launchctl"] + arguments).map(shellQuote).joined(separator: " ")
    let privileged = runPrivilegedShellSync(command: shellCommand)
    return (privileged ?? direct, true)
}

private func trimTrailingSlashes(_ path: String) -> String {
    if path == "/" { return "/" }
    var normalized = path
    while normalized.hasSuffix("/") {
        normalized.removeLast()
    }
    return normalized.isEmpty ? "/" : normalized
}

private func pathPrefixMatch(_ path: String, prefix: String) -> Bool {
    let normalizedPath = trimTrailingSlashes(path)
    let normalizedPrefix = trimTrailingSlashes(prefix)

    guard normalizedPrefix.hasPrefix("/") else { return false }
    if normalizedPrefix == "/" {
        return normalizedPath.hasPrefix("/")
    }
    return normalizedPath == normalizedPrefix || normalizedPath.hasPrefix(normalizedPrefix + "/")
}

private func homeDigitRoot(path: String, home: String) -> String? {
    let normalizedPath = trimTrailingSlashes(path)
    let normalizedHome = trimTrailingSlashes(home)
    let homePrefix = normalizedHome + "/"
    guard normalizedPath.hasPrefix(homePrefix) else { return nil }

    let suffix = String(normalizedPath.dropFirst(homePrefix.count))
    guard let firstComponent = suffix.split(separator: "/").first, !firstComponent.isEmpty else { return nil }
    guard firstComponent.first?.isNumber == true else { return nil }
    return normalizedHome + "/" + String(firstComponent)
}

private func acquireDirectoryLock(path: String, retries: Int = 100, sleepMs: UInt32 = 50) -> URL? {
    let lockURL = URL(fileURLWithPath: path)
    for _ in 0..<max(retries, 1) {
        do {
            try FileManager.default.createDirectory(
                at: lockURL,
                withIntermediateDirectories: false
            )
            return lockURL
        } catch {
            usleep(sleepMs * 1_000)
        }
    }
    return nil
}

private func releaseDirectoryLock(_ lockURL: URL?) {
    guard let lockURL else { return }
    try? FileManager.default.removeItem(at: lockURL)
}

private func readPolicyFile(path: String) throws -> SecurityPolicy {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    return try JSONDecoder().decode(SecurityPolicy.self, from: data)
}

private func writePolicyFile(_ policy: SecurityPolicy, path: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(policy)
    try data.write(to: URL(fileURLWithPath: path), options: .atomic)
}

@MainActor
final class ESGuardViewModel: ObservableObject {
    @Published var guardRunning: Bool = false
    @Published var records: [DenialRecord] = [] // UI 列表使用，只保留最新的 500 条
    @Published var policy: SecurityPolicy = .empty
    @Published var lastDenial: String = "暂无最新拦截记录"
    @Published var overrideMessage: String = ""
    @Published var overrideSuccess: Bool = false
    @Published var daemonActionInProgress: Bool = false
    @Published var logLines: [LogLine] = []
    
    // 全局真实统计数据 (不限于内存里的前 N 条)
    @Published var totalIntercepts: Int = 0
    @Published var totalDeletes: Int = 0
    @Published var totalMoves: Int = 0
    @Published var agentStats: [AgentStats] = []
    
    // 偏好设置
    @AppStorage("autoRevokeMinutes") var autoRevokeMinutes: Int = 3
    @AppStorage("lastAcknowledgedRecordId") var lastAcknowledgedRecordId: String = ""
    
    var hasUnacknowledgedRecords: Bool {
        guard let first = records.first else { return false }
        return first.id != lastAcknowledgedRecordId
    }
    
    // File paths
    private let homeDir = FileManager.default.homeDirectoryForCurrentUser.path
    var policyPath: String { "\(homeDir)/.codex/es_policy.json" }
    private var policyLockPath: String { "\(policyPath).lock" }
    private var denialsPath: String { "\(homeDir)/.codex/es-guard/denials.jsonl" }
    private var lastDenialPath: String { "\(homeDir)/.codex/es-guard/last_denial.txt" }
    private let logPath = "/tmp/codex-es-guard.log"
    private let daemonServiceTarget = "system/dev.codex-es-guard"
    private let daemonPlistPath = "/Library/LaunchDaemons/dev.codex-es-guard.plist"
    
    // Services
    private let fileMonitor = FileMonitorService()
    private let logTailer = LogTailService()
    
    private var previousRecordCount: Int = 0
    private var isFirstLoad: Bool = true
    private var recordsLoadToken: UInt64 = 0

    init() {
        if autoRevokeMinutes <= 0 {
            autoRevokeMinutes = 3
        }
        refresh()
        setupWatchers()
    }
    
    deinit {
        fileMonitor.stopAll()
        logTailer.stopTailing()
    }
    
    func refresh() {
        checkGuardRunning()
        loadRecords()
        loadPolicy()
        loadLastDenial()
    }
    
    func acknowledgeRecords() {
        if let first = records.first {
            lastAcknowledgedRecordId = first.id
        }
    }
    
    private func checkGuardRunning() {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runProcessSync(
                launchPath: "/usr/bin/pgrep",
                arguments: ["-x", "codex-es-guard"]
            )
            let running = (result?.status == 0)
            DispatchQueue.main.async { [weak self] in
                self?.guardRunning = running
            }
        }
    }

    var lastDeniedPath: String? {
        let lines = lastDenial.split(separator: "\n")
        if let pathLine = lines.first(where: { $0.hasPrefix("Path: ") }) {
            let raw = String(pathLine).replacingOccurrences(of: "Path: ", with: "")
            let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            return cleaned.isEmpty ? nil : cleaned
        }
        return nil
    }

    private func presentMessage(_ message: String, success: Bool, clearAfter seconds: TimeInterval = 4.0) {
        self.overrideMessage = message
        self.overrideSuccess = success
        if seconds > 0 {
            DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
                self.overrideMessage = ""
            }
        }
    }

    private func refreshGuardRunningAfterDelay(_ delay: TimeInterval = 0.25) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            self.checkGuardRunning()
        }
    }

    func startDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        let serviceTarget = daemonServiceTarget
        let plistPath = daemonPlistPath

        DispatchQueue.global(qos: .userInitiated).async {
            let enableResult = runLaunchctlCommand(arguments: ["enable", serviceTarget])
            let kickResult = runLaunchctlCommand(arguments: ["kickstart", "-k", serviceTarget])

            var usedPrivilege = enableResult.usedPrivilege || kickResult.usedPrivilege
            var started = (kickResult.result?.status == 0)
            var details = bestProcessDetail(kickResult.result)

            if !started, FileManager.default.fileExists(atPath: plistPath) {
                let bootstrapResult = runLaunchctlCommand(arguments: ["bootstrap", "system", plistPath])
                let retryKickResult = runLaunchctlCommand(arguments: ["kickstart", "-k", serviceTarget])
                usedPrivilege = usedPrivilege || bootstrapResult.usedPrivilege || retryKickResult.usedPrivilege
                started = (retryKickResult.result?.status == 0)
                let retryDetail = bestProcessDetail(retryKickResult.result)
                if !retryDetail.isEmpty {
                    details = retryDetail
                } else {
                    let bootstrapDetail = bestProcessDetail(bootstrapResult.result)
                    if !bootstrapDetail.isEmpty {
                        details = bootstrapDetail
                    }
                }
            }

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.daemonActionInProgress = false
                self.refreshGuardRunningAfterDelay()
                if started {
                    if usedPrivilege {
                        self.presentMessage("守护进程已请求启动（已完成管理员授权）", success: true)
                    } else {
                        self.presentMessage("守护进程已请求启动", success: true)
                    }
                } else if details.lowercased().contains("could not find service") {
                    self.presentMessage(
                        "启动失败：系统中未加载 dev.codex-es-guard，请先执行 nix switch/make 再试",
                        success: false,
                        clearAfter: 7.0
                    )
                } else if isUserCanceledMessage(details) {
                    self.presentMessage("启动已取消：未完成管理员授权", success: false, clearAfter: 6.0)
                } else if details.isEmpty {
                    self.presentMessage("启动失败，请检查 launchctl 权限或守护配置", success: false, clearAfter: 6.0)
                } else {
                    self.presentMessage("启动失败: \(details)", success: false, clearAfter: 6.0)
                }
            }
        }
    }

    func stopDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        let serviceTarget = daemonServiceTarget

        DispatchQueue.global(qos: .userInitiated).async {
            let disableResult = runLaunchctlCommand(arguments: ["disable", serviceTarget])
            let bootoutResult = runLaunchctlCommand(arguments: ["bootout", serviceTarget])

            let usedPrivilege = disableResult.usedPrivilege || bootoutResult.usedPrivilege
            let details = bestProcessDetail(bootoutResult.result)
            let likelyAlreadyStopped = details.contains("No such process")
                || details.contains("not found")
                || details.contains("No such file or directory")
            let stopped = (bootoutResult.result?.status == 0) || likelyAlreadyStopped

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.daemonActionInProgress = false
                self.refreshGuardRunningAfterDelay()
                if stopped {
                    if usedPrivilege {
                        self.presentMessage("守护进程已请求停止（已完成管理员授权）", success: true)
                    } else {
                        self.presentMessage("守护进程已请求停止", success: true)
                    }
                } else if isUserCanceledMessage(details) {
                    self.presentMessage("停止已取消：未完成管理员授权", success: false, clearAfter: 6.0)
                } else if isPermissionDeniedMessage(details) {
                    self.presentMessage("停止失败：需要管理员权限，请在弹窗中授权", success: false, clearAfter: 6.0)
                } else if details.isEmpty {
                    self.presentMessage("停止失败，请检查 launchctl 权限或守护配置", success: false, clearAfter: 6.0)
                } else {
                    self.presentMessage("停止失败: \(details)", success: false, clearAfter: 6.0)
                }
            }
        }
    }
    
    func restartDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        let serviceTarget = daemonServiceTarget

        DispatchQueue.global(qos: .userInitiated).async {
            let kickResult = runLaunchctlCommand(arguments: ["kickstart", "-k", serviceTarget])

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.daemonActionInProgress = false
                self.refreshGuardRunningAfterDelay()
                if kickResult.result?.status == 0 {
                    if kickResult.usedPrivilege {
                        self.presentMessage("守护进程已成功重启（已完成管理员授权）", success: true)
                    } else {
                        self.presentMessage("守护进程已成功重启", success: true)
                    }
                } else {
                    let detail = bestProcessDetail(kickResult.result)
                    if isUserCanceledMessage(detail) {
                        self.presentMessage("重启已取消：未完成管理员授权", success: false, clearAfter: 6.0)
                    } else if detail.isEmpty {
                        self.presentMessage("重启失败，可能存在权限或配置问题", success: false, clearAfter: 6.0)
                    } else {
                        self.presentMessage("重启失败: \(detail)", success: false, clearAfter: 6.0)
                    }
                }
            }
        }
    }
    
    private func setupWatchers() {
        fileMonitor.watch(path: policyPath) { [weak self] in
            Task { @MainActor in self?.loadPolicy() }
        }
        
        fileMonitor.watch(path: denialsPath) { [weak self] in
            Task { @MainActor in self?.loadRecords() }
        }
        
        fileMonitor.watch(path: lastDenialPath) { [weak self] in
            Task { @MainActor in self?.loadLastDenial() }
        }
        
        logTailer.startTailing(path: logPath) { [weak self] newLines in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.logLines.append(contentsOf: newLines)
                if self.logLines.count > 200 {
                    self.logLines.removeFirst(self.logLines.count - 200)
                }
            }
        }
    }
    
    private func loadRecords() {
        recordsLoadToken += 1
        let token = recordsLoadToken
        let path = denialsPath

        DispatchQueue.global(qos: .utility).async {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    guard token == self.recordsLoadToken else { return }
                    self.records = []
                    self.agentStats = []
                    self.totalIntercepts = 0
                    self.totalDeletes = 0
                    self.totalMoves = 0
                    self.previousRecordCount = 0
                    self.isFirstLoad = false
                }
                return
            }

            let snapshot = parseDenialsSnapshot(from: data)
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                guard token == self.recordsLoadToken else { return }

                if !self.isFirstLoad && snapshot.totalIntercepts > self.previousRecordCount,
                   let newest = snapshot.records.first {
                    NotificationService.shared.sendDenialNotification(for: newest)
                }

                self.previousRecordCount = snapshot.totalIntercepts
                self.records = snapshot.records
                self.totalIntercepts = snapshot.totalIntercepts
                self.totalDeletes = snapshot.totalDeletes
                self.totalMoves = snapshot.totalMoves
                self.agentStats = snapshot.agentStats
                self.isFirstLoad = false
            }
        }
    }
    
    private func loadPolicy() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: policyPath)),
              let policy = try? JSONDecoder().decode(SecurityPolicy.self, from: data) else {
            self.policy = .empty
            return
        }
        self.policy = policy
    }
    
    private func loadLastDenial() {
        if let text = try? String(contentsOfFile: lastDenialPath, encoding: .utf8), !text.isEmpty {
            self.lastDenial = text.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            self.lastDenial = "暂无最新拦截记录"
        }
    }

    private func normalizedAbsolutePath(from rawPath: String) -> String? {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let expanded = NSString(string: trimmed).expandingTildeInPath
        let normalized = URL(fileURLWithPath: expanded).standardizedFileURL.path
        return normalized.hasPrefix("/") ? normalized : nil
    }

    private func isInProtectedZone(_ path: String) -> Bool {
        if policy.protectedZones.contains(where: { pathPrefixMatch(path, prefix: $0) }) {
            return true
        }
        return (policy.autoProtectHomeDigitChildren ?? true)
            && homeDigitRoot(path: path, home: homeDir) != nil
    }

    private func isDangerousBroadPath(_ path: String) -> Bool {
        let normalized = trimTrailingSlashes(path)
        let home = trimTrailingSlashes(homeDir)
        if normalized == "/" || normalized == home {
            return true
        }
        if policy.protectedZones.contains(where: { trimTrailingSlashes($0) == normalized }) {
            return true
        }
        if (policy.autoProtectHomeDigitChildren ?? true),
           let autoRoot = homeDigitRoot(path: normalized, home: home),
           trimTrailingSlashes(autoRoot) == normalized {
            return true
        }
        return false
    }

    private func mutatePolicyOnDisk(
        successMessage: String? = nil,
        successClearAfter: TimeInterval = 4.0,
        mutation: @escaping (inout SecurityPolicy) -> Void
    ) {
        let policyPath = self.policyPath
        let lockPath = self.policyLockPath
        let fallbackPolicy = self.policy

        DispatchQueue.global(qos: .userInitiated).async {
            guard let lockURL = acquireDirectoryLock(path: lockPath) else {
                DispatchQueue.main.async { [weak self] in
                    self?.presentMessage("策略文件正被占用，请稍后重试", success: false, clearAfter: 6.0)
                }
                return
            }
            defer { releaseDirectoryLock(lockURL) }

            var updatedPolicy = (try? readPolicyFile(path: policyPath)) ?? fallbackPolicy
            mutation(&updatedPolicy)

            do {
                try writePolicyFile(updatedPolicy, path: policyPath)
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.policy = updatedPolicy
                    if let successMessage {
                        self.presentMessage(successMessage, success: true, clearAfter: successClearAfter)
                    }
                }
            } catch {
                DispatchQueue.main.async { [weak self] in
                    self?.presentMessage(
                        "更新策略文件失败: \(error.localizedDescription)",
                        success: false,
                        clearAfter: 6.0
                    )
                }
            }
        }
    }
    
    func requestOverride(for path: String) {
        guard let cleanPath = normalizedAbsolutePath(from: path) else {
            presentMessage("放行失败：路径必须是绝对路径", success: false, clearAfter: 6.0)
            return
        }
        guard isInProtectedZone(cleanPath) else {
            presentMessage("放行失败：该路径不在受保护目录中，无需放行", success: false, clearAfter: 6.0)
            return
        }
        guard !isDangerousBroadPath(cleanPath) else {
            presentMessage("放行失败：禁止对根目录/家目录/保护目录根做整段放行", success: false, clearAfter: 7.0)
            return
        }

        let revokeMinutes = autoRevokeMinutes
        guard revokeMinutes > 0 else {
            presentMessage("放行失败：已禁用不过期放行，请选择 1-30 分钟", success: false, clearAfter: 7.0)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let env = ["ES_GUARD_OVERRIDE_MINUTES": "\(max(revokeMinutes, 1))"]
            let result = runProcessSync(
                launchPath: "/usr/local/bin/es-guard-override",
                arguments: [cleanPath],
                environment: env
            )
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                if let result, result.status == 0 {
                    self.presentMessage(
                        "成功将 \(URL(fileURLWithPath: cleanPath).lastPathComponent) 设为临时放行（\(revokeMinutes) 分钟）",
                        success: true
                    )
                    self.refresh()
                    return
                }

                if let result {
                    let detail = result.stderr.isEmpty ? result.stdout : result.stderr
                    if detail.isEmpty {
                        self.presentMessage("放行执行失败 (退出码: \(result.status))", success: false)
                    } else {
                        self.presentMessage("放行执行失败: \(detail)", success: false)
                    }
                } else {
                    self.presentMessage("放行程序调用出错，请检查 es-guard-override 是否可执行", success: false)
                }
            }
        }
    }

    func requestQuarantine(for path: String) {
        guard let cleanPath = normalizedAbsolutePath(from: path) else {
            presentMessage("隔离失败: 路径必须是绝对路径", success: false, clearAfter: 6.0)
            return
        }
        guard !isDangerousBroadPath(cleanPath) else {
            presentMessage("隔离失败: 目标过于宽泛，请选择具体文件或子目录", success: false, clearAfter: 6.0)
            return
        }

        let fileURL = URL(fileURLWithPath: cleanPath)
        let parentDir = fileURL.deletingLastPathComponent().path
        guard !parentDir.isEmpty else {
            presentMessage("隔离失败: 无法确定目标目录", success: false)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = runProcessSync(
                launchPath: "/usr/local/bin/es-guard-quarantine",
                arguments: [cleanPath],
                currentDirectory: parentDir
            )

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                if let result, result.status == 0 {
                    self.presentMessage(
                        "已将 \(fileURL.lastPathComponent) 隔离到 \(parentDir)/temp",
                        success: true,
                        clearAfter: 5.0
                    )
                    self.refresh()
                } else if let result {
                    let detail = result.stderr.isEmpty ? result.stdout : result.stderr
                    if detail.isEmpty {
                        self.presentMessage("隔离失败，请检查路径和权限", success: false, clearAfter: 6.0)
                    } else {
                        self.presentMessage("隔离失败: \(detail)", success: false, clearAfter: 6.0)
                    }
                } else {
                    self.presentMessage("隔离失败: 无法调用 es-guard-quarantine", success: false, clearAfter: 6.0)
                }
            }
        }
    }
    
    func removeOverride(path: String) {
        guard let cleanPath = normalizedAbsolutePath(from: path) else {
            presentMessage("撤销失败：路径无效", success: false, clearAfter: 6.0)
            return
        }
        submitOverrideCommand(
            arguments: ["--remove", cleanPath],
            successMessage: "已撤销临时放行：\(URL(fileURLWithPath: cleanPath).lastPathComponent)",
            failurePrefix: "撤销放行失败"
        )
    }
    
    func clearAllOverrides() {
        submitOverrideCommand(
            arguments: ["--clear"],
            successMessage: "已清空全部临时放行路径",
            failurePrefix: "清空放行失败",
            clearAfter: 3.0
        )
    }

    private func submitOverrideCommand(
        arguments: [String],
        successMessage: String,
        failurePrefix: String,
        clearAfter: TimeInterval = 5.0
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runProcessSync(
                launchPath: "/usr/local/bin/es-guard-override",
                arguments: arguments
            )
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                if let result, result.status == 0 {
                    self.presentMessage(successMessage, success: true, clearAfter: clearAfter)
                    self.refresh()
                    return
                }
                if let result {
                    let detail = result.stderr.isEmpty ? result.stdout : result.stderr
                    if detail.isEmpty {
                        self.presentMessage("\(failurePrefix) (退出码: \(result.status))", success: false, clearAfter: 6.0)
                    } else {
                        self.presentMessage("\(failurePrefix): \(detail)", success: false, clearAfter: 6.0)
                    }
                } else {
                    self.presentMessage("\(failurePrefix)：无法调用 es-guard-override", success: false, clearAfter: 6.0)
                }
            }
        }
    }

    func updateAllowTrustedToolsInAIContext(_ enabled: Bool) {
        mutatePolicyOnDisk(
            successMessage: enabled
                ? "已开启兼容模式：AI 上下文可按 trusted_tools 放行（风险更高）"
                : "已关闭兼容模式：AI 上下文将严格拦截（推荐）",
            successClearAfter: 6.0
        ) {
            $0.allowTrustedToolsInAIContext = enabled
        }
    }

    func updateAllowVCSMetadataInAIContext(_ enabled: Bool) {
        mutatePolicyOnDisk(
            successMessage: enabled
                ? "已允许 AI 维护 .git/.jj 元数据（推荐，仍会拦截 git rm 工作区文件）"
                : "已关闭 AI 的 .git/.jj 元数据放行（更严格，但可能影响 AI 执行 git commit）",
            successClearAfter: 6.0
        ) {
            $0.allowVCSMetadataInAIContext = enabled
        }
    }

    func updateAutoProtectHomeDigitChildren(_ enabled: Bool) {
        mutatePolicyOnDisk(
            successMessage: enabled
                ? "已开启：HOME 下数字前缀目录（如 01-agent/0x-lab）自动受保护"
                : "已关闭：仅按 protected_zones 目录匹配（边界匹配）",
            successClearAfter: 6.0
        ) {
            $0.autoProtectHomeDigitChildren = enabled
        }
    }
}
