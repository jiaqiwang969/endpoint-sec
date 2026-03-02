import Foundation
import SwiftUI
import Combine

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
    private var revokeTimers: [String: Timer] = [:]

    init() {
        refresh()
        setupWatchers()
    }
    
    deinit {
        fileMonitor.stopAll()
        logTailer.stopTailing()
        for timer in revokeTimers.values {
            timer.invalidate()
        }
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
        let task = Process()
        task.launchPath = "/usr/bin/pgrep"
        task.arguments = ["-x", "codex-es-guard"]
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            self.guardRunning = (task.terminationStatus == 0)
        } catch {
            self.guardRunning = false
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

    private func runProcess(
        launchPath: String,
        arguments: [String],
        currentDirectory: String? = nil
    ) -> (status: Int32, stdout: String, stderr: String)? {
        let task = Process()
        task.launchPath = launchPath
        task.arguments = arguments
        if let currentDirectory {
            task.currentDirectoryURL = URL(fileURLWithPath: currentDirectory)
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

        return (task.terminationStatus, stdout, stderr)
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

    private func refreshGuardRunningAfterDelay(_ delay: TimeInterval = 0.8) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            self.checkGuardRunning()
        }
    }

    func startDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        defer { daemonActionInProgress = false }

        _ = runProcess(launchPath: "/bin/launchctl", arguments: ["enable", daemonServiceTarget])
        let kick = runProcess(launchPath: "/bin/launchctl", arguments: ["kickstart", "-k", daemonServiceTarget])

        var started = (kick?.status == 0)
        var details = kick?.stderr ?? ""

        if !started, FileManager.default.fileExists(atPath: daemonPlistPath) {
            _ = runProcess(launchPath: "/bin/launchctl", arguments: ["bootstrap", "system", daemonPlistPath])
            let retryKick = runProcess(launchPath: "/bin/launchctl", arguments: ["kickstart", "-k", daemonServiceTarget])
            started = (retryKick?.status == 0)
            if let retryErr = retryKick?.stderr, !retryErr.isEmpty {
                details = retryErr
            }
        }

        refreshGuardRunningAfterDelay()
        if started {
            presentMessage("守护进程已请求启动", success: true)
        } else if details.isEmpty {
            presentMessage("启动失败，请检查 launchctl 权限或守护配置", success: false, clearAfter: 6.0)
        } else {
            presentMessage("启动失败: \(details)", success: false, clearAfter: 6.0)
        }
    }

    func stopDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        defer { daemonActionInProgress = false }

        _ = runProcess(launchPath: "/bin/launchctl", arguments: ["disable", daemonServiceTarget])
        let bootout = runProcess(launchPath: "/bin/launchctl", arguments: ["bootout", daemonServiceTarget])

        let stderr = bootout?.stderr ?? ""
        let likelyAlreadyStopped = stderr.contains("No such process")
            || stderr.contains("not found")
            || stderr.contains("No such file or directory")
        let stopped = (bootout?.status == 0) || likelyAlreadyStopped

        refreshGuardRunningAfterDelay()
        if stopped {
            presentMessage("守护进程已请求停止", success: true)
        } else if stderr.isEmpty {
            presentMessage("停止失败，请检查 launchctl 权限或守护配置", success: false, clearAfter: 6.0)
        } else {
            presentMessage("停止失败: \(stderr)", success: false, clearAfter: 6.0)
        }
    }
    
    func restartDaemon() {
        guard !daemonActionInProgress else { return }
        daemonActionInProgress = true
        defer { daemonActionInProgress = false }

        let kick = runProcess(launchPath: "/bin/launchctl", arguments: ["kickstart", "-k", daemonServiceTarget])
        refreshGuardRunningAfterDelay()
        if kick?.status == 0 {
            presentMessage("守护进程已成功重启", success: true)
        } else {
            let detail = kick?.stderr ?? ""
            if detail.isEmpty {
                presentMessage("重启失败，可能存在权限或配置问题", success: false, clearAfter: 6.0)
            } else {
                presentMessage("重启失败: \(detail)", success: false, clearAfter: 6.0)
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
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: denialsPath)) else {
            self.records = []
            self.agentStats = []
            self.totalIntercepts = 0
            self.totalDeletes = 0
            self.totalMoves = 0
            return
        }
        
        let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
        let decoder = JSONDecoder()
        
        // 我们完整遍历所有的行，用于统计真实的全局数据和图表
        var allParsed: [DenialRecord] = []
        
        for line in lines {
            guard let lineData = String(line).data(using: .utf8) else { continue }
            if let record = try? decoder.decode(DenialRecord.self, from: lineData) {
                allParsed.append(record)
            }
        }
        
        // 提取最新用于显示的列表，倒序，最多取前 500 条给 UI
        let reversedAll = Array(allParsed.reversed())
        let uiRecords = Array(reversedAll.prefix(500))
        
        // 发送通知逻辑：只根据最新状态判断
        if !isFirstLoad && allParsed.count > self.previousRecordCount && !uiRecords.isEmpty {
            if let newest = uiRecords.first {
                NotificationService.shared.sendDenialNotification(for: newest)
            }
        }
        
        self.previousRecordCount = allParsed.count
        self.records = uiRecords
        
        // 更新真实的全局统计数据
        self.totalIntercepts = allParsed.count
        var deletes = 0
        var moves = 0
        var statsDict: [String: (del: Int, mov: Int)] = [:]
        
        for r in allParsed {
            let key = r.ancestor
            let current = statsDict[key] ?? (0, 0)
            if r.op == "unlink" {
                deletes += 1
                statsDict[key] = (current.del + 1, current.mov)
            } else if r.op == "rename" {
                moves += 1
                statsDict[key] = (current.del, current.mov + 1)
            }
        }
        
        self.totalDeletes = deletes
        self.totalMoves = moves
        self.agentStats = statsDict.map { k, v in
            AgentStats(agentName: k, deleteCount: v.del, moveCount: v.mov)
        }.sorted(by: { $0.total > $1.total })
        
        self.isFirstLoad = false
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
    
    func requestOverride(for path: String) {
        let cleanPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanPath.isEmpty else { return }
        
        let task = Process()
        task.launchPath = "/usr/local/bin/es-guard-override"
        task.arguments = [cleanPath]
        
        do {
            try task.run()
            task.waitUntilExit()
            if task.terminationStatus == 0 {
                self.presentMessage("成功将 \(URL(fileURLWithPath: cleanPath).lastPathComponent) 设为临时放行", success: true)
                scheduleOverrideRevocation(for: cleanPath)
            } else {
                self.presentMessage("放行执行失败 (退出码: \(task.terminationStatus))", success: false)
            }
        } catch {
            self.presentMessage("放行程序调用出错: \(error.localizedDescription)", success: false)
        }
    }

    func requestQuarantine(for path: String) {
        let cleanPath = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanPath.isEmpty else { return }

        let fileURL = URL(fileURLWithPath: cleanPath)
        let parentDir = fileURL.deletingLastPathComponent().path
        guard !parentDir.isEmpty else {
            presentMessage("隔离失败: 无法确定目标目录", success: false)
            return
        }

        let result = runProcess(
            launchPath: "/usr/local/bin/es-guard-quarantine",
            arguments: [cleanPath],
            currentDirectory: parentDir
        )

        if let result, result.status == 0 {
            presentMessage(
                "已将 \(fileURL.lastPathComponent) 隔离到 \(parentDir)/temp",
                success: true,
                clearAfter: 5.0
            )
            refresh()
        } else if let result {
            let detail = result.stderr.isEmpty ? result.stdout : result.stderr
            if detail.isEmpty {
                presentMessage("隔离失败，请检查路径和权限", success: false, clearAfter: 6.0)
            } else {
                presentMessage("隔离失败: \(detail)", success: false, clearAfter: 6.0)
            }
        } else {
            presentMessage("隔离失败: 无法调用 es-guard-quarantine", success: false, clearAfter: 6.0)
        }
    }
    
    private func scheduleOverrideRevocation(for path: String) {
        revokeTimers[path]?.invalidate()
        if autoRevokeMinutes <= 0 { return }
        
        let duration = TimeInterval(autoRevokeMinutes * 60)
        let timer = Timer.scheduledTimer(withTimeInterval: duration, repeats: false) { [weak self] _ in
            Task { @MainActor in
                self?.removeOverride(path: path, autoRevoked: true)
                self?.revokeTimers.removeValue(forKey: path)
            }
        }
        revokeTimers[path] = timer
    }
    
    func removeOverride(path: String, autoRevoked: Bool = false) {
        var newPolicy = self.policy
        newPolicy.temporaryOverrides.removeAll(where: { $0 == path })
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let policyURL = URL(fileURLWithPath: policyPath)
        
        do {
            let data = try encoder.encode(newPolicy)
            try data.write(to: policyURL)
            self.policy = newPolicy
            
            if autoRevoked {
                self.presentMessage(
                    "安全提醒: \(URL(fileURLWithPath: path).lastPathComponent) 临时放行期已满，自动清理。",
                    success: true,
                    clearAfter: 5.0
                )
                NotificationService.shared.sendAutoRevokeNotification(path: path)
            }
            
        } catch {
            print("Failed to remove override: \(error)")
        }
    }
    
    func clearAllOverrides() {
        var newPolicy = self.policy
        newPolicy.temporaryOverrides = []
        
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        
        do {
            let data = try encoder.encode(newPolicy)
            try data.write(to: URL(fileURLWithPath: policyPath))
            self.presentMessage("已清除所有的临时放行路径", success: true, clearAfter: 3.0)
            
            for timer in revokeTimers.values {
                timer.invalidate()
            }
            revokeTimers.removeAll()
        } catch {
            self.presentMessage("更新策略文件失败: \(error.localizedDescription)", success: false)
        }
    }
}
