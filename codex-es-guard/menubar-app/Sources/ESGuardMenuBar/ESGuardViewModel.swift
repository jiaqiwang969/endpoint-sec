import Foundation
import SwiftUI
import Combine

@MainActor
final class ESGuardViewModel: ObservableObject {
    @Published var guardRunning: Bool = false
    @Published var records: [DenialRecord] = []
    @Published var policy: SecurityPolicy = .empty
    @Published var lastDenial: String = "暂无最新拦截记录"
    @Published var overrideMessage: String = ""
    @Published var overrideSuccess: Bool = false
    @Published var logLines: [LogLine] = []
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
    
    func restartDaemon() {
        let task = Process()
        task.launchPath = "/bin/launchctl"
        task.arguments = ["kickstart", "-k", "system/dev.codex-es-guard"]
        do {
            try task.run()
            task.waitUntilExit()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                self.checkGuardRunning()
                if self.guardRunning {
                    self.overrideMessage = "守护进程已成功重启"
                    self.overrideSuccess = true
                } else {
                    self.overrideMessage = "重启失败，可能存在权限或配置问题"
                    self.overrideSuccess = false
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                    self.overrideMessage = ""
                }
            }
        } catch {
            print("重启失败: \(error)")
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
            return
        }
        
        let lines = String(data: data, encoding: .utf8)?.split(separator: "\n") ?? []
        let decoder = JSONDecoder()
        
        var parsed: [DenialRecord] = []
        for line in lines.reversed().prefix(200) {
            guard let lineData = String(line).data(using: .utf8) else { continue }
            if let record = try? decoder.decode(DenialRecord.self, from: lineData) {
                parsed.append(record)
            }
        }
        
        if !isFirstLoad && parsed.count > self.previousRecordCount && !parsed.isEmpty {
            if let newest = parsed.first {
                NotificationService.shared.sendDenialNotification(for: newest)
            }
        }
        
        self.previousRecordCount = parsed.count
        self.records = parsed
        
        var statsDict: [String: (del: Int, mov: Int)] = [:]
        for r in parsed {
            let key = r.ancestor
            let current = statsDict[key] ?? (0, 0)
            if r.op == "unlink" {
                statsDict[key] = (current.del + 1, current.mov)
            } else if r.op == "rename" {
                statsDict[key] = (current.del, current.mov + 1)
            }
        }
        
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
                self.overrideMessage = "成功将 \(URL(fileURLWithPath: cleanPath).lastPathComponent) 设为临时放行"
                self.overrideSuccess = true
                scheduleOverrideRevocation(for: cleanPath)
            } else {
                self.overrideMessage = "放行执行失败 (退出码: \(task.terminationStatus))"
                self.overrideSuccess = false
            }
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                self.overrideMessage = ""
            }
        } catch {
            self.overrideMessage = "放行程序调用出错: \(error.localizedDescription)"
            self.overrideSuccess = false
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
                self.overrideMessage = "安全提醒: \(URL(fileURLWithPath: path).lastPathComponent) 临时放行期已满，自动清理。"
                self.overrideSuccess = true
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) {
                    self.overrideMessage = ""
                }
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
            self.overrideMessage = "已清除所有的临时放行路径"
            self.overrideSuccess = true
            
            for timer in revokeTimers.values {
                timer.invalidate()
            }
            revokeTimers.removeAll()
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                self.overrideMessage = ""
            }
        } catch {
            self.overrideMessage = "更新策略文件失败: \(error.localizedDescription)"
            self.overrideSuccess = false
        }
    }
}
