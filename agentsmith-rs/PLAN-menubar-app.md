# ES Guard MenuBar App 计划书

## 1. 项目目标

在 `agentsmith-rs` 项目中构建一个**独立的 macOS MenuBar 应用**，让用户通过菜单栏实时监控 ES Guard 守护进程的运行状态、拦截记录、保护策略，并提供一键放行等交互能力。

## 2. 设计参考

借鉴 `cliProxyAPI-Dashboard/macos-menubar/CLIProxyMenuBar` 的 UI 风格和架构模式：

| 参考点 | cliProxyAPI-Dashboard 实现 | ES Guard 应用适配 |
|--------|---------------------------|------------------|
| 入口 | `@main` + `MenuBarExtra(.window)` | 相同模式 |
| 窗口宽度 | `.frame(width: 400)` | 保持 400pt |
| Tab 导航 | `Picker(.segmented)` + `enum` | 相同模式 |
| 字体体系 | `.headline` 标题 / `.callout` 正文 / `.caption` 辅助 / `.system(size:10-11, design:.monospaced)` 日志 | 保持一致 |
| 颜色语义 | `.primary` 正文 / `.secondary` 辅助 / `.orange` 警告 / `.red` 错误 / `.green` 成功 / `.blue` 信息 | 保持一致 |
| 底部栏 | 刷新 / 暂停 / 退出按钮 | 改为 刷新 / 退出 |
| 数据刷新 | 轮询 (`Task.sleep` 循环) | 相同模式，5秒间隔 |
| 状态管理 | `@StateObject` ViewModel + `@Published` 属性 | 相同模式 |
| 最小macOS | `.macOS(.v13)` | `.macOS(.v13)` |

## 3. 数据源

所有数据均来自本地文件，**不需要网络请求**：

| 数据 | 来源 | 格式 |
|------|------|------|
| 守护进程状态 | `pgrep -x agentsmith-rs` | 进程是否存在 |
| 拦截记录 | `~/.agentsmith-rs/guard/denials.jsonl` | 每行一个 JSON |
| 最新拦截反馈 | `~/.agentsmith-rs/guard/last_denial.txt` | 人类可读文本 |
| 保护策略 | `~/.agentsmith-rs/policy.json` | JSON |
| 守护进程日志 | `/tmp/agentsmith-rs.log` + `.err` | 文本行 |

### 3.1 denials.jsonl 记录格式

```json
{
  "ts": 1772096243,
  "op": "unlink",
  "path": "/Users/jqwang/100-test-guard/codex-test.txt",
  "dest": null,
  "zone": "/Users/jqwang/1",
  "process": "rm",
  "ancestor": "codex"
}
```

### 3.2 es_policy.json 策略格式

```json
{
  "protected_zones": ["/Users/jqwang/0", "/Users/jqwang/1", ...],
  "temporary_overrides": ["/path/to/temporarily/allowed/file"]
}
```

运行时还有内置默认值（不在 JSON 中）：
- `trusted_tools`: git, cargo, npm, node, python3, swift 等
- `ai_agent_patterns`: codex, claude, claude-code

## 4. 功能规划

### Tab 1: 状态（Status）

**核心看板页**，一眼掌握全局。

```
┌──────────────────────────────────────┐
│  ● ES Guard: Running        12 拦截  │
│──────────────────────────────────────│
│  ⏱ 运行时间  自 2026-02-26 10:00     │
│  🗑 DELETE    8                       │
│  ➡ MOVE      4                       │
│  🤖 Agents   claude, codex           │
│──────────────────────────────────────│
│  最新拦截 (30s ago)                   │
│  ┌────────────────────────────────┐  │
│  │ DELETE rm (via claude)         │  │
│  │ /Users/.../important.rs       │  │
│  │ Zone: /Users/jqwang/0         │  │
│  └────────────────────────────────┘  │
│  [ Override: important.rs ]          │
│  ✓ Override granted                  │
└──────────────────────────────────────┘
```

内容：
- 守护进程运行状态（绿色/红色指示灯 + 文字）
- 拦截统计：总数、按类型(delete/move)、涉及的 Agent
- 最新一条拦截的详情（来自 `last_denial.txt`）
- 一键 Override 按钮（调用 `agentsmith-override`）
- Override 结果反馈

### Tab 2: 记录（Records）

**拦截历史列表**，可滚动浏览。

```
┌──────────────────────────────────────┐
│  拦截记录 (12)          [仅DELETE ▼]  │
│──────────────────────────────────────│
│  DELETE  codex-test.txt    via codex │
│  /Users/.../codex-test.txt  14:30:43 │
│  ─────────────────────────────────── │
│  DELETE  build.db       via claude   │
│  /Users/.../.build/build.db 14:23:08 │
│  ─────────────────────────────────── │
│  MOVE    config.bak      via claude  │
│  /Users/.../config → /tmp/  14:20:15 │
│  ─────────────────────────────────── │
│  ...                                 │
└──────────────────────────────────────┘
```

内容：
- 按时间倒序排列的拦截记录
- 每条显示：操作类型（彩色标签）、文件名、Agent、完整路径、时间
- rename 操作显示目标路径
- 筛选器：全部 / 仅 DELETE / 仅 MOVE
- 最多显示最近 100 条

### Tab 3: 策略（Policy）

**查看和管理保护策略**。

```
┌──────────────────────────────────────┐
│  保护区域 (10)                        │
│  ─────────────────────────────────── │
│  /Users/jqwang/0                     │
│  /Users/jqwang/1                     │
│  /Users/jqwang/2                     │
│  ...                                 │
│──────────────────────────────────────│
│  临时放行 (2)          [ 清除全部 ]   │
│  ─────────────────────────────────── │
│  /Users/.../build.db          [ ✕ ]  │
│  /Users/.../AgentSmithViewModel   [ ✕ ] │
│──────────────────────────────────────│
│  ▶ 受信工具 (19)                      │
│    git, jj, cargo, rustup, ...       │
│  ▶ AI Agent 模式 (3)                  │
│    codex, claude, claude-code        │
└──────────────────────────────────────┘
```

内容：
- `protected_zones` 列表（来自策略文件，Nix 管理）
- `temporary_overrides` 列表 + 单条删除按钮 + 清除全部
- `trusted_tools` 折叠列表（内置默认 + JSON 覆盖）
- `ai_agent_patterns` 折叠列表

交互：
- 清除单条/全部 `temporary_overrides`（直接修改 JSON）
- 保护区域和受信工具仅展示（由 Nix 管理）

### Tab 4: 日志（Logs）

**守护进程运行日志**（stdout/stderr）。

```
┌──────────────────────────────────────┐
│  运行日志              [仅错误] [📋]  │
│──────────────────────────────────────│
│  [policy] reloaded                   │
│  [DENY] unlink by rm (via claude):   │
│    /Users/.../test.txt               │
│  [policy] reloaded                   │
│  Codex-ES-Guard started [process-    │
│    aware mode]                       │
│  ...                                 │
└──────────────────────────────────────┘
```

内容：
- 实时跟踪 `/tmp/agentsmith-rs.log` 和 `/tmp/agentsmith-rs.err`
- `tail -f` 模式，最多保留最近 200 行
- 筛选：全部 / 仅错误（含 `[DENY]`、`error`、`panic`）
- 复制日志按钮

## 5. 架构设计

### 5.1 项目结构

```
agentsmith-rs/
├── src/main.rs                    # 守护进程（Rust，已有）
├── agentsmith-override              # Override 脚本（已有）
├── es.plist                       # Entitlements（已有）
├── Cargo.toml                     # Rust 构建（已有）
├── menubar-app/                   # 新增：MenuBar 应用
│   ├── Package.swift
│   └── Sources/
│       └── AgentSmithMenuBar/
│           ├── AgentSmithMenuBarApp.swift      # @main 入口
│           ├── DashboardView.swift          # 主视图 + Tab 容器
│           ├── StatusPanel.swift            # Tab 1: 状态
│           ├── RecordsPanel.swift           # Tab 2: 记录
│           ├── PolicyPanel.swift            # Tab 3: 策略
│           ├── LogsPanel.swift              # Tab 4: 日志
│           ├── AgentSmithViewModel.swift       # 数据层 ViewModel
│           └── Models.swift                 # DenialRecord, Policy 模型
└── PLAN-menubar-app.md            # 本文档
```

### 5.2 模块职责

| 文件 | 职责 |
|------|------|
| `AgentSmithMenuBarApp.swift` | 应用入口，`MenuBarExtra(.window)`，图标状态（绿色运行/红色停止/橙色有拦截） |
| `DashboardView.swift` | 主视图容器：标题栏 + Segmented Picker + Tab 内容 + 底部操作栏 |
| `AgentSmithViewModel.swift` | 所有数据加载/轮询：进程状态、记录解析、策略加载、日志跟踪、override 调用 |
| `Models.swift` | `DenialRecord`、`SecurityPolicy` 数据模型（与 Rust 端 JSON 对齐） |
| 各 Panel | 纯 UI 视图，从 ViewModel 读取数据 |

### 5.3 ViewModel 设计

```swift
@MainActor
final class AgentSmithViewModel: ObservableObject {
    // --- 状态 ---
    @Published var guardRunning: Bool = false
    @Published var records: [DenialRecord] = []
    @Published var policy: SecurityPolicy = .empty
    @Published var lastDenial: String = ""
    @Published var overrideMessage: String = ""

    // --- 日志 ---
    @Published var logLines: [LogLine] = []
    @Published var showOnlyErrors: Bool = false

    // --- 操作 ---
    func reload()                          // 手动刷新全部
    func requestOverride(for path: String)  // 调用 agentsmith-override
    func removeOverride(_ path: String)     // 从 policy JSON 删除单条 override
    func clearAllOverrides()                // 清空全部 overrides

    // --- 内部 ---
    private func startPolling()             // 5s 轮询循环
    private func loadRecords() -> [DenialRecord]
    private func loadPolicy() -> SecurityPolicy
    private func loadFeedback() -> String
    private func checkGuardRunning() -> Bool
    private func startLogMonitoring()       // tail -f 日志
}
```

### 5.4 MenuBar 图标状态

| 状态 | 图标 | 说明 |
|------|------|------|
| 运行中 + 无拦截 | `shield.checkmark` (绿色) | 正常防护 |
| 运行中 + 有新拦截 | `shield.exclamationmark` (橙色) | 最近有拦截 |
| 已停止 | `shield.slash` (红色) | 守护进程未运行 |

## 6. 构建与部署

### 6.1 开发期构建

```bash
cd agentsmith-rs/menubar-app
swift build
# 运行
.build/arm64-apple-macosx/debug/AgentSmithMenuBar
```

### 6.2 Nix 集成（后期）

在 `flake.nix` 中新增 Swift 包构建，或作为独立 derivation：

```nix
packages.es-guard-menubar = pkgs.swiftPackages.stdenv.mkDerivation {
  # ...swift build...
};
```

也可以先手动构建 `.app`，后续再考虑 Nix 集成。

### 6.3 部署形式

- 开发期：直接 `swift build && open` 运行
- 正式部署：打包为 `.app` bundle，放入 `/Applications/` 或 `~/Applications/`
- 可选：通过 Nix activation script 自动安装

## 7. 与 cliProxyAPI-Dashboard 的关键差异

| 维度 | cliProxyAPI-Dashboard | ES Guard MenuBar |
|------|----------------------|------------------|
| 数据来源 | HTTP API (`/api/usage`) | 本地文件 (JSON/JSONL/文本) |
| 依赖 | 需要后端服务运行 | 仅需本地文件，无外部依赖 |
| 复杂度 | 5 个 Tab + API Key 管理 + 服务控制 | 4 个 Tab，更精简 |
| 通知 | 服务崩溃通知 (UNNotification) | 可选：拦截通知 |
| 配置 | 读取 config.yaml | 读取 es_policy.json |
| 写操作 | 修改 config.yaml (Key 管理) | 仅修改 temporary_overrides |

## 8. 实施步骤

| 阶段 | 内容 | 估计文件数 |
|------|------|-----------|
| Phase 1 | 项目脚手架：Package.swift + App 入口 + 空 Tab 框架 | 3 |
| Phase 2 | ViewModel + Models：数据加载、轮询、记录解析 | 2 |
| Phase 3 | StatusPanel + RecordsPanel：核心 UI | 2 |
| Phase 4 | PolicyPanel + LogsPanel：策略展示 + 日志跟踪 | 2 |
| Phase 5 | Override 交互 + MenuBar 图标动态更新 | 修改已有 |
| Phase 6 | 测试 + 打包 + 部署集成 | - |

## 9. 风险与注意事项

1. **无 App Bundle 问题**：直接 `swift build` 的二进制没有 `.app` bundle，可能导致 `UNUserNotificationCenter` 崩溃（cliProxyAPI-Dashboard 已遇到）。解决：不使用 `UNNotification`，或用 `xcodebuild` 打包
2. **ES Guard 未运行时的体验**：App 应优雅处理守护进程未运行的情况，显示引导信息
3. **文件权限**：`denials.jsonl` 和 `last_denial.txt` 由 root 进程写入，需确保当前用户可读
4. **性能**：轮询间隔 5 秒，JSONL 文件可能增长较大，需设上限（守护进程已有 1MB 轮转）
5. **Swift 6 并发**：Package.swift 使用 `swift-tools-version: 6.0`，需注意 `@Sendable` 和 actor isolation
