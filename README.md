# AgentSmith-RS

macOS Endpoint Security 的 Rust 封装，以及基于它构建的 **AI Agent 文件安全守护进程**。

## 目标

AI 编程 Agent（如 Codex、Claude Code）在 full-access 模式下拥有完全的文件系统操作权限，效率很高，但存在误删关键文件的风险。

本项目的目标是：**在不牺牲 Agent 自主性的前提下，提供内核级的文件安全防护网**。

核心理念：不是禁止所有删除，而是**只拦截 AI Agent 进程发起的危险操作** —— 人类用户的操作不受影响。当 Agent 确实需要删除时，可以申请临时放行。

## 架构

```
  用户 rm file.txt ─────────────────────────→ ALLOW (非 AI 进程)

  AI Agent → zsh → rm file.txt
       │
       ▼
  agentsmith-rs (进程树检测)
       │  发现祖先进程 argv[0] = "claude" / exe = "codex"
       │  → AI Agent 上下文 → 检查保护策略
       ▼
  DENY + 写入 last_denial.txt
       │
       ▼
  Agent 读取反馈 → 运行 agentsmith-override（请求队列）→ root helper 放行 → 重试成功
```

## 进程感知防护

传统的路径豁免方案（如豁免 `.git/`、`node_modules/` 等）存在安全漏洞 —— AI Agent 也可以利用这些豁免路径。

agentsmith-rs 采用**进程感知**方案，通过遍历进程树来判断**谁**在发起操作：

### 决策流程

```
文件操作事件 (AUTH_UNLINK / AUTH_RENAME)
    │
    ├─ 不在 protected_zones 中？ ──→ ALLOW
    │
    ├─ 系统临时路径？ ──→ ALLOW
    │
    ├─ 遍历进程树，祖先中有 AI Agent？
    │   │
    │   ├─ 无 AI 祖先 ──→ ALLOW (人类操作)
    │   │
    │   └─ 有 AI 祖先 ──→ 默认 DENY（仅允许 git/jj 在 .git/.jj 元数据目录内维护）
    │
    └─ 默认 ──→ ALLOW
```

### 进程树检测

通过三种 macOS API 识别进程身份：

| API | 用途 | 示例 |
|-----|------|------|
| `proc_pidpath()` | 获取 Mach-O 二进制路径 | `/usr/local/bin/codex` |
| `sysctl(KERN_PROCARGS2)` | 读取 argv[0]（反映 `process.title`） | `claude`（Node.js 进程） |
| `proc_pidinfo(PROC_PIDTBSDINFO)` | 获取父进程 PID（256 字节缓冲区） | 用于向上遍历进程树 |

Claude Code 的实际二进制是 `node`，但通过 `process.title` 将 `argv[0]` 设置为 `claude`。
因此必须同时检查 exe path 和 argv[0] 才能正确识别。

### 实测结果

| 操作来源 | 进程链 | 结果 |
|----------|--------|------|
| 人类终端 `rm file` | `rm → zsh → login → ghostty` | ALLOW |
| Claude Code `rm file` | `rm → zsh → node(argv0=claude)` | **DENY** |
| Codex `rm file` | `rm → codex` | **DENY** |
| AI 的 `git commit` 元数据写入 | `git → ... (AI 祖先)` + `.git/.jj` | **ALLOW**（默认） |
| AI 调用 `git rm`/`git clean` 删除工作区 | `git → ... (AI 祖先)` + 非 `.git/.jj` | **DENY**（默认） |
| AI 调用 trusted tool 删除关键文件 | `cargo/swift/... (AI 祖先)` | 默认 **DENY** |
| CLIProxyAPI 日志轮转 | `cli-proxy-api` (非 AI 进程) | ALLOW |

## 闭环反馈：拦截 → 临时隔离(temp) → 按需放行

当 AI Agent 被拦截后，默认先走“临时隔离”而不是直接改策略放行：

```
Agent 执行 rm important.rs
    │
    ▼
agentsmith-rs DENY → 返回 EPERM
    │  同时写入 ~/.agentsmith-rs/guard/last_denial.txt
    ▼
Agent 读取 last_denial.txt，了解拦截原因
    │
    ▼
Agent 运行 agentsmith-quarantine <path>
    │  → 自动创建 ./temp（若不存在）
    │  → 先把目标移动到当前目录的 ./temp/
    ▼
需要彻底删除时，再走 agentsmith-override --minutes 3 <path>
    │  → root helper 写入 runtime temporary_overrides 后再重试
    ▼
最终删除成功（两段式防护）
```

### 反馈文件

每次拦截后，守护进程写入 `~/.agentsmith-rs/guard/last_denial.txt`：

```
[AGENTSMITH DENIED]
Operation: unlink
Path: /Users/you/project/important.rs
Zone: /Users/you/project
Process: rm (via claude)

Recommended (safer first step): agentsmith-quarantine /Users/you/project/important.rs
This moves the target into ./temp under your CURRENT working directory.

If you must permanently delete via AI, request one-time override with TTL:
agentsmith-override --minutes 3 /Users/you/project/important.rs
Then retry the operation.
```

### agentsmith-override 命令

```bash
# 申请临时放行 3 分钟（默认值）
agentsmith-override /path/to/file

# 显式指定放行时长（推荐）
agentsmith-override --minutes 5 /path/to/file

# 删除某条放行
agentsmith-override --remove /path/to/file

# 清空全部放行
agentsmith-override --clear

# 查看当前放行
agentsmith-override --list

# 放行后重试
rm /path/to/file  # 成功
```

> 安全限流：`--minutes` 默认上限 30 分钟（可通过环境变量 `AGENTSMITH_OVERRIDE_MAX_MINUTES` 调整），`--no-expire` 自动请求已禁用。
>
> root helper 还会校验 `requester_pid`：来自 AI 祖先进程的自动放行请求将被拒绝（避免 Agent 自行给自己放行）。
> 同时会验证该 PID 当前确实在运行 `agentsmith-override` helper，防止伪造其他进程 PID 进行绕过。

### agentsmith-quarantine 命令（推荐第一步）

```bash
# 将目标先移动到当前目录下的 ./temp（不存在会自动创建）
agentsmith-quarantine /path/to/file
```

### Agent 集成与“安保条约” Prompt

真正的 AI 时代安全防线，是“内核级硬拦截 + LLM 认知级软约束”的结合。
建议在你使用的 AI 编程助手的全局提示词配置文件中（如 Codex 的 `~/.codex/instructions.md` 或 Claude Code 的 `~/.claude/CLAUDE.md`），加入我们的**《Agent 独立安全审计与响应条约》**。

这套提示词赋予了 AI 以下能力：
1. 遇到 EPERM 拦截时懂得呼叫人类申请 `agentsmith-override` 放行，而不是盲目用 Python/C 尝试绕过。
2. 拥有**反 Prompt Injection 的硬性红线**，面对 `rm -rf $HOME` 或 `rm -rf .git` 这种低级破坏指令，无条件拒绝执行。

👉 **[点击这里获取开箱即用的 Prompt 样板文件 (agent-instructions-sample.md)](./agentsmith-rs/agent-instructions-sample.md)**


## 仓库结构

| 目录 | 说明 |
|------|------|
| `agentsmith-rs-core/` | ES 框架的高层 Rust 封装（fork 自 [HarfangLab/agentsmith-rs-core](https://github.com/jiaqiwang969/AgentSmith-RS)） |
| `agentsmith-rs-sys/` | ES 框架的底层 C→Rust FFI 绑定 |
| `agentsmith-rs/` | 文件安全守护进程（本项目的核心贡献） |

## 策略文件

静态策略路径：`~/.agentsmith-rs/policy.json`  
运行时放行存储：`/var/db/agentsmith-rs/<user>.json`（root 管理）

```json
{
  "protected_zones": [
    "/Users/you/important-project",
    "/Users/you/another-project"
  ],
  "temporary_overrides": [
    {
      "path": "/Users/you/important-project/tmp.txt",
      "expires_at": 1772500000,
      "created_at": 1772499820,
      "created_by": "agentsmith-helper"
    }
  ],
  "sensitive_zones": [
    "/Users/you/.codex"
  ],
  "sensitive_export_allow_zones": [
    "/Users/you/.agentsmith-rs/guard/quarantine"
  ],
  "auto_protect_home_digit_children": true,
  "trusted_tools": ["git", "jj", "cargo", "rustup", "rustc", "swift", "nix", "make", "go", "docker"],
  "trusted_tool_identities": [
    {
      "path": "/absolute/path/to/git",
      "signing_identifier": "com.example.git"
    }
  ],
  "ai_agent_patterns": ["codex", "claude", "claude-code"],
  "allow_vcs_metadata_in_ai_context": true,
  "allow_trusted_tools_in_ai_context": false,
  "exec_exfil_tool_blocklist": ["curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat"],
  "read_gate_enabled": true,
  "transfer_gate_enabled": true,
  "exec_gate_enabled": true,
  "taint_ttl_seconds": 600
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `protected_zones` | 受保护目录前缀 | `[]` |
| `temporary_overrides` | 运行时临时豁免（由 root helper 维护并镜像到本文件） | `[]` |
| `sensitive_zones` | 敏感目录前缀（受读门禁与外传门禁约束） | `[]` |
| `sensitive_export_allow_zones` | 允许从敏感目录导出的目的地前缀 | `[]` |
| `auto_protect_home_digit_children` | 自动保护 HOME 下首层“数字开头”目录（如 `~/01-agent`、`~/0x-lab`） | `true` |
| `trusted_tools` | 受信任工具名（第一层筛选） | git, jj, cargo, rustup 等 |
| `trusted_tool_identities` | 受信任工具身份白名单（绝对路径 + 签名标识；与 `trusted_tools` 共同生效） | `[]`（首次激活会自动补最小集合） |
| `ai_agent_patterns` | AI Agent 进程名匹配模式（子字符串匹配） | codex, claude, claude-code |
| `allow_vcs_metadata_in_ai_context` | 是否允许 AI 的 git/jj 维护 `.git/.jj` 元数据（不包含工作区删除） | `true` |
| `allow_trusted_tools_in_ai_context` | 是否允许 AI 上下文命中 trusted_tools 后放行 | `false` |
| `exec_exfil_tool_blocklist` | AI 上下文下禁止执行的外传工具名 | `curl,wget,scp,...` |
| `read_gate_enabled` | 是否启用敏感读取门禁（`AUTH_OPEN`） | `true` |
| `transfer_gate_enabled` | 是否启用敏感外传门禁（copy/clone/link/exchange/rename） | `true` |
| `exec_gate_enabled` | 是否启用外传工具执行门禁（`AUTH_EXEC`） | `true` |
| `taint_ttl_seconds` | 进程读取敏感数据后的污点有效期（秒） | `600` |

- 策略文件支持 **热重载**（1 秒轮询），修改即生效
- 守护进程会自动清理已过期的 runtime `temporary_overrides`，并镜像回策略文件给 UI 展示
- root helper 会拒绝过长路径、超大请求文件，并限制最多 512 条同时生效的 runtime overrides
- 请求队列增加每分钟速率限制（默认 120 条）与单轮处理上限（默认 256 条）以降低滥用风险
- 所有放行请求都会写入 `~/.agentsmith-rs/guard/override-audit.jsonl` 审计日志（成功/失败都记录）
- 默认兼顾效率与安全：允许 AI 的 git/jj 维护 `.git/.jj` 元数据，但 `git rm/git clean` 这类工作区删除仍会拦截
- 默认更安全：AI 上下文不再因为 trusted_tools 自动放行；如需兼容可显式开启 `allow_trusted_tools_in_ai_context`
- `trusted_tools` 与 `trusted_tool_identities` 是双因子校验；命中名称但身份不匹配会 fail-closed
- 若检测到 `trusted_tool_identities` 为空，或缺少某些 `trusted_tools` 的身份条目，守护进程启动/热重载时会输出自检告警
- Nix 激活脚本会在 `trusted_tool_identities` 缺失或空数组时，尝试自动写入最小签名身份（git/jj/cargo/xcrun 中可解析签名的工具）
- 路径匹配使用“目录边界匹配”：`/Users/you/0` 不会匹配 `/Users/you/01-agent`
- 如需覆盖新建的 `0x-*`/`01-*` 目录，开启 `auto_protect_home_digit_children` 更稳妥
- `trusted_tools` 和 `ai_agent_patterns` 有内置默认值，无需在 JSON 中指定
- `protected_zones` 由 Nix 激活脚本管理；`temporary_overrides` 不再信任手改 JSON，统一走 `agentsmith-override` 请求队列

### 拒绝原因码（denials.jsonl `reason` 字段）

| reason | 含义 |
|---|---|
| `SENSITIVE_READ_NON_AI` | 非 AI 上下文尝试读取敏感目录 |
| `SENSITIVE_TRANSFER_OUT` | 从敏感目录向非允许区域复制/移动/链接 |
| `TAINT_WRITE_OUT` | 进程读取敏感数据后，在污点 TTL 内向非允许区域写出 |
| `EXEC_EXFIL_TOOL` | AI 上下文执行外传工具（如 curl/scp）被拒绝 |
| `TRUST_IDENTITY_MISMATCH` | 命中 `trusted_tools` 但未通过 `trusted_tool_identities` 身份校验 |
| `PROTECTED_ZONE_AI_DELETE` | AI 在受保护区发起删除/重命名（原有删除防护） |

### ES 能力边界与完整 C 方案

- Endpoint Security 负责**文件/执行授权**（read/transfer/write/exec 事件）。
- ES 本身不做通用域名/IP 出站策略；完整 C 方案需要额外出站层。
- 本仓库提供 `agentsmith-egress`，配合 PF anchor 实现“显式 allowlist 出站”：
  - `agentsmith-egress --print-rules`
  - `agentsmith-egress --apply --allowlist ~/.agentsmith-rs/guard/egress-allowlist.txt`
  - `agentsmith-egress --flush`
- 参考验证矩阵：`docs/plans/2026-03-03-codex-sensitive-data-guard-c-verification.md`

## Nix 集成

通过 flake 提供 nix-darwin 模块，开机自动启动：

```nix
# flake.nix inputs
agentsmith-rs-core.url = "github:jiaqiwang969/agentsmith-rs-core";

# machines/your-mac.nix
services.agentsmith-rs = {
  enable = true;
  user = "yourname";
  protectedZones = [ "/Users/yourname/projects" ];
  sensitiveZones = [ "/Users/yourname/.codex" ];
  sensitiveExportAllowZones = [ "/Users/yourname/.agentsmith-rs/guard/quarantine" ];
  readGateEnabled = true;
  transferGateEnabled = true;
  execGateEnabled = true;
  autoProtectHomeDigitChildrenDefault = true;
};
```

激活脚本自动完成：复制二进制 → codesign → 安装 helper（`agentsmith-override` / `agentsmith-quarantine` / `agentsmith-egress`）→ 启动 LaunchDaemon → 同步策略文件。

## 手动构建与运行

```bash
# 构建
nix build .#agentsmith-rs

# 签名（需要 ES entitlement）
sudo cp result/bin/agentsmith-rs /usr/local/bin/
sudo cp result/bin/agentsmith-override /usr/local/bin/
sudo cp result/bin/agentsmith-quarantine /usr/local/bin/
sudo cp result/bin/agentsmith-egress /usr/local/bin/
sudo codesign --entitlements agentsmith-rs/agentsmith.plist --force -s - /usr/local/bin/agentsmith-rs

# 运行（需要 root）
sudo /usr/local/bin/agentsmith-rs
```

## 项目进度

| 阶段 | 状态 |
|------|------|
| agentsmith-rs-core Rust 封装 | 已完成（上游维护） |
| agentsmith-rs 守护进程 | 已完成 |
| 进程感知防护（进程树检测） | 已完成 |
| 策略热重载 | 已完成 |
| 拦截审计日志 | 已完成 |
| 闭环反馈（反馈文件 + override 命令） | 已完成 |
| nix-darwin 模块集成 | 已完成 |

| Nix-Darwin 模块集成 | 已完成 |
| Agent 指令集成 (CLAUDE.md / instructions.md) | 已完成 |
| **MenuBar UI 应用 (AgentSmith.app)** | **已完成 (全新)** |

## 🖥️ AgentSmith-RS MenuBar 监控应用

作为底层 Root 守护进程的完美补充，本项目包含一个完全原生的 **macOS SwiftUI 菜单栏应用**，提供极客级的视觉监控与控制闭环。

> **环境要求**：macOS 13.0 (Ventura) 或更高版本。

### 核心特性

*   **⚡️ 零开销事件驱动 (FSEvents)**
    不使用低效的定时轮询。底层封装 `DispatchSourceFileSystemObject` 直接与内核文件系统事件绑定。当守护进程写入拦截日志时，UI 在微秒级瞬间唤醒并更新，平时 CPU 占用严格为 `0%`。
*   **🔔 交互式原生系统通知 (Push Notifications)**
    当 Agent 试图越权操作被拦截时，macOS 右上角会立刻弹出原生横幅告警。你甚至不需要打开控制台，直接点击通知横幅上的 **[临时放行]** 按钮即可授权。
*   **⏳ 智能“阅后即焚”放行策略**
    安全的最大敌人是遗忘。通过 UI 授权的临时放行操作，应用会在后台启动一个静默倒计时（默认 3 分钟，支持偏好设置持久化修改）。时间一到，自动撤销授权，防止留下永久后门。
*   **🧷 前端安全兜底**
    App 侧会拒绝对根目录/家目录/保护目录根执行整段放行，并要求放行路径必须落在受保护范围内（`protected_zones` 或自动数字目录保护），避免误操作导致策略失控。
*   **🧩 Git 元数据细粒度开关**
    UI 提供 `allow_vcs_metadata_in_ai_context`（默认开启，推荐），只允许 AI 的 git/jj 维护 `.git/.jj` 元数据，不放行工作区删除。
*   **⚖️ 兼容模式开关**
    UI 提供 `allow_trusted_tools_in_ai_context` 开关（默认关闭，推荐）。开启前会弹出高风险确认。
*   **📊 AI 行为画像 (SwiftUI Charts)**
    提供可视化的堆叠柱状图，精准统计是 Codex、Claude 还是 Copilot 在尝试对你的哪些文件发起 `Delete` 或 `Move` 操作。
*   **🤖 人机协同指令生成**
    针对全自动 Agent 的特性，专门设计了“一键生成 Prompt”按钮。点击后自动将拦截记录打包为一段带有明确上下文的英文 Prompt，直接喂给大模型纠正它的后续行为。

### 构建与安装

我们提供了极简的构建脚本，一键将其编译、剥离隔离属性并注册为合法的系统 App：

```bash
cd agentsmith-rs/menubar-app
make install
```

执行后，带有“系统级保险箱”图标的 `AgentSmith.app` 将被静默安装至你的 `~/Applications/` 目录并自动启动。

### 近期更新（2026-03-04）

- **守护控制可靠性增强**：修复了 `launchctl` 在输出权限错误但整体返回 `0` 时未触发提权重试的问题；现在会根据 stderr 关键字（如 `Operation not permitted`）自动走管理员授权重试。
- **敏感区管理改为可维护列表**：MenuBar `sensitive_zones` 支持直接“添加 + 一键移除（x）”，用于维护“人不可读、Agent 可读但防外传”的目录集合。
- **拦截与日志降噪**：新增噪声过滤器，支持在 Records/Logs 面板隐藏高频低价值噪声事件，并显示已隐藏条数，减少告警疲劳。
- **路径判定更稳**：守护进程路径前缀匹配支持 `/System/Volumes/Data` 与 `/private` 等别名路径，避免同一路径不同前缀导致策略漏判。
- **读意图识别修正**：`AUTH_OPEN` 的 `fflag=0` 现按读意图处理，确保敏感目录读取门禁在该类事件上不会漏拦。


## License

- `agentsmith-rs-core` / `agentsmith-rs-sys`：MIT OR Apache-2.0（原作者 HarfangLab）
- `agentsmith-rs`：MIT OR Apache-2.0
