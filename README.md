# Endpoint Security + Codex-ES-Guard

macOS Endpoint Security 的 Rust 封装，以及基于它构建的 **AI Agent 文件安全守护进程**。

## 目标

AI 编程 Agent（如 Codex、Claude Code）在 full-access 模式下拥有完全的文件系统操作权限，效率很高，但存在误删关键文件的风险。

本项目的目标是：**在不牺牲 Agent 自主性的前提下，提供内核级的文件安全防护网**。

核心理念：不是禁止所有删除，而是**只拦截 AI Agent 进程发起的危险操作** —— 人类用户的操作不受影响。

## 架构

```
  用户 rm file.txt ─────────────────────────→ ALLOW (非 AI 进程)

  Claude Code → zsh → rm file.txt
       │
       ▼
  codex-es-guard (进程树检测)
       │  发现祖先进程 argv[0] = "claude"
       │  → AI Agent 上下文 → 检查保护策略
       ▼
  DENY + 审计日志
       │
       ▼
  Agent 收到 EPERM → 理解原因 → 可申请 temporary_override
```

## 进程感知防护机制

传统的路径豁免方案（如豁免 `.git/`、`node_modules/` 等）存在安全漏洞 —— AI Agent 也可以利用这些豁免路径。

codex-es-guard 采用**进程感知**方案，通过遍历进程树来判断**谁**在发起操作：

### 决策流程

```
文件操作事件 (AUTH_UNLINK / AUTH_RENAME)
    │
    ├─ 不在 protected_zones 中？ ──→ ALLOW
    │
    ├─ 系统临时路径？ ──→ ALLOW
    │
    ├─ 直接进程是受信工具 (git/cargo/npm...)？ ──→ ALLOW
    │
    ├─ 遍历进程树，祖先中有 AI Agent？
    │   │
    │   ├─ 无 AI 祖先 ──→ ALLOW (人类操作)
    │   │
    │   └─ 有 AI 祖先 ──→ DENY + 审计日志
    │
    └─ 默认 ──→ ALLOW
```

### 进程树检测

通过三种 macOS API 识别进程身份：

| API | 用途 | 示例 |
|-----|------|------|
| `proc_pidpath()` | 获取 Mach-O 二进制路径 | `/usr/local/bin/codex` |
| `sysctl(KERN_PROCARGS2)` | 读取 argv[0]（反映 `process.title`） | `claude`（Node.js 进程） |
| `proc_pidinfo(PROC_PIDTBSDINFO)` | 获取父进程 PID | 用于向上遍历进程树 |

Claude Code 的实际二进制是 `node`，但通过 `process.title` 将 `argv[0]` 设置为 `claude`。
因此必须同时检查 exe path 和 argv[0] 才能正确识别。

### 实测结果

| 操作来源 | 进程链 | 结果 |
|----------|--------|------|
| 人类终端 `rm file` | `rm → zsh → login → ghostty` | ALLOW |
| Claude Code `rm file` | `rm → zsh → node(argv0=claude)` | **DENY** |
| Codex `rm file` | `rm → codex` | **DENY** |
| git 操作 `.git/objects/` | `git` (trusted tool) | ALLOW |
| CLIProxyAPI 日志轮转 | `cli-proxy-api` (非 AI 进程) | ALLOW |

## 仓库结构

| 目录 | 说明 |
|------|------|
| `endpoint-sec/` | ES 框架的高层 Rust 封装（fork 自 [HarfangLab/endpoint-sec](https://github.com/HarfangLab/endpoint-sec)） |
| `endpoint-sec-sys/` | ES 框架的底层 C→Rust FFI 绑定 |
| `codex-es-guard/` | 文件安全守护进程（本项目的核心贡献） |

## codex-es-guard

### 策略文件

路径：`~/.codex/es_policy.json`

```json
{
  "protected_zones": [
    "/Users/you/important-project",
    "/Users/you/another-project"
  ],
  "temporary_overrides": [
    "/Users/you/important-project/tmp-can-delete"
  ],
  "trusted_tools": ["git", "cargo", "npm", "node", "python3"],
  "ai_agent_patterns": ["codex", "claude", "claude-code"]
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `protected_zones` | 受保护目录前缀 | `[]` |
| `temporary_overrides` | 临时豁免的子路径 | `[]` |
| `trusted_tools` | 受信任的工具进程名（即使在 AI 上下文中也允许） | git, cargo, npm, node 等 |
| `ai_agent_patterns` | AI Agent 进程名匹配模式（子字符串匹配） | codex, claude, claude-code |

- 策略文件支持 **热重载**（1 秒轮询），修改即生效
- `trusted_tools` 和 `ai_agent_patterns` 有内置默认值，无需在 JSON 中指定

### 拦截日志

路径：`~/.codex/es-guard/denials.jsonl`（超过 1MB 自动截断）

```json
{"ts":1718000000,"op":"unlink","path":"/Users/you/project/main.rs","dest":null,"zone":"/Users/you/project","process":"rm","ancestor":"claude"}
```

### Nix 集成

通过 flake 提供 nix-darwin 模块，开机自动启动：

```nix
# flake.nix inputs
endpoint-sec.url = "github:jiaqiwang969/endpoint-sec";

# machines/your-mac.nix
services.codex-es-guard = {
  enable = true;
  user = "yourname";
  protectedZones = [ "/Users/yourname/projects" ];
};
```

激活脚本自动完成：复制二进制 → codesign → 启动 LaunchDaemon → 同步策略文件。

### 手动构建与运行

```bash
# 构建
nix build .#codex-es-guard
# 或
cargo build --release -p codex-es-guard

# 签名（需要 ES entitlement）
codesign --entitlements codex-es-guard/es.plist --force -s - target/release/codex-es-guard

# 运行（需要 root）
sudo target/release/codex-es-guard
```

## 最终愿景：与 AI Agent 的闭环集成

当前守护进程是单向拦截。最终目标是实现完整的闭环：

```
AI Agent 执行 rm important.rs
        │
        ▼
codex-es-guard DENY + 写入 denials.jsonl
        │
        ▼
Agent Sandbox 检测到 EPERM，读取 denials.jsonl
        │
        ▼
Agent 上下文收到反馈："删除被安全策略阻止，该文件在保护区内"
        │
        ▼
Agent 理解原因，决定是否发起 request_security_override
        │
        ▼
临时放行写入 es_policy.json 的 temporary_overrides
        │
        ▼
守护进程 1s 内热重载，放行该路径
        │
        ▼
Agent 重试操作，成功
```

| 阶段 | 状态 |
|------|------|
| endpoint-sec Rust 封装 | 已完成（上游维护） |
| codex-es-guard 守护进程 | 已完成 |
| 进程感知防护（进程树检测） | 已完成 |
| 策略热重载 | 已完成 |
| 拦截审计日志 | 已完成 |
| nix-darwin 模块集成 | 已完成 |
| Agent 闭环反馈 | 规划中 |

## License

- `endpoint-sec` / `endpoint-sec-sys`：MIT OR Apache-2.0（原作者 HarfangLab）
- `codex-es-guard`：MIT OR Apache-2.0
