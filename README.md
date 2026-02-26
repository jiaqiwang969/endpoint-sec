# Endpoint Security + Codex-ES-Guard

macOS Endpoint Security 的 Rust 封装，以及基于它构建的 **AI Agent 文件安全守护进程**。

## 目标

AI 编程 Agent（如 Codex）在 full-access 模式下拥有完全的文件系统操作权限，效率很高，但存在误删关键文件的风险。

本项目的目标是：**在不牺牲 Agent 自主性的前提下，提供内核级的文件安全防护网**。

核心理念：不是不让 AI 删文件，而是让 AI **有意识地**删文件 —— 拦截是手段，闭环反馈才是目的。

## 架构

```
                        Codex-RS Sandbox（规划中）
                         │  检测 DENY → 反馈 AI 上下文
                         │  AI 申请 temporary_override → 临时放行
                         ▼
  ~/.codex/es_policy.json ──→ codex-es-guard 守护进程
                               │  AUTH_UNLINK / AUTH_RENAME
                               ▼
                          macOS Endpoint Security
                               │
                               ▼
                          endpoint-sec (Rust crate)
```

## 仓库结构

| 目录 | 说明 |
|------|------|
| `endpoint-sec/` | ES 框架的高层 Rust 封装（fork 自 [HarfangLab/endpoint-sec](https://github.com/HarfangLab/endpoint-sec)） |
| `endpoint-sec-sys/` | ES 框架的底层 C→Rust FFI 绑定 |
| `codex-es-guard/` | 文件安全守护进程（本项目的核心贡献） |

## codex-es-guard

### 工作原理

1. 以 root 权限运行，订阅 macOS ES 的 `AUTH_UNLINK`（删除）和 `AUTH_RENAME`（移动/重命名）事件
2. 从 `~/.codex/es_policy.json` 读取保护策略，决定 ALLOW 或 DENY
3. 默认放行所有操作，仅拦截命中 `protected_zones` 的路径
4. 每次拦截写入审计日志 `~/.codex/es-guard/denials.jsonl`

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
  ]
}
```

- `protected_zones`：受保护目录前缀，匹配路径的删除/移出操作被拦截
- `temporary_overrides`：临时豁免的子路径，即使在保护区内也允许操作
- 策略文件支持 **热重载**（1 秒轮询），修改即生效

### 自动豁免

以下路径始终放行，避免阻断正常开发流程：

- `.Trash/`、`/tmp/`、`/var/folders/` — 系统临时目录
- `.cache/`、`target/`、`node_modules/`、`result/` — 构建和依赖缓存
- `.git/` — Git 内部操作

### 拦截日志

路径：`~/.codex/es-guard/denials.jsonl`（超过 1MB 自动截断）

```json
{"ts":1718000000,"op":"unlink","path":"/Users/you/project/flake.nix","dest":null,"zone":"/Users/you/project"}
{"ts":1718000001,"op":"rename","path":"/Users/you/project/src/main.rs","dest":"/tmp/main.rs","zone":"/Users/you/project"}
```

### 构建与运行

```bash
# 构建
cargo build --release -p codex-es-guard

# 签名（需要 ES entitlement）
codesign --entitlements codex-es-guard/es.plist --force -s - target/release/codex-es-guard

# 运行（需要 root）
sudo target/release/codex-es-guard
```

## 最终愿景：与 Codex 的闭环集成

当前守护进程是单向拦截。最终目标是实现完整的闭环：

```
AI Agent 执行 rm important.rs
        │
        ▼
codex-es-guard DENY + 写入 denials.jsonl
        │
        ▼
Codex-RS Sandbox 检测到 EPERM，读取 denials.jsonl
        │
        ▼
Agent 上下文收到反馈："删除被安全策略阻止，该文件在保护区 /Users/you/project 内"
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
| 策略热重载 | 已完成 |
| 拦截审计日志 | 已完成 |
| Codex-RS Sandbox 集成 | 规划中 |
| Agent 闭环反馈 | 规划中 |

## License

- `endpoint-sec` / `endpoint-sec-sys`：MIT OR Apache-2.0（原作者 HarfangLab）
- `codex-es-guard`：MIT OR Apache-2.0
