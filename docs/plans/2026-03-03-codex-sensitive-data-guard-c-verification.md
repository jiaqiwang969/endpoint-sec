# Codex Sensitive Data Guard (Plan C) Verification Matrix

Date: 2026-03-03  
Host: `macbook-pro-m4` (`jqwang`)  
Manual test run id: `1772528008`

## Scope

This matrix verifies Plan C behavior after enabling:

- sensitive read gate (`AUTH_OPEN`)
- sensitive transfer gate (`AUTH_COPYFILE`/`AUTH_CLONE`/`AUTH_LINK`/`AUTH_EXCHANGEDATA`/`AUTH_RENAME`)
- taint write gate (`AUTH_CREATE`/`AUTH_TRUNCATE`)
- exec exfil gate (`AUTH_EXEC`)
- optional outbound egress helper (`agentsmith-egress`, PF anchor sync)

## Host Policy Snapshot

Source: `~/.agentsmith-rs/policy.json`

- `sensitive_zones = ["/Users/jqwang/.codex"]`
- `sensitive_export_allow_zones = ["/Users/jqwang/.agentsmith-rs/guard/quarantine"]`
- `read_gate_enabled = true`
- `transfer_gate_enabled = true`
- `exec_gate_enabled = true`
- `taint_ttl_seconds = 600`

## Execution Context Note

- Commands executed directly from this Codex session run in AI context (`ancestor=codex`).
- To validate true non-AI denial, the read test was executed via `launchctl submit` with a standalone `cat` job (`ancestor=none`).

## Manual Verification Results (Observed)

| Scenario | Command (summary) | Observed result | Evidence |
|---|---|---|---|
| Non-AI sensitive read | `launchctl submit ... /bin/cat ~/.agentsmith-rs/guard/plan-c-read-1772528008.txt` | DENY (`Operation not permitted`) | `op=open`, `reason=SENSITIVE_READ_NON_AI`, `process=cat`, `ancestor=none` |
| AI sensitive read | `exec -a codex /bin/cat ~/.agentsmith-rs/guard/plan-c-read-1772528008.txt` | ALLOW | exit code `0`, file content printed |
| Sensitive transfer to external dir | `mv ~/.agentsmith-rs/guard/plan-c-rename-1772528008.txt ~/esguard-planc-verify-1772528008/rename-out.txt` | DENY | `op=rename`, `reason=SENSITIVE_TRANSFER_OUT` |
| Sensitive move to quarantine | `mv ~/.agentsmith-rs/guard/plan-c-quarantine-1772528008.txt ~/.agentsmith-rs/guard/quarantine/...` | ALLOW | exit code `0`, no new denial |
| AI taint write-out deny | same AI process reads sensitive then writes external (`python3`) | DENY | `op=create`, `reason=TAINT_WRITE_OUT`, `process=Python`, `ancestor=tainted` |
| AI exfil tool exec deny | `exec -a codex /usr/bin/curl ...` | DENY | `op=exec`, `reason=EXEC_EXFIL_TOOL`, `process=curl`, `ancestor=codex` |

Notes:

- In the `cp` transfer test, the first deny reason observed was `TAINT_WRITE_OUT` (same-process read->write path), which is expected under taint enforcement.
- A `launchctl submit` test job was briefly left running and repeatedly triggered read denials; it was cleaned up via `launchctl remove dev.esguard.nonai.read.1772528008`.

## Automated Checks Run

```bash
cargo test -p agentsmith-rs -- --nocapture
NIXPKGS_ALLOW_UNFREE=1 nix build --impure --extra-experimental-features nix-command --extra-experimental-features flakes ".#darwinConfigurations.macbook-pro-m4.system"
```

Observed: both commands passed.

## Egress Layer Status

- `dev.codex-egress-guard-sync` currently shows historical `last exit code = 78 (EX_CONFIG)`.
- Current sync script behavior is to skip apply and exit `0` when allowlist is absent.
- Remaining rollout item: create and maintain `~/.agentsmith-rs/guard/egress-allowlist.txt`, then re-run daemon sync and confirm clean status.

## Notes / Boundaries

- Endpoint Security handles file/exec authorization decisions for Plan C.
- Generic outbound domain/IP control is outside ES itself; full C-scope depends on PF-based egress layer (`agentsmith-egress` + launchd sync).
