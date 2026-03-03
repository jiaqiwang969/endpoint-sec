# Codex Sensitive Data Guard (Plan C) Verification Matrix

Date: 2026-03-03

## Scope

This matrix verifies Plan C behavior after adding:

- sensitive read gate (`AUTH_OPEN`)
- sensitive transfer gate (`AUTH_COPYFILE`/`AUTH_CLONE`/`AUTH_LINK`/`AUTH_EXCHANGEDATA`/`AUTH_RENAME`)
- taint write gate (`AUTH_CREATE`/`AUTH_TRUNCATE`)
- exec exfil gate (`AUTH_EXEC`)
- optional outbound egress allowlist helper (`es-guard-egress`, PF anchor)

## Preconditions

- macOS host has `codex-es-guard` enabled via nix-darwin.
- Policy contains:
  - `sensitive_zones: [ "~/.codex" ]`
  - `sensitive_export_allow_zones: [ "~/.codex/es-guard/quarantine" ]`
  - `read_gate_enabled: true`
  - `transfer_gate_enabled: true`
  - `exec_gate_enabled: true`
- Optional egress layer:
  - `services.codex-egress-guard.enable = true`
  - allowlist file exists at `~/.codex/es-guard/egress-allowlist.txt`

## Verification Matrix

| Scenario | Command | Expected | Reason code |
|---|---|---|---|
| Non-AI read sensitive file | `cat ~/.codex/...` from human terminal | DENY | `SENSITIVE_READ_NON_AI` |
| AI read sensitive file | same read from AI context | ALLOW | n/a |
| Export sensitive file to external dir | `cp ~/.codex/... ~/Desktop/...` | DENY | `SENSITIVE_TRANSFER_OUT` |
| Move sensitive file to quarantine allow-zone | `mv ~/.codex/... ~/.codex/es-guard/quarantine/...` | ALLOW | n/a |
| AI writes outside allow-zone after sensitive read (within TTL) | read sensitive then create/truncate external file | DENY | `TAINT_WRITE_OUT` |
| AI executes obvious exfil tool | `curl/wget/scp/...` in AI context | DENY | `EXEC_EXFIL_TOOL` |
| AI delete in protected zone | `rm` in `protected_zones` | DENY | `PROTECTED_ZONE_AI_DELETE` |
| Egress apply without explicit allowlist | `es-guard-egress --apply` | DENY (cli error) | n/a |
| Egress print rules | `es-guard-egress --print-rules` | Show PF rules | n/a |

## Automated Checks Run

### 1) Guard unit/integration tests

Command:

```bash
cargo test -p codex-es-guard
```

Expected: pass.

### 2) Build package output

Command:

```bash
nix build .#codex-es-guard
```

Expected: pass.

### 3) Egress helper syntax and guardrails

Commands:

```bash
bash -n codex-es-guard/es-guard-egress
codex-es-guard/es-guard-egress --print-rules --user "$USER"
codex-es-guard/es-guard-egress --apply
```

Expected:

- shell syntax check passes
- print-rules prints a PF ruleset template or current applied rules
- apply without allowlist fails with explicit error

## Manual Host Checks (Required)

The following require live host policy + real process ancestry and must be executed manually:

- Non-AI terminal sensitive read deny (`SENSITIVE_READ_NON_AI`)
- AI-sensitive-read allow
- AI exfil-tool deny (`EXEC_EXFIL_TOOL`)
- taint-write deny (`TAINT_WRITE_OUT`)

Use `~/.codex/es-guard/denials.jsonl` and `~/.codex/es-guard/last_denial.txt` to confirm outcomes.

## Notes

- Endpoint Security enforces file and exec authorization decisions.
- Generic domain/IP outbound control is outside ES scope; it is provided by the separate PF egress layer (`es-guard-egress` + `codex-egress-guard` launchd sync).
