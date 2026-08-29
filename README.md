# permission-receipt

**Every “always allow” should leave a receipt.**

See which persisted Claude Code and Codex permission rules appeared or disappeared between two moments. Local-only, deterministic, and runtime dependency-free.

[![CI](https://github.com/leavemagic-cyber/permission-receipt/actions/workflows/ci.yml/badge.svg)](https://github.com/leavemagic-cyber/permission-receipt/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](pyproject.toml)
[![No telemetry](https://img.shields.io/badge/telemetry-none-success.svg)](#privacy-by-construction)

```text
PERMISSION RECEIPT
baseline 2026-08-30T09:00:00Z  checked 2026-08-30T09:14:00Z
configured rules only; not effective runtime authorization

ALLOW RULES ADDED (2)
+ claude / local / allow
  Bash(<details withheld>)
  source: <project>/.claude/settings.local.json
  locator: /permissions/allow/2
+ codex / user / allow
  prefix_rule(pattern=<3 positions>, decision="allow")
  source: ~/.codex/rules/default.rules
  locator: lines 8-11
```

The rule details are deliberately withheld. A receipt should help you find a trust change without making another copy of a command that may contain a token, hostname, or private path.

## Quick start

Install directly from GitHub:

```bash
pipx install git+https://github.com/leavemagic-cyber/permission-receipt.git
```

Or with `uv`:

```bash
uv tool install git+https://github.com/leavemagic-cyber/permission-receipt.git
```

Before a coding-agent session, save the on-disk rule state:

```bash
permission-receipt baseline
```

After the session, compare it:

```bash
permission-receipt check
```

`check` exits `0` for no drift, `1` when persisted rules changed, and `2` when a source or receipt cannot be read safely. It never changes either agent's settings.

Try the synthetic demo without reading any local settings:

```bash
permission-receipt demo
permission-receipt demo --format markdown
permission-receipt demo --format json
```

## What it observes

Only these documented permission values are extracted. Claude's containing JSON settings files are parsed as a whole, but unrelated fields are discarded before snapshot serialization:

| Host | Scope | Source | Data |
|---|---|---|---|
| Claude Code | user | `$CLAUDE_CONFIG_DIR/settings.json` or `~/.claude/settings.json` | `permissions.allow`, `ask`, `deny` |
| Claude Code | project | `<project>/.claude/settings.json` | `permissions.allow`, `ask`, `deny` |
| Claude Code | local | `<project>/.claude/settings.local.json` | `permissions.allow`, `ask`, `deny` |
| Codex | user | `$CODEX_HOME/rules/*.rules` or `~/.codex/rules/*.rules` | literal `prefix_rule(...)` calls |
| Codex | project | `<project>/.codex/rules/*.rules` | literal `prefix_rule(...)` calls |

The selected project is the current Git root, or the path supplied with `--root`. Version 0.1 does not reconstruct vendor-specific worktree redirects or remote/cloud configuration.

Claude Code merges permission arrays across scopes and applies other trust and policy layers. Codex project rules also depend on the project configuration layer being trusted, and its execpolicy language remains subject to change. The receipt therefore reports **configured disk-rule drift**, not an effective authorization verdict.

## Privacy by construction

- No network calls, model calls, telemetry, or runtime dependencies.
- Never reads transcripts, session history, auth data, `.env`, or `~/.claude.json`.
- Parses each selected Claude settings file as a whole, then ignores unrelated fields; those fields are never copied into the baseline or report.
- Never stores full permission rules. Baselines contain a random salt, salted fingerprints, coarse rule shapes, symbolic source labels, and locators.
- A baseline is neither encrypted nor signed. Its stored salt permits offline guessing of common rules, and a modified file can fabricate a comparison; keep it private and uncommitted.
- Unknown or damaged JSON, unsupported `prefix_rule` syntax, unreadable files, redirected source paths, receipt-file symlinks, oversized inputs, and mid-read changes fail closed.
- JSON and terminal output escape control characters and never include literal command patterns.
- Baselines are atomically written and set to mode `0600` where POSIX permissions exist.

You can inspect the receipt yourself at `.permission-receipt/baseline.json`. The directory is ignored by this repository and should remain uncommitted in yours.

## Claim boundary

Permission Receipt can say:

> An on-disk allow rule was added between these two snapshots.

It cannot say:

- which UI button, person, hook, or manual edit caused the change;
- whether a session-only approval happened;
- whether a configured rule was active, matched, or overruled;
- whether an operation was safe;
- what happened in a remote environment whose files are not local.

Those limits are the product boundary, not missing confidence labels.

## Commands

```text
permission-receipt baseline [--root PATH] [--receipt FILE] [--force] [--json]
permission-receipt check    [--root PATH] [--receipt FILE] [--format text|markdown|json]
permission-receipt demo     [--format text|markdown|json]
```

The default baseline is `<project>/.permission-receipt/baseline.json`. `baseline` refuses to overwrite it unless `--force` is explicit.

## Why this exists

Users have reported the gap in both upstream trackers:

- In [Claude Code #40634](https://github.com/anthropics/claude-code/issues/40634), a user reported that available logs did not capture the final manual-vs-rule approval method. The issue was later closed automatically for inactivity, not as a documented product fix.
- In the open [Codex #27157](https://github.com/openai/codex/issues/27157), a user reports that persisted command-approval rules lack an in-app review/remove surface and must be hand-edited.

Permission Receipt does not pretend to reconstruct approval events. It solves the smaller, verifiable problem: **what persisted rule data changed on disk?**

The current competitive scan and positioning are in [docs/landscape.md](docs/landscape.md).

## Development

```bash
python -m pip install -e .
python -B -m unittest discover -s tests -v
permission-receipt demo --format json
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for fixture and claim rules. Security issues belong in [private vulnerability reports](https://github.com/leavemagic-cyber/permission-receipt/security/advisories/new), not public issues.

Traditional Chinese: [README.zh-TW.md](README.zh-TW.md)

## License

MIT
