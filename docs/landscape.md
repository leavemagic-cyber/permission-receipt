# Competitive landscape

Snapshot date: 2026-08-30.

The repository was launched only after checking whether GitHub already had a substantially equivalent product. The search found important adjacent tools, but no inspected repository combined these exact boundaries:

- Claude Code and Codex;
- persisted rule changes between two local snapshots;
- symbolic scope/source plus a locator;
- no runtime approval, policy synchronization, or model call;
- no stored rule literals;
- explicit refusal to infer the user's prompt choice or effective authorization.

## Closest inspected projects

| Project | Observed stars | What it does | Different boundary |
|---|---:|---|---|
| [Mearman/agent-permissions](https://github.com/Mearman/agent-permissions) | 2 | Cross-agent canonical permission policy, sync, CLI, and evaluator | Manages and synchronizes policy; does not issue a before/after cross-host disk-rule receipt |
| [tantk/permission-hook](https://github.com/tantk/permission-hook) | 4 | Fast Claude-oriented runtime allow/deny/ask hook and recent-prompt data | Evaluates permission requests; does not compare persisted Claude/Codex rule sources |
| [selfradiance/reapproval-gate](https://github.com/selfradiance/reapproval-gate) | 0 | Checks a proposed action against an approved scope before execution | Produces pre-action reapproval decisions; does not snapshot agent permission files |
| [disler/claude-code-hooks-mastery](https://github.com/disler/claude-code-hooks-mastery) | 3,907 | Broad Claude Code hook examples and education | General hook library, not this receipt product |

Stars and activity are current observations, not adoption guarantees. Search coverage is not proof that no equivalent repository exists.

## Upstream gap reports

- [anthropics/claude-code#40634](https://github.com/anthropics/claude-code/issues/40634): a user reported that available hook/log surfaces did not capture the final approval method after settings evaluation. The issue was automatically closed for inactivity on 2026-05-02, not as a documented product fix.
- The open [openai/codex#27157](https://github.com/openai/codex/issues/27157) reports that persisted prefix approvals lack an in-app review/remove surface.
- The open [openai/codex#29145](https://github.com/openai/codex/issues/29145) reports that interactive execpolicy amendments are generally saved at user scope while project-local authoring is manual.

These are user reports and demand signals, not authoritative proof of current product behavior. The scanner boundary itself follows the hosts' current settings/rules documentation and source.

## Positioning decision

Permission Receipt is not another allowlist manager, hook engine, or security score. Its narrow job is to make a verifiable disk change visible without expanding authority or duplicating sensitive rule text.

If an active, maintained project or upstream feature gains cross-Claude/Codex persisted-rule delta receipts with the same privacy and claim boundary, this repository should narrow again or stop rather than manufacture differentiation.
