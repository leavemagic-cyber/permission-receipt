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
| [disler/claude-code-hooks-mastery](https://github.com/disler/claude-code-hooks-mastery) | 3,907 | Broad Claude Code hook examples and education | General hook library, not this receipt product |

Stars and activity are current observations, not adoption guarantees. Search coverage is not proof that no equivalent repository exists.

## Upstream gap evidence

- [anthropics/claude-code#40634](https://github.com/anthropics/claude-code/issues/40634): available hook/log surfaces do not capture the final approval method after settings evaluation.
- [openai/codex#27157](https://github.com/openai/codex/issues/27157): users can persist prefix approvals but lack an in-app way to review or remove them.
- [openai/codex#29145](https://github.com/openai/codex/issues/29145): current persisted execpolicy amendments are generally user-global, while project-local authoring requires manual work.

## Positioning decision

Permission Receipt is not another allowlist manager, hook engine, or security score. Its narrow job is to make a verifiable disk change visible without expanding authority or duplicating sensitive rule text.

If an active, maintained project or upstream feature gains cross-Claude/Codex persisted-rule delta receipts with the same privacy and claim boundary, this repository should narrow again or stop rather than manufacture differentiation.
