# Security policy

## Supported versions

The latest tagged release receives security fixes.

## Report a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/leavemagic-cyber/permission-receipt/security/advisories/new). Do not include sensitive permission rules, tokens, private paths, or real configuration files in a public issue.

Reports are especially useful for:

- rule literals or unrelated settings leaking into a receipt;
- terminal, Markdown, JSON, or path injection;
- parser inputs causing code execution;
- symlink or race behavior reading an unintended file;
- partial-read failures being reported as clean drift;
- unexpected mutation of Claude Code or Codex configuration.

You should receive an initial response within seven days.
