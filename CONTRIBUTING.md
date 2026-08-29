# Contributing

Small, reviewable contributions are welcome.

## Set up

```bash
python -m pip install -e .
python -B -m unittest discover -s tests -v
permission-receipt demo --format json
```

## Non-negotiable boundaries

- Tests use disposable fixtures only. Never read or commit a contributor's real Claude Code or Codex settings.
- Never add transcript, session, history, auth, `.env`, or `~/.claude.json` readers.
- Baselines and reports must not contain full Claude specifiers, Codex patterns, command arguments, hostnames, tokens, or private absolute paths.
- Invalid or unreadable in-scope sources are errors, not empty permission sets.
- Do not infer who changed a rule, which approval button was used, whether a rule is effective, or whether an operation is safe.
- No auto-approval or config mutation belongs in v0.1.

## Pull requests

Keep each pull request to one concern. Include:

- the behavior being changed;
- tests for success and failure paths;
- the exact validation commands run;
- any change to the privacy or claim boundary.

Security findings should use GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).
