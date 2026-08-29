# Repository instructions

Permission Receipt is a read-only privacy tool, not a permission manager.

- Preserve the claim boundary in `README.md`: disk-rule drift is not a prompt-choice or effective-authorization verdict.
- Use synthetic temporary fixtures only. Never inspect real user agent settings while developing or testing.
- Never persist full Claude specifiers, Codex patterns, command arguments, private absolute paths, or unrelated settings.
- Unknown syntax and partial reads fail closed. Do not convert errors into empty snapshots.
- Keep runtime dependencies at zero unless a concrete safety requirement cannot be met with the standard library.
- Run `python -B -m unittest discover -s tests -v` and the installed `permission-receipt demo --format json` path before release.
