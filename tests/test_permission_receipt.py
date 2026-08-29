from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from permission_receipt import cli
from permission_receipt.core import (
    ReceiptError,
    compare,
    demo_report,
    parse_claude_settings,
    parse_codex_rules,
    read_snapshot,
    render_markdown,
    render_text,
    scan_permissions,
    write_snapshot,
)

SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
SECRET = "API_KEY_SENTINEL_never_persist"


class PermissionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        base = Path(self.temporary.name)
        self.root = base / "project with spaces"
        self.home = base / "home"
        self.claude_home = base / "claude-home"
        self.codex_home = base / "codex-home"
        for path in (self.root, self.home, self.claude_home, self.codex_home):
            path.mkdir(parents=True)
        self.env = {
            "CLAUDE_CONFIG_DIR": str(self.claude_home),
            "CODEX_HOME": str(self.codex_home),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def scan(self, created_at: str = "2026-08-30T01:00:00Z"):
        return scan_permissions(
            self.root,
            home=self.home,
            env=self.env,
            created_at=created_at,
            fingerprint_salt=SALT,
        )

    def test_scans_documented_scopes_without_persisting_literals(self) -> None:
        user_settings = self.claude_home / "settings.json"
        project_settings = self.root / ".claude" / "settings.json"
        local_settings = self.root / ".claude" / "settings.local.json"
        self.write(
            user_settings,
            json.dumps(
                {
                    "permissions": {"allow": [f"Bash(curl --token {SECRET})"]},
                    "env": {"IGNORED_SECRET": SECRET},
                }
            ),
        )
        self.write(project_settings, '{"permissions":{"ask":["Write(./dist/**)"]}}')
        self.write(local_settings, '{"permissions":{"deny":["Read(./.env)"]}}')
        self.write(
            self.codex_home / "rules" / "default.rules",
            """
prefix_rule(pattern=["gh", ["pr", "issue"], "view"], decision="allow")
prefix_rule(pattern=["cargo", "publish"], decision="prompt")
prefix_rule(pattern=["rm"], decision="forbidden")
""".strip(),
        )
        self.write(
            self.root / ".codex" / "rules" / "project.rules",
            'prefix_rule(pattern=["npm", "test"])',
        )
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (user_settings, project_settings, local_settings)}

        snapshot = self.scan()

        self.assertEqual(len(snapshot.entries), 7)
        self.assertEqual({entry.kind for entry in snapshot.entries}, {"allow", "ask", "deny"})
        self.assertEqual({entry.scope for entry in snapshot.entries}, {"user", "project", "local"})
        serialized = json.dumps(snapshot.as_dict(), ensure_ascii=False)
        self.assertNotIn(SECRET, serialized)
        self.assertNotIn("cargo", serialized)
        self.assertNotIn(str(self.home), serialized)
        self.assertIn("<details withheld>", serialized)
        self.assertEqual(
            before,
            {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before},
        )

    def test_reorder_is_not_drift_and_duplicate_count_is(self) -> None:
        settings = self.root / ".claude" / "settings.json"
        self.write(settings, '{"permissions":{"allow":["Read","Bash(git status)"]}}')
        baseline = self.scan()
        self.write(settings, '{"permissions":{"allow":["Bash(git status)","Read"]}}')
        reordered = self.scan("2026-08-30T01:01:00Z")
        self.assertFalse(compare(baseline, reordered).changed)

        self.write(settings, '{"permissions":{"allow":["Read","Bash(git status)","Read"]}}')
        duplicate = self.scan("2026-08-30T01:02:00Z")
        report = compare(baseline, duplicate)
        self.assertEqual(len(report.added), 1)
        self.assertEqual(report.added[0].display, "Read")

    def test_scope_move_is_remove_plus_add(self) -> None:
        project = self.root / ".claude" / "settings.json"
        local = self.root / ".claude" / "settings.local.json"
        self.write(project, '{"permissions":{"allow":["Bash(npm test)"]}}')
        baseline = self.scan()
        self.write(project, '{"permissions":{"allow":[]}}')
        self.write(local, '{"permissions":{"allow":["Bash(npm test)"]}}')
        report = compare(baseline, self.scan("2026-08-30T01:03:00Z"))
        self.assertEqual((len(report.added), len(report.removed)), (1, 1))
        self.assertEqual((report.added[0].scope, report.removed[0].scope), ("local", "project"))

    def test_json_validation_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(ReceiptError, "duplicate JSON key"):
            parse_claude_settings(
                '{"permissions":{"allow":[],"allow":["Read"]}}', "user", "<user>/settings.json", SALT
            )
        for invalid in ("[]", '{"permissions":[]}', '{"permissions":{"allow":[1]}}', "{"):
            with self.subTest(invalid=invalid), self.assertRaises(ReceiptError):
                parse_claude_settings(invalid, "user", "<user>/settings.json", SALT)

    def test_codex_parser_accepts_literals_and_rejects_code(self) -> None:
        valid = """
# comment
prefix_rule(
  pattern=["echo", ["a)", "b#"]],
  decision="allow",
  justification="literal ) and # are harmless",
)
"""
        entries = parse_codex_rules(valid, "user", "<codex-user>/rules/default.rules", SALT)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].kind, "allow")
        self.assertEqual(entries[0].locator, "lines 3-7")
        self.assertNotIn("echo", entries[0].display)

        malicious = (
            'prefix_rule(pattern=__import__("os").system("echo pwned"))',
            'prefix_rule(pattern=[x for x in ["git"]])',
            'prefix_rule(pattern=["git"], **{"decision":"allow"})',
            'prefix_rule(pattern=["git"], unknown="allow")',
            'prefix_rule(pattern=[])',
            'prefix_rule pattern=["git"]',
        )
        with mock.patch("os.system", side_effect=AssertionError("must not execute")):
            for source in malicious:
                with self.subTest(source=source), self.assertRaises(ReceiptError):
                    parse_codex_rules(source, "user", "<codex-user>/rules/default.rules", SALT)

    def test_snapshot_is_private_atomic_and_guarded(self) -> None:
        settings = self.root / ".claude" / "settings.json"
        self.write(settings, json.dumps({"permissions": {"allow": [f"Bash(echo {SECRET})"]}}))
        snapshot = self.scan()
        receipt = self.root / ".permission-receipt" / "baseline.json"
        write_snapshot(snapshot, receipt)
        payload = receipt.read_text(encoding="utf-8")
        self.assertNotIn(SECRET, payload)
        self.assertEqual(read_snapshot(receipt), snapshot)
        with self.assertRaisesRegex(ReceiptError, "already exists"):
            write_snapshot(snapshot, receipt)
        write_snapshot(snapshot, receipt, overwrite=True)
        if os.name != "nt":
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        with mock.patch("tempfile.NamedTemporaryFile", side_effect=PermissionError):
            with self.assertRaisesRegex(ReceiptError, "cannot write baseline receipt"):
                write_snapshot(snapshot, self.root / "blocked.json")

    def test_bad_receipts_are_rejected(self) -> None:
        receipt = self.root / "bad.json"
        for payload in (
            "{}",
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":999,"created_at":"x","entries":[],"sources_checked":[]}',
        ):
            self.write(receipt, payload)
            with self.subTest(payload=payload), self.assertRaises(ReceiptError):
                read_snapshot(receipt)

        self.write(
            receipt,
            json.dumps(
                {
                    "schema_version": 1,
                    "created_at": "not-a-timestamp",
                    "fingerprint_salt": SALT.hex(),
                    "entries": [],
                    "sources_checked": [],
                }
            ),
        )
        with self.assertRaisesRegex(ReceiptError, "incomplete"):
            read_snapshot(receipt)

    def test_source_limits_and_partial_failures_are_fail_closed(self) -> None:
        settings = self.root / ".claude" / "settings.json"
        self.write(settings, '{"permissions":{"allow":["Read"]}}')
        baseline = self.scan()
        self.write(settings, "{" + "x" * 1_048_576)
        with self.assertRaisesRegex(ReceiptError, "exceeds 1 MiB"):
            self.scan()

        self.write(
            settings,
            json.dumps({"permissions": {"allow": ["Read"] * 1_001}}),
        )
        with self.assertRaisesRegex(ReceiptError, "more than 1000"):
            self.scan()
        self.assertEqual(len(baseline.entries), 1)

    def test_symlink_sources_are_refused_when_supported(self) -> None:
        target = self.root / "real-settings.json"
        link = self.root / ".claude" / "settings.json"
        self.write(target, '{"permissions":{"allow":["Read"]}}')
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(ReceiptError, "symlink"):
            self.scan()

    def test_redirected_project_ancestor_is_refused(self) -> None:
        outside = self.root.parent / "outside-claude"
        self.write(outside / "settings.json", '{"permissions":{"allow":["Read"]}}')
        redirected = self.root / ".claude"
        if os.name == "nt":
            result = subprocess.run(
                ["cmd", "/d", "/c", "mklink", "/J", str(redirected), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest("junction creation is unavailable")
            self.addCleanup(lambda: os.rmdir(redirected) if redirected.exists() else None)
        else:
            redirected.symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(ReceiptError, "redirected source path"):
            self.scan()

    def test_symlink_receipts_and_default_directory_escape_are_refused_when_supported(self) -> None:
        snapshot = self.scan()
        outside = self.root.parent / "outside"
        outside.mkdir()
        target = outside / "baseline.json"
        write_snapshot(snapshot, target)
        receipt_link = self.root / "receipt-link.json"
        default_directory = self.root / ".permission-receipt"
        try:
            receipt_link.symlink_to(target)
            default_directory.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation is unavailable")

        with self.assertRaisesRegex(ReceiptError, "symlink"):
            read_snapshot(receipt_link)
        with self.assertRaisesRegex(ReceiptError, "symlink"):
            write_snapshot(snapshot, receipt_link, overwrite=True)
        with self.assertRaisesRegex(ReceiptError, "outside the project"):
            cli._receipt_path(self.root, None)

    def test_control_characters_cannot_inject_terminal_or_markdown(self) -> None:
        entries = parse_claude_settings(
            json.dumps({"permissions": {"allow": ["Bad\u001b[31m(<script>)"]}}),
            "user",
            "<user>/settings.json",
            SALT,
        )
        baseline = self.scan()
        current = type(baseline)(baseline.created_at, baseline.fingerprint_salt, tuple(entries), baseline.sources_checked)
        report = compare(type(baseline)(baseline.created_at, baseline.fingerprint_salt, (), baseline.sources_checked), current)
        text = render_text(report)
        markdown = render_markdown(report)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("<script>", markdown)

    def test_modified_receipt_cannot_inject_controls_bidi_or_markdown(self) -> None:
        receipt = self.root / "modified.json"
        self.write(
            receipt,
            json.dumps(
                {
                    "schema_version": 1,
                    "created_at": "2026-08-30T01:00:00Z",
                    "fingerprint_salt": SALT.hex(),
                    "entries": [
                        {
                            "host": "claude",
                            "scope": "user",
                            "kind": "allow",
                            "source": "`source\u001b\u202e</code><script>",
                            "locator": "`locator\u2066",
                            "rule": "`rule\u0007</code><script>",
                            "fingerprint": "0" * 64,
                        }
                    ],
                    "sources_checked": [],
                },
                ensure_ascii=False,
            ),
        )
        baseline = read_snapshot(receipt)
        current = type(baseline)(
            "2026-08-30T01:01:00Z",
            baseline.fingerprint_salt,
            (),
            baseline.sources_checked,
        )
        report = compare(baseline, current)
        text = render_text(report)
        markdown = render_markdown(report)
        for rendered in (text, markdown):
            self.assertNotIn("\x1b", rendered)
            self.assertNotIn("\u202e", rendered)
            self.assertNotIn("\u2066", rendered)
        self.assertIn(r"\u202e", text)
        self.assertNotIn("</code><script>", markdown)

    def test_demo_is_synthetic_and_deterministic(self) -> None:
        with mock.patch("permission_receipt.cli.scan_permissions", side_effect=AssertionError("demo read settings")):
            first = io.StringIO()
            with contextlib.redirect_stdout(first):
                self.assertEqual(cli.main(["demo", "--format", "json"]), 0)
            second = io.StringIO()
            with contextlib.redirect_stdout(second):
                self.assertEqual(cli.main(["demo", "--format", "json"]), 0)
        self.assertEqual(first.getvalue(), second.getvalue())
        self.assertEqual(json.loads(first.getvalue())["review_first_count"], 2)

    def test_cli_baseline_and_check_have_diff_exit_codes(self) -> None:
        settings = self.root / ".claude" / "settings.local.json"
        self.write(settings, '{"permissions":{"allow":[]}}')
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(cli.main(["baseline", "--root", str(self.root)]), 0)
        self.assertEqual(errors.getvalue(), "")

        self.write(settings, json.dumps({"permissions": {"allow": [f"Bash(echo {SECRET})"]}}))
        output = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=False), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["check", "--root", str(self.root), "--format", "json"]), 1)
        report = json.loads(output.getvalue())
        self.assertTrue(report["drift"])
        self.assertNotIn(SECRET, output.getvalue())

        with mock.patch.dict(os.environ, self.env, clear=False), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["baseline", "--root", str(self.root), "--force"]), 0)
            self.assertEqual(cli.main(["check", "--root", str(self.root)]), 0)


if __name__ == "__main__":
    unittest.main()
