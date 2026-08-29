from __future__ import annotations

import ast
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import tempfile
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

SCHEMA_VERSION = 1
KINDS = ("allow", "ask", "deny")
MAX_SOURCE_BYTES = 1_048_576
MAX_RECEIPT_BYTES = 4_194_304
MAX_RULES = 1_000
_WINDOWS_REPARSE_POINT = 0x400


class ReceiptError(Exception):
    """A source or receipt could not be read without guessing."""


@dataclass(frozen=True, slots=True)
class Entry:
    host: str
    scope: str
    kind: str
    source: str
    locator: str
    display: str
    fingerprint: str

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.host, self.scope, self.kind, self.source, self.fingerprint)

    def as_dict(self) -> dict[str, str]:
        return {
            "host": self.host,
            "scope": self.scope,
            "kind": self.kind,
            "source": self.source,
            "locator": self.locator,
            "rule": self.display,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Entry":
        required = ("host", "scope", "kind", "source", "locator", "rule", "fingerprint")
        if any(not isinstance(data.get(field), str) for field in required):
            raise ReceiptError("receipt contains an invalid permission entry")
        if data["host"] not in {"claude", "codex"} or data["scope"] not in {
            "user",
            "project",
            "local",
        }:
            raise ReceiptError("receipt contains an invalid host or scope")
        if data["kind"] not in KINDS or not re.fullmatch(r"[0-9a-f]{64}", str(data["fingerprint"])):
            raise ReceiptError("receipt contains an invalid kind or fingerprint")
        return cls(
            host=str(data["host"]),
            scope=str(data["scope"]),
            kind=str(data["kind"]),
            source=safe_display(str(data["source"])),
            locator=safe_display(str(data["locator"])),
            display=safe_display(str(data["rule"])),
            fingerprint=str(data["fingerprint"]),
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    created_at: str
    fingerprint_salt: str
    entries: tuple[Entry, ...]
    sources_checked: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "created_at": self.created_at,
            "fingerprint_salt": self.fingerprint_salt,
            "entries": [entry.as_dict() for entry in self.entries],
            "sources_checked": list(self.sources_checked),
            "privacy": "rule literals are withheld; salted fingerprints support comparison",
        }


@dataclass(frozen=True, slots=True)
class Report:
    baseline_created_at: str
    checked_at: str
    added: tuple[Entry, ...]
    removed: tuple[Entry, ...]

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    @property
    def added_allows(self) -> tuple[Entry, ...]:
        return tuple(entry for entry in self.added if entry.kind == "allow")

    @property
    def removed_restrictions(self) -> tuple[Entry, ...]:
        return tuple(entry for entry in self.removed if entry.kind in {"ask", "deny"})

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "baseline_created_at": self.baseline_created_at,
            "checked_at": self.checked_at,
            "complete": True,
            "drift": self.changed,
            "changed": self.changed,
            "review_first_count": len(self.added_allows) + len(self.removed_restrictions),
            "added": [entry.as_dict() for entry in self.added],
            "removed": [entry.as_dict() for entry in self.removed],
            "claim_boundary": "persisted configuration diff, not effective runtime authorization",
            "limits": {
                "observes_disk_rules_only": True,
                "observes_prompt_choice": False,
                "knows_runtime_effectiveness": False,
                "auto_approves": False,
                "can_restore_hidden_literals": False,
            },
            "errors": [],
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_display(value: str, limit: int = 320) -> str:
    escaped: list[str] = []
    for char in value:
        code = ord(char)
        if char == "\n":
            escaped.append(r"\n")
        elif char == "\r":
            escaped.append(r"\r")
        elif char == "\t":
            escaped.append(r"\t")
        elif code < 32 or code == 127:
            escaped.append(f"\\x{code:02x}")
        elif unicodedata.category(char) in {"Cc", "Cf"}:
            escaped.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            escaped.append(char)
    result = "".join(escaped)
    return result if len(result) <= limit else result[: limit - 1] + "…"


def _guard_source_path(path: Path, anchor: Path, label: str) -> None:
    """Refuse source paths redirected outside their declared settings scope."""
    anchor = anchor.resolve()
    candidate = path.absolute()
    try:
        relative = candidate.relative_to(anchor)
    except ValueError as exc:
        raise ReceiptError(f"source is outside its settings scope: {safe_display(label)}") from exc

    current = anchor
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ReceiptError(
                f"cannot inspect source path {safe_display(label)}: {exc.__class__.__name__}"
            ) from exc
        if current.is_symlink() or (
            os.name == "nt"
            and getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
        ):
            raise ReceiptError(f"refusing redirected source path {safe_display(label)}")

    try:
        candidate.resolve().relative_to(anchor)
    except (OSError, ValueError) as exc:
        raise ReceiptError(f"source resolves outside its settings scope: {safe_display(label)}") from exc


def _entry(
    host: str,
    scope: str,
    kind: str,
    source: str,
    locator: str,
    raw: str,
    display: str,
    salt: bytes,
) -> Entry:
    material = json.dumps(
        [host, scope, kind, source, raw], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    fingerprint = hmac.new(salt, material, hashlib.sha256).hexdigest()
    return Entry(
        host,
        scope,
        kind,
        safe_display(source),
        safe_display(locator),
        safe_display(display),
        fingerprint,
    )


def _read_text(path: Path, label: str) -> str:
    label = safe_display(label)
    try:
        if path.is_symlink():
            raise ReceiptError(f"refusing symlink source {label}")
        before = path.stat()
        if before.st_size > MAX_SOURCE_BYTES:
            raise ReceiptError(f"source exceeds 1 MiB: {label}")
        payload = path.read_bytes()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ReceiptError(f"source changed while reading: {label}")
        return payload.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ReceiptError(f"cannot read {label}: {exc.__class__.__name__}") from exc


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError(f"duplicate JSON key: {safe_display(key)}")
        result[key] = value
    return result


def _claude_shape(rule: str) -> str:
    match = re.match(r"^([A-Za-z][A-Za-z0-9_.:-]*)", rule)
    if not match:
        return "<permission rule details withheld>"
    tool = safe_display(match.group(1), limit=80)
    return tool if "(" not in rule else f"{tool}(<details withheld>)"


def parse_claude_settings(text: str, scope: str, source: str, salt: bytes) -> list[Entry]:
    source = safe_display(source)
    try:
        data = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise ReceiptError(f"invalid JSON in {source}: line {exc.lineno}") from exc
    if not isinstance(data, dict):
        raise ReceiptError(f"{source} must contain a JSON object")
    permissions = data.get("permissions")
    if permissions is None:
        return []
    if not isinstance(permissions, dict):
        raise ReceiptError(f"permissions in {source} must be an object")
    entries: list[Entry] = []
    for kind in KINDS:
        rules = permissions.get(kind, [])
        if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
            raise ReceiptError(f"permissions.{kind} in {source} must be a string array")
        entries.extend(
            _entry(
                "claude",
                scope,
                kind,
                source,
                f"/permissions/{kind}/{index}",
                rule,
                _claude_shape(rule),
                salt,
            )
            for index, rule in enumerate(rules)
        )
    return entries


_PREFIX_START = re.compile(r"(?m)^[ \t]*prefix_rule[ \t]*\(")
_PREFIX_TOKEN = re.compile(r"(?m)^[ \t]*prefix_rule\b")


def _call_end(text: str, open_index: int, source: str) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    comment = False
    for index in range(open_index, len(text)):
        char = text[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "#":
            comment = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
    raise ReceiptError(f"unterminated prefix_rule in {source}")


def _validate_pattern(value: object, source: str) -> object:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_validate_pattern(item, source) for item in value]
    raise ReceiptError(f"non-literal prefix_rule pattern in {source}")


def _pattern_shape(pattern: list[object]) -> str:
    alternatives = sum(1 for item in pattern if isinstance(item, list))
    if not alternatives:
        return f"<{len(pattern)} positions>"
    noun = "set" if alternatives == 1 else "sets"
    return f"<{len(pattern)} positions, {alternatives} alternative {noun}>"


def parse_codex_rules(text: str, scope: str, source: str, salt: bytes) -> list[Entry]:
    source = safe_display(source)
    entries: list[Entry] = []
    position = 0
    starts = {match.start() for match in _PREFIX_START.finditer(text)}
    for token in _PREFIX_TOKEN.finditer(text):
        if token.start() not in starts:
            line = text.count("\n", 0, token.start()) + 1
            raise ReceiptError(f"unsupported prefix_rule in {source}: line {line}")
    while match := _PREFIX_START.search(text, position):
        open_index = text.find("(", match.start())
        end = _call_end(text, open_index, source)
        block = text[match.start() : end].strip()
        position = end
        try:
            node = ast.parse(block, mode="eval").body
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "prefix_rule":
                raise ValueError
            if node.args or any(keyword.arg is None for keyword in node.keywords):
                raise ValueError
            allowed = {"pattern", "decision", "justification", "match", "not_match"}
            if any(keyword.arg not in allowed for keyword in node.keywords):
                raise ValueError
            values = {keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords}
            pattern = _validate_pattern(values["pattern"], source)
            decision = values.get("decision", "allow")
        except (KeyError, ValueError, SyntaxError) as exc:
            line = text.count("\n", 0, match.start()) + 1
            raise ReceiptError(f"unsupported prefix_rule in {source}: line {line}") from exc
        if not isinstance(pattern, list) or not pattern:
            raise ReceiptError(f"prefix_rule pattern must be a non-empty list in {source}")
        if decision not in {"allow", "prompt", "forbidden"}:
            raise ReceiptError(f"invalid prefix_rule decision in {source}: {decision!r}")
        kind = {"allow": "allow", "prompt": "ask", "forbidden": "deny"}[str(decision)]
        raw = json.dumps(
            {"decision": decision, "pattern": pattern}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        start_line = text.count("\n", 0, match.start()) + 1
        end_line = text.count("\n", 0, end) + 1
        display = f"prefix_rule(pattern={_pattern_shape(pattern)}, decision={json.dumps(decision)})"
        entries.append(
            _entry("codex", scope, kind, source, f"lines {start_line}-{end_line}", raw, display, salt)
        )
    return entries


def _rules_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    if directory.is_symlink():
        raise ReceiptError("refusing symlink rules directory")
    try:
        return sorted(path for path in directory.glob("*.rules") if path.is_file())
    except OSError as exc:
        raise ReceiptError(f"cannot enumerate rules directory: {exc.__class__.__name__}") from exc


def scan_permissions(
    project_root: Path,
    *,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
    created_at: str | None = None,
    fingerprint_salt: bytes | None = None,
) -> Snapshot:
    project_root = project_root.resolve()
    home = (home or Path.home()).resolve()
    env = os.environ if env is None else env
    fingerprint_salt = fingerprint_salt or secrets.token_bytes(16)
    claude_home = Path(env.get("CLAUDE_CONFIG_DIR", str(home / ".claude"))).expanduser().resolve()
    codex_home = Path(env.get("CODEX_HOME", str(home / ".codex"))).expanduser().resolve()

    entries: list[Entry] = []
    sources = [
        "$CLAUDE_CONFIG_DIR/settings.json" if "CLAUDE_CONFIG_DIR" in env else "~/.claude/settings.json",
        "<project>/.claude/settings.json",
        "<project>/.claude/settings.local.json",
        "$CODEX_HOME/rules/*.rules" if "CODEX_HOME" in env else "~/.codex/rules/*.rules",
        "<project>/.codex/rules/*.rules",
    ]
    claude_sources = (
        (claude_home / "settings.json", claude_home, "user", sources[0]),
        (project_root / ".claude" / "settings.json", project_root, "project", sources[1]),
        (project_root / ".claude" / "settings.local.json", project_root, "local", sources[2]),
    )
    for path, anchor, scope, label in claude_sources:
        _guard_source_path(path, anchor, label)
        if path.is_file():
            entries.extend(parse_claude_settings(_read_text(path, label), scope, label, fingerprint_salt))

    codex_sources = (
        (codex_home / "rules", codex_home, "user", sources[3]),
        (project_root / ".codex" / "rules", project_root, "project", sources[4]),
    )
    for directory, anchor, scope, label in codex_sources:
        _guard_source_path(directory, anchor, label)
        for path in _rules_files(directory):
            file_label = label.replace("*.rules", path.name)
            _guard_source_path(path, anchor, file_label)
            entries.extend(parse_codex_rules(_read_text(path, file_label), scope, file_label, fingerprint_salt))

    if len(entries) > MAX_RULES:
        raise ReceiptError(f"more than {MAX_RULES} permission rules; refusing an incomplete receipt")
    entries.sort(key=lambda item: (item.host, item.scope, item.source, item.kind, item.fingerprint))
    return Snapshot(created_at or utc_now(), fingerprint_salt.hex(), tuple(entries), tuple(sources))


def write_snapshot(snapshot: Snapshot, path: Path, *, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise ReceiptError(f"receipt already exists: {safe_display(path.name)}; use --force to replace it")
    if path.is_symlink():
        raise ReceiptError("refusing to write a receipt through a symlink")
    payload = json.dumps(snapshot.as_dict(), ensure_ascii=False, indent=2) + "\n"
    temporary: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = handle.name
            handle.write(payload)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError as exc:
        raise ReceiptError(f"cannot write baseline receipt: {exc.__class__.__name__}") from exc
    finally:
        if temporary and os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass


def read_snapshot(path: Path) -> Snapshot:
    try:
        if path.is_symlink():
            raise ReceiptError("refusing to read a receipt through a symlink")
        if path.stat().st_size > MAX_RECEIPT_BYTES:
            raise ReceiptError("baseline receipt exceeds 4 MiB")
        data = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except FileNotFoundError as exc:
        raise ReceiptError(f"no baseline receipt at {safe_display(str(path))}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"cannot read baseline receipt: {exc.__class__.__name__}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ReceiptError("unsupported baseline receipt schema")
    raw_entries = data.get("entries")
    raw_sources = data.get("sources_checked")
    salt = data.get("fingerprint_salt")
    created_at = data.get("created_at")
    try:
        if isinstance(created_at, str):
            datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        created_at = None
    if (
        not isinstance(created_at, str)
        or not isinstance(salt, str)
        or not re.fullmatch(r"[0-9a-f]{32}", salt)
        or not isinstance(raw_entries, list)
        or not isinstance(raw_sources, list)
    ):
        raise ReceiptError("baseline receipt is incomplete")
    if len(raw_entries) > MAX_RULES:
        raise ReceiptError(f"baseline receipt contains more than {MAX_RULES} permission rules")
    if any(not isinstance(source, str) for source in raw_sources) or any(
        not isinstance(entry, dict) for entry in raw_entries
    ):
        raise ReceiptError("baseline receipt contains an invalid source")
    return Snapshot(
        str(data["created_at"]),
        salt,
        tuple(Entry.from_dict(entry) for entry in raw_entries),
        tuple(str(source) for source in raw_sources),
    )


def compare(baseline: Snapshot, current: Snapshot) -> Report:
    if baseline.fingerprint_salt != current.fingerprint_salt:
        raise ReceiptError("cannot compare snapshots with different fingerprint salts")
    before = Counter(entry.key for entry in baseline.entries)
    after = Counter(entry.key for entry in current.entries)
    before_entry = {entry.key: entry for entry in baseline.entries}
    after_entry = {entry.key: entry for entry in current.entries}
    added = tuple(
        after_entry[key]
        for key in sorted(after.keys())
        for _ in range(max(0, after[key] - before[key]))
    )
    removed = tuple(
        before_entry[key]
        for key in sorted(before.keys())
        for _ in range(max(0, before[key] - after[key]))
    )
    return Report(baseline.created_at, current.created_at, added, removed)


def _groups(report: Report) -> Iterable[tuple[str, tuple[Entry, ...], str]]:
    yield "ALLOW RULES ADDED", tuple(e for e in report.added if e.kind == "allow"), "+"
    yield "RESTRICTIONS REMOVED", tuple(e for e in report.removed if e.kind in {"ask", "deny"}), "-"
    yield "ALLOW RULES REMOVED", tuple(e for e in report.removed if e.kind == "allow"), "-"
    yield "RESTRICTIONS ADDED", tuple(e for e in report.added if e.kind in {"ask", "deny"}), "+"


def render_text(report: Report) -> str:
    lines = [
        "PERMISSION RECEIPT",
        f"baseline {report.baseline_created_at}  checked {report.checked_at}",
        "configured rules only; not effective runtime authorization",
        "",
    ]
    if not report.changed:
        lines.append("NO PERSISTED RULE CHANGES")
        return "\n".join(lines)
    for title, entries, marker in _groups(report):
        if not entries:
            continue
        lines.append(f"{title} ({len(entries)})")
        for entry in entries:
            lines.extend(
                [
                    f"{marker} {entry.host} / {entry.scope} / {entry.kind}",
                    f"  {entry.display}",
                    f"  source: {entry.source}",
                    f"  locator: {entry.locator}",
                ]
            )
        lines.append("")
    lines.append("Review added allow rules and removed restrictions first. Revoke by removing the shown entry from its source file.")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    lines = [
        "## Permission Receipt",
        "",
        f"Baseline <code>{html.escape(report.baseline_created_at)}</code> / checked <code>{html.escape(report.checked_at)}</code>",
        "",
        "> Persisted configuration diff only; this does not prove effective runtime authorization or which prompt button was used.",
        "",
    ]
    if not report.changed:
        return "\n".join(lines + ["**No persisted rule changes.**"])
    for title, entries, marker in _groups(report):
        if not entries:
            continue
        lines.extend([f"### {title.title()} ({len(entries)})", ""])
        for entry in entries:
            lines.append(
                f"- `{marker}` **{entry.host} / {entry.scope} / {entry.kind}** - "
                f"<code>{html.escape(entry.display)}</code> / <code>{html.escape(entry.source)}</code> / "
                f"<code>{html.escape(entry.locator)}</code>"
            )
        lines.append("")
    lines.append("Review added allow rules and removed restrictions first. Revoke by removing the shown entry from its source file.")
    return "\n".join(lines)


def demo_report() -> Report:
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    baseline = Snapshot("2026-08-30T09:00:00Z", salt.hex(), (), ("demo",))
    current = Snapshot(
        "2026-08-30T09:14:00Z",
        salt.hex(),
        (
            _entry(
                "claude",
                "local",
                "allow",
                "<project>/.claude/settings.local.json",
                "/permissions/allow/2",
                "Bash(npm test *)",
                "Bash(<details withheld>)",
                salt,
            ),
            _entry(
                "codex",
                "user",
                "allow",
                "~/.codex/rules/default.rules",
                "lines 8-11",
                '{"decision":"allow","pattern":["gh","pr","view"]}',
                'prefix_rule(pattern=<3 positions>, decision="allow")',
                salt,
            ),
        ),
        ("demo",),
    )
    return compare(baseline, current)
