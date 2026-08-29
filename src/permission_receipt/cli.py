from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import (
    ReceiptError,
    compare,
    demo_report,
    read_snapshot,
    render_markdown,
    render_text,
    safe_display,
    scan_permissions,
    write_snapshot,
)


def _project_root(start: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return Path(result.stdout.strip()).resolve() if result.returncode == 0 else start.resolve()


def _root(value: str | None) -> Path:
    path = Path(value or ".").expanduser()
    if not path.is_dir():
        raise ReceiptError(f"project root is not a directory: {safe_display(str(path))}")
    return _project_root(path)


def _receipt_path(root: Path, value: str | None) -> Path:
    if value:
        return Path(value).expanduser().absolute()
    path = root / ".permission-receipt" / "baseline.json"
    try:
        path.parent.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ReceiptError("default receipt directory resolves outside the project") from exc
    return path


def _render(report: object, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)
    if output_format == "markdown":
        return render_markdown(report)
    return render_text(report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permission-receipt",
        description="Receipt persisted Claude Code and Codex permission-rule changes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    baseline = commands.add_parser("baseline", help="Save the current persisted permission rules.")
    baseline.add_argument("--root", help="Project directory (defaults to the current git root).")
    baseline.add_argument("--receipt", help="Baseline receipt path.")
    baseline.add_argument("--force", action="store_true", help="Replace an existing baseline receipt.")
    baseline.add_argument("--json", action="store_true", help="Print the redacted snapshot as JSON.")

    check = commands.add_parser("check", help="Compare current rules with the saved baseline.")
    check.add_argument("--root", help="Project directory (defaults to the current git root).")
    check.add_argument("--receipt", help="Baseline receipt path.")
    check.add_argument("--format", choices=("text", "markdown", "json"), default="text")

    demo = commands.add_parser("demo", help="Show a constructed receipt without reading local settings.")
    demo.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo":
            print(_render(demo_report(), args.format))
            return 0

        root = _root(args.root)
        receipt_path = _receipt_path(root, args.receipt)
        if args.command == "baseline":
            snapshot = scan_permissions(root)
            write_snapshot(snapshot, receipt_path, overwrite=args.force)
            if args.json:
                print(json.dumps(snapshot.as_dict(), ensure_ascii=False, indent=2))
            else:
                print(f"Baseline saved: {safe_display(str(receipt_path))}")
                print(f"Persisted permission rules: {len(snapshot.entries)}")
                print("Only redacted permission data and fingerprints were stored.")
            return 0

        baseline = read_snapshot(receipt_path)
        report = compare(
            baseline,
            scan_permissions(root, fingerprint_salt=bytes.fromhex(baseline.fingerprint_salt)),
        )
        print(_render(report, args.format))
        return 1 if report.changed else 0
    except ReceiptError as exc:
        print(f"permission-receipt: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
