#!/usr/bin/env python3
"""Generate docs/decisions/DECISIONS.md and docs/decision-aliases.md (issue #640, items 4 and 5).

The index used to be hand-maintained, so nothing kept it in step with the
`spec:` field that `validate-decisions.py` checks against each spec file's
`## Rules` table. It is now a projection: one section per spec file, in the
spec files' fixed order, each listing that spec's records by filename (which
is date order) under the record's own H1 title.

    python3 -B scripts/generate-decisions-index.py --check
    python3 -B scripts/generate-decisions-index.py

`docs/decision-aliases.md` maps every folded (removed) decision id to the
record that now carries it and to the commit-pinned permalink of its last full
text. A folded id lives only in frontmatter `aliases:`, where a plain search
for the id finds no file; this page is the searchable place it appears.

Deterministic: no timestamps, no network access.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR = importlib.util.spec_from_file_location("validate_decisions", Path(__file__).with_name("validate-decisions.py"))
assert _VALIDATOR and _VALIDATOR.loader
VALIDATE = importlib.util.module_from_spec(_VALIDATOR)
sys.modules[_VALIDATOR.name] = VALIDATE
_VALIDATOR.loader.exec_module(VALIDATE)

# Section order and headings; keys must equal validate-decisions.py's SPEC_NAMES.
SECTIONS: list[tuple[str, str]] = [
    ("detector-families", "Detector families"),
    ("contextual-detection", "Contextual detection"),
    ("engine", "Engine"),
    ("distribution", "Distribution"),
    ("evidence-and-gates", "Evidence and gates"),
]

REGENERATE = "`python3 -B scripts/generate-decisions-index.py`"
H1 = re.compile(r"^# (.+?)\s*$", re.MULTILINE)


def render(root: Path) -> str:
    if {name for name, _ in SECTIONS} != VALIDATE.SPEC_NAMES:
        raise ValueError("SECTIONS is out of step with validate-decisions.py SPEC_NAMES")
    decision_dir = root / "docs" / "decisions"
    by_spec: dict[str, list[tuple[str, str]]] = {name: [] for name, _ in SECTIONS}
    for record in sorted(p for p in decision_dir.glob("*.md") if p.name != "DECISIONS.md"):
        fields, body, _ = VALIDATE.parse_frontmatter(record)
        spec = fields.get("spec")
        title = H1.search(body)
        if spec not in by_spec:
            raise ValueError(f"{record.name}: spec: {spec!r} is not a known spec name")
        if title is None:
            raise ValueError(f"{record.name}: missing an H1 title")
        by_spec[spec].append((title.group(1), record.name))

    lines = [
        "# Architecture decisions",
        "",
        "These records preserve accepted project-wide choices. They provide context for",
        "future planning and implementation but do not authorize Git or release actions.",
        "",
        f"Generated from each record's `spec:` field by {REGENERATE}; do not edit by hand.",
        "Each spec file under `docs/specs/` states the current rules and links the records",
        "that decided them.",
    ]
    for name, heading in SECTIONS:
        lines += ["", f"## {heading}", "", f"Current rules: `docs/specs/{name}.md`.", ""]
        lines += [f"- [{title}]({filename})" for title, filename in by_spec[name]]
    return "\n".join(lines) + "\n"


def render_aliases(root: Path) -> str:
    decision_dir = root / "docs" / "decisions"
    rows: list[tuple[str, str, str, str]] = []
    for record in sorted(p for p in decision_dir.glob("*.md") if p.name != "DECISIONS.md"):
        fields, body, _ = VALIDATE.parse_frontmatter(record)
        title = H1.search(body)
        permalinks = VALIDATE.alias_permalinks(body)
        for alias in VALIDATE.alias_list(fields):
            if alias not in permalinks:
                raise ValueError(f"{record.name}: folded alias {alias} has no full-record permalink row")
            rows.append((alias, title.group(1) if title else record.name, record.name, permalinks[alias]))
    lines = [
        "# Folded decision ids",
        "",
        "Each id below names a decision that was merged into a surviving record. The id is kept in",
        "that record's `aliases:` frontmatter, so an old citation still resolves. Search this page",
        "for the old id to find where it went and read its last full text.",
        "",
        f"Generated from every record's `aliases:` and `Folded records` table by {REGENERATE}; do not edit by hand.",
        "",
        "| Folded `decision_id` | Surviving record | Last full text |",
        "| --- | --- | --- |",
    ]
    for alias, title, filename, permalink in sorted(rows):
        lines.append(f"| `{alias}` | [{title}](decisions/{filename}) | [permalink]({permalink}) |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true", help="fail if the index is out of date; write nothing")
    args = parser.parse_args(argv)

    try:
        outputs = {
            args.root / "docs" / "decisions" / "DECISIONS.md": render(args.root),
            args.root / "docs" / "decision-aliases.md": render_aliases(args.root),
        }
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    status = 0
    for path, expected in outputs.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                print(f"error: {path} drifted from the decision records; regenerate with {REGENERATE}", file=sys.stderr)
                status = 1
        else:
            path.write_text(expected, encoding="utf-8")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
