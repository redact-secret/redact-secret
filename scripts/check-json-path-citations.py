#!/usr/bin/env python3
"""Gate a dangling repo-relative path cited in a tracked JSON `note` or
`reference` field (issue #638).

`doc-links:check` only parses Markdown `[text](path)` link syntax, so a path
string written as free-text prose -- `"Reclassified by issue #372 (frozen
precision contract in docs/audits/evidence/367/precision-contracts.json,
...)"` -- is invisible to it whether it lives in Markdown or JSON. Issue
#638 found 41 such citations left dangling by a path move that no checker
caught. This script closes the JSON half of that gap: Markdown prose
citations are excluded because `docs/audits/evidence/<issue>/` and similar
narrative archives cite paths as of when they were written and are
correctly allowed to go stale (a frozen record's job is to say what was
true then, not what is true now); every corpus fixture and generated
report, in contrast, describes current behavior, so a dangling path there
is always a defect, not a historical fact.

`docs/audits/evidence/` and `docs/releases/` are excluded for the same
reason: both are frozen narrative/record archives under this repository's
artifact taxonomy (`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`),
not live contracts or generated reports, so a path they cite is allowed to
outlive the file it names.

This is a read-only gate: it fixes nothing.

    python3 -B scripts/check-json-path-citations.py
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CITATION_KEYS = ("note", "reference")

FROZEN_PREFIXES = ("docs/audits/evidence/", "docs/releases/")

# Repo-relative path citations always start with one of these top-level
# directories, followed by at least one more path segment and a file
# extension -- narrow enough to skip prose that merely mentions a bare
# directory name or an unrelated dotted identifier.
TOP_LEVEL_DIRS = (
    "assessment",
    "benchmarks",
    "bindings",
    "conformance",
    "conventions",
    "crates",
    "docs",
    "examples",
    "packages",
    "scripts",
    "sast",
)
PATH_RE = re.compile(
    r"\b(?:" + "|".join(TOP_LEVEL_DIRS) + r")(?:/[\w.-]+)+\.[A-Za-z0-9]+\b"
)


def list_tracked_json_files(root: Path) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "*.json"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [line for line in output.splitlines() if line]


def citations(value: object) -> list[str]:
    """Every path-like string cited under a `note`/`reference` key, walking
    the whole structure -- a citation can sit at any depth or inside a list
    of fixtures/rows."""
    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key in CITATION_KEYS and isinstance(child, str):
                    found.extend(PATH_RE.findall(child))
                else:
                    walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return found


def check_file(root: Path, relative: str) -> list[str]:
    try:
        data = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []

    errors: list[str] = []
    for citation in citations(data):
        if not (root / citation).exists():
            errors.append(f"{relative}: dangling path citation {citation!r}")
    return errors


def validate(root: Path, files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    for relative in files if files is not None else list_tracked_json_files(root):
        if relative.startswith(FROZEN_PREFIXES):
            continue
        errors.extend(check_file(root, relative))
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("root", nargs="?", default=ROOT, type=Path)
    args = parser.parse_args()

    errors = validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"JSON path citations check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
