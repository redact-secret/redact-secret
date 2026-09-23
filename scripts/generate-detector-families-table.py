#!/usr/bin/env python3
"""Keep the finding-type table in docs/specs/detector-families.md joined to the inventory (issue #640, item 2).

`docs/coverage/detector-inventory.json` declares every finding type the built-in
registry can emit. The table between the
`<!-- detector-families:start -->` / `<!-- detector-families:end -->` markers in
`docs/specs/detector-families.md` is generated from it: the set of rows, and
each row's Type, Detector and Policy class columns, cannot be edited by hand.

The Governing ADR column is reviewed prose, not derivable from the inventory. It
is carried over from the existing row for the same type; a type with no existing
row gets the generic-policy default until a reviewer replaces it. Every ADR link
in it is resolved by `doc-links:check`, and the spec-routing rules stay checked
by `decisions:validate`.

    python3 -B scripts/generate-detector-families-table.py --check
    python3 -B scripts/generate-detector-families-table.py

Deterministic: rows sorted by finding type, no timestamps, no network access.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
DOC_PATH = ROOT / "docs" / "specs" / "detector-families.md"

START = "<!-- detector-families:start -->"
END = "<!-- detector-families:end -->"

DEFAULT_ADR = "generic policy default, no dedicated ADR in this repository"
REGENERATE = "`python3 -B scripts/generate-detector-families-table.py`"
ROW = re.compile(r"^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| (.*) \|$")


def existing_adr_column(block: str) -> dict[str, str]:
    """Map finding type -> hand-authored Governing ADR cell from the current block."""
    cells: dict[str, str] = {}
    for line in block.splitlines():
        match = ROW.match(line)
        if match is not None:
            cells[match.group(1)] = match.group(4)
    return cells


def render_block(inventory: dict, adr_cells: dict[str, str]) -> str:
    lines = [
        START,
        f"Generated from [`docs/coverage/detector-inventory.json`](../coverage/detector-inventory.json) by {REGENERATE}; "
        "the rows and the first three columns are checked against the inventory. "
        "Only the Governing ADR column is edited by hand.",
        "",
        "| Type | Detector | Policy class | Governing ADR |",
        "| --- | --- | --- | --- |",
    ]
    for row in sorted(inventory["types"], key=lambda entry: entry["type"]):
        cell = adr_cells.get(row["type"], DEFAULT_ADR)
        lines.append(f"| `{row['type']}` | `{row['detector']}` | `{row['policyClass']}` | {cell} |")
    lines.append(END)
    return "\n".join(lines)


def inject(doc_text: str, inventory: dict) -> str:
    start = doc_text.find(START)
    end = doc_text.find(END)
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"{DOC_PATH.name} is missing the {START} / {END} markers")
    current = doc_text[start : end + len(END)]
    return doc_text[:start] + render_block(inventory, existing_adr_column(current)) + doc_text[end + len(END) :]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--doc", type=Path, default=DOC_PATH)
    parser.add_argument("--check", action="store_true", help="fail if the table is out of date; write nothing")
    args = parser.parse_args(argv)

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    doc_text = args.doc.read_text(encoding="utf-8")
    try:
        new_text = inject(doc_text, inventory)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        if new_text != doc_text:
            print(f"error: {args.doc} finding-type table drifted from {args.inventory}; regenerate with {REGENERATE}", file=sys.stderr)
            return 1
        return 0

    args.doc.write_text(new_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
