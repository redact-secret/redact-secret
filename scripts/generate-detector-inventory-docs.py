#!/usr/bin/env python3
"""Project the detector inventory into the detection reference (issue #602, DS8).

`docs/coverage/detector-inventory.json` is the reviewed declaration of every
finding type the built-in registry can emit, reconciled against the real
registry by `built_in_inventory_matches_the_declared_baseline` in
`crates/secret-scan-core/src/detectors/mod.rs`. This script renders it, one
row per detector, between the
`<!-- detector-inventory:start -->` / `<!-- detector-inventory:end -->`
markers in `docs/reference/detection.md`, so that page can no longer omit a
detector the registry ships.

    python3 -B scripts/generate-detector-inventory-docs.py --check
    python3 -B scripts/generate-detector-inventory-docs.py

Output is deterministic given its input: the inventory's own detector order,
no timestamps, no network access. The inventory carries no matched value, and
neither does the rendered block.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
DOC_PATH = ROOT / "docs" / "reference" / "detection.md"

START = "<!-- detector-inventory:start -->"
END = "<!-- detector-inventory:end -->"

REGENERATE = "`python3 -B scripts/generate-detector-inventory-docs.py`"


def group_by_detector(inventory: dict) -> list[dict]:
    """One entry per detector, in first-appearance order, merging its types."""
    detectors: dict[str, dict] = {}
    for row in inventory["types"]:
        entry = detectors.setdefault(
            row["detector"], {"detector": row["detector"], "types": [], "policyClasses": [], "schemes": []}
        )
        entry["types"].append(row["type"])
        if row["policyClass"] not in entry["policyClasses"]:
            entry["policyClasses"].append(row["policyClass"])
        for scheme in row.get("schemes") or ():
            if scheme not in entry["schemes"]:
                entry["schemes"].append(scheme)
    return list(detectors.values())


def _code_list(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) if values else "—"


def render_block(inventory: dict) -> str:
    detectors = group_by_detector(inventory)
    lines = [
        START,
        f"{len(detectors)} built-in detectors emit {len(inventory['types'])} finding types. "
        "Generated from [`detector-inventory.json`](../coverage/detector-inventory.json) by "
        f"{REGENERATE}; do not edit by hand.",
        "",
        "| Detector | Finding types | Default policy class | Schemes |",
        "| --- | --- | --- | --- |",
    ]
    for entry in detectors:
        lines.append(
            f"| `{entry['detector']}` | {_code_list(entry['types'])} | "
            f"{_code_list(entry['policyClasses'])} | {_code_list(entry['schemes'])} |"
        )
    lines.append(END)
    return "\n".join(lines)


def inject(doc_text: str, block: str) -> str:
    start = doc_text.find(START)
    end = doc_text.find(END)
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"docs/reference/detection.md is missing the {START} / {END} markers")
    return doc_text[:start] + block + doc_text[end + len(END) :]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--doc", type=Path, default=DOC_PATH)
    parser.add_argument("--check", action="store_true", help="fail if the doc's block is out of date; write nothing")
    args = parser.parse_args(argv)

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    doc_text = args.doc.read_text(encoding="utf-8")
    try:
        new_text = inject(doc_text, render_block(inventory))
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        if new_text != doc_text:
            print(f"error: {args.doc} detector block drifted from {args.inventory}; regenerate with {REGENERATE}", file=sys.stderr)
            return 1
        return 0

    args.doc.write_text(new_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
