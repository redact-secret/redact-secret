#!/usr/bin/env python3
"""Generate the reviewable coverage report (issue #104, tracking-key
``dacd-f1-t4``).

``docs/coverage/inventory-report.json`` (issue #101) and
``docs/coverage/coverage-declarations.json`` (issue #103) are each already
deterministic, machine-checked joins over the real registry and corpus, but
neither is a document a reviewer can scan in one pass: the first is one row
per detector/finding-type/scheme triple, the second is one row per declared
type with nine evidence-dimension sub-rows. This script summarizes both --
grouped by detector, finding type, scheme, evidence dimension, and unresolved
state -- into a single Markdown report meant to be read, not parsed.

It also cross-checks the two source documents against each other: every
declared finding type must appear in both, with the same detector. That is a
second, independent line of defense (`generate-coverage-inventory.py` and
`generate-coverage-declarations.py` each already reconcile against the real
registry and corpus on their own) against exactly the failure issue #104
means to close off -- a built-in capability (a detector, a finding type, a
scheme) added or removed on one side of that split without reconciling the
other.

This script never touches a fixture's `input` or a matched value, and does
not read the corpus or the registry itself: it only reads the two already-
sanitized generated documents above, so it can carry nothing those documents
did not already carry -- fixture ids, detector ids, finding types, schemes,
dimension names, states, and free-text `note`/`backlogId` fields.

Output is deterministic: stable insertion order (both inputs are already
sorted), no timestamps.

    python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_REPORT_PATH = ROOT / "docs" / "coverage" / "inventory-report.json"
DECLARATIONS_PATH = ROOT / "docs" / "coverage" / "coverage-declarations.json"

ROW_STATES = ("supported", "intentionally-unsupported", "unresolved")
DIMENSION_STATES = ("supported", "not-applicable", "pending")
DECLARATION_TYPE_CLASSES = {"provider", "structural", "contextual"}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _declarations_by_type(declarations: list[dict]) -> dict[str, dict]:
    return {row["type"]: row for row in declarations}


def by_detector(inventory_rows: list[dict]) -> list[dict]:
    detectors: dict[str, dict] = {}
    for row in inventory_rows:
        entry = detectors.setdefault(
            row["detector"],
            {"detector": row["detector"], "types": [], "stateCounts": {state: 0 for state in ROW_STATES}},
        )
        entry["types"].append(row["type"])
        entry["stateCounts"][row["state"]] += 1
    return [detectors[name] for name in sorted(detectors)]


def by_finding_type(inventory_rows: list[dict], declarations_by_type: dict[str, dict]) -> list[dict]:
    rows = []
    for row in sorted(inventory_rows, key=lambda r: r["type"]):
        declaration = declarations_by_type.get(row["type"])
        pending_dimensions = (
            sorted(d["dimension"] for d in declaration["dimensions"] if d["state"] == "pending")
            if declaration is not None
            else None
        )
        rows.append(
            {
                "type": row["type"],
                "detector": row["detector"],
                "behaviorClass": declaration["behaviorClass"] if declaration is not None else None,
                "state": row["state"],
                "schemeStates": (
                    sorted(
                        {s["state"] for s in row["schemeRows"]}
                    )
                    if row["schemeRows"] != "not-applicable"
                    else "not-applicable"
                ),
                "pendingDimensions": pending_dimensions,
            }
        )
    return rows


def by_scheme(inventory_rows: list[dict]) -> list[dict]:
    rows = []
    for row in sorted(inventory_rows, key=lambda r: r["type"]):
        if row["schemeRows"] == "not-applicable":
            continue
        for scheme_row in sorted(row["schemeRows"], key=lambda s: s["scheme"]):
            rows.append(
                {
                    "detector": row["detector"],
                    "type": row["type"],
                    "scheme": scheme_row["scheme"],
                    "state": scheme_row["state"],
                }
            )
    return rows


def by_evidence_dimension(declarations: list[dict]) -> list[dict]:
    counts: dict[str, dict[str, int]] = {}
    for row in declarations:
        for dimension in row["dimensions"]:
            entry = counts.setdefault(
                dimension["dimension"], {state: 0 for state in DIMENSION_STATES}
            )
            entry[dimension["state"]] += 1
    return [
        {"dimension": name, **counts[name]}
        for name in sorted(counts)
    ]


def unresolved(inventory_rows: list[dict], declarations: list[dict]) -> dict:
    unresolved_types = sorted(row["type"] for row in inventory_rows if row["state"] == "unresolved")
    unresolved_schemes = sorted(
        f"{row['type']}/{scheme_row['scheme']}"
        for row in inventory_rows
        if row["schemeRows"] != "not-applicable"
        for scheme_row in row["schemeRows"]
        if scheme_row["state"] == "unresolved"
    )
    pending_dimensions = sorted(
        (
            f"{row['type']}.{dimension['dimension']}",
            dimension.get("exception", {}).get("backlogId", ""),
        )
        for row in declarations
        for dimension in row["dimensions"]
        if dimension["state"] == "pending"
    )
    return {
        "types": unresolved_types,
        "schemes": unresolved_schemes,
        "pendingDimensions": pending_dimensions,
    }


def build_report(inventory_report: dict, declarations_doc: dict) -> dict:
    inventory_rows = inventory_report["rows"]
    declarations = declarations_doc["declarations"]
    declarations_by_type = _declarations_by_type(declarations)
    return {
        "byDetector": by_detector(inventory_rows),
        "byFindingType": by_finding_type(inventory_rows, declarations_by_type),
        "byScheme": by_scheme(inventory_rows),
        "byEvidenceDimension": by_evidence_dimension(declarations),
        "unresolved": unresolved(inventory_rows, declarations),
        "summary": {
            "rowStates": inventory_report["summary"],
            "declarationCount": len(declarations),
        },
    }


def reconciliation_errors(inventory_report: dict, declarations_doc: dict) -> list[str]:
    """Drift between the two already-generated source documents, independent
    of each document's own reconciliation against the registry and corpus."""
    inventory_types = {row["type"]: row["detector"] for row in inventory_report["rows"]}
    declared_types = {
        row["type"]: row["detector"]
        for row in declarations_doc["declarations"]
        if row["behaviorClass"] in DECLARATION_TYPE_CLASSES
    }

    errors = []
    for type_name in sorted(set(inventory_types) - set(declared_types)):
        errors.append(f"inventory declares {type_name!r} with no matching coverage declaration")
    for type_name in sorted(set(declared_types) - set(inventory_types)):
        errors.append(f"coverage declaration {type_name!r} has no matching inventory row")
    for type_name in sorted(set(inventory_types) & set(declared_types)):
        if inventory_types[type_name] != declared_types[type_name]:
            errors.append(
                f"{type_name}: inventory declares detector {inventory_types[type_name]!r}, "
                f"coverage declaration declares {declared_types[type_name]!r}"
            )
    return errors


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    lines = [
        "# Corpus coverage report",
        "",
        "Generated by `scripts/generate-coverage-report.py` from "
        "`docs/coverage/inventory-report.json` (issue #101) and "
        "`docs/coverage/coverage-declarations.json` (issue #103). Do not edit by hand --",
        "regenerate with:",
        "",
        "```sh",
        "python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md",
        "```",
        "",
        "`npm run ci` fails if this file, or either source document, is out of date with the "
        "real detector registry and canonical corpus -- see `docs/coverage/README.md`.",
        "",
        "## Summary",
        "",
        "These counts describe finding-type inventory rows with corpus evidence, not detector counts or an accuracy rate. `supported` means positive conformance evidence exists; 26/26 supported does not mean 100% recall or precision. See [detection reliability](../reference/detection-reliability.md) for separately measured outcomes.",
        "",
    ]
    summary_rows = [[state, str(report["summary"]["rowStates"][state])] for state in ROW_STATES]
    lines.append(_markdown_table(["Row state", "Count"], summary_rows))
    lines.append("")
    lines.append(f"Coverage declarations: {report['summary']['declarationCount']}.")
    lines.append("")

    lines.append("## Coverage by detector")
    lines.append("")
    detector_rows = [
        [
            entry["detector"],
            str(len(entry["types"])),
            ", ".join(f"{state}: {entry['stateCounts'][state]}" for state in ROW_STATES),
        ]
        for entry in report["byDetector"]
    ]
    lines.append(_markdown_table(["Detector", "Declared types", "Row states"], detector_rows))
    lines.append("")

    lines.append("## Coverage by finding type")
    lines.append("")
    type_rows = [
        [
            row["type"],
            row["detector"],
            row["behaviorClass"] or "(undeclared)",
            row["state"],
            (
                "not-applicable"
                if row["schemeStates"] == "not-applicable"
                else ", ".join(row["schemeStates"])
            ),
            (
                "(no declaration)"
                if row["pendingDimensions"] is None
                else (", ".join(row["pendingDimensions"]) or "none")
            ),
        ]
        for row in report["byFindingType"]
    ]
    lines.append(
        _markdown_table(
            ["Type", "Detector", "Behavior class", "State", "Scheme states", "Pending dimensions"],
            type_rows,
        )
    )
    lines.append("")

    lines.append("## Coverage by scheme")
    lines.append("")
    if report["byScheme"]:
        scheme_rows = [
            [row["detector"], row["type"], row["scheme"], row["state"]] for row in report["byScheme"]
        ]
        lines.append(_markdown_table(["Detector", "Type", "Scheme", "State"], scheme_rows))
    else:
        lines.append("No finding type declares an accepted-scheme dimension.")
    lines.append("")

    lines.append("## Coverage by evidence dimension")
    lines.append("")
    dimension_rows = [
        [
            entry["dimension"],
            str(entry["supported"]),
            str(entry["not-applicable"]),
            str(entry["pending"]),
        ]
        for entry in report["byEvidenceDimension"]
    ]
    lines.append(
        _markdown_table(["Dimension", "Supported", "Not applicable", "Pending"], dimension_rows)
    )
    lines.append("")

    lines.append("## Unresolved and pending coverage")
    lines.append("")
    lines.append(
        "`unresolved` is the inventory baseline's row/scheme state: a reachable finding "
        "type or scheme with no positive corpus evidence and no documented exemption. "
        "`pending` is the coverage declaration's dimension state: an evidence dimension "
        "with no supporting evidence and a tracked backlog id. Both are honest, reportable "
        "gaps, not errors."
    )
    lines.append("")
    lines.append("### Unresolved finding types")
    lines.append("")
    lines.append(
        "\n".join(f"- {t}" for t in report["unresolved"]["types"]) or "None."
    )
    lines.append("")
    lines.append("### Unresolved schemes")
    lines.append("")
    lines.append(
        "\n".join(f"- {s}" for s in report["unresolved"]["schemes"]) or "None."
    )
    lines.append("")
    lines.append("### Pending evidence dimensions")
    lines.append("")
    lines.append(
        "\n".join(
            f"- {dimension} (`{backlog_id}`)"
            for dimension, backlog_id in report["unresolved"]["pendingDimensions"]
        )
        or "None."
    )
    lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--inventory-report", type=Path, default=INVENTORY_REPORT_PATH)
    parser.add_argument("--declarations", type=Path, default=DECLARATIONS_PATH)
    parser.add_argument("--out", type=Path, default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    inventory_report = load_json(args.inventory_report)
    declarations_doc = load_json(args.declarations)

    errors = reconciliation_errors(inventory_report, declarations_doc)
    report = build_report(inventory_report, declarations_doc)
    text = render_markdown(report)

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(
            f"\n{len(errors)} reconciliation error(s); "
            "docs/coverage/inventory-report.json and docs/coverage/coverage-declarations.json "
            "disagree about which finding types are declared",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
