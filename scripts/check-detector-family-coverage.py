#!/usr/bin/env python3
"""Report detectors whose family is missing from the pinned support matrix
(issue #995, part of redact-secret-benchmarks#473).

Every detector in `docs/coverage/detector-inventory.json` (one entry per
finding type, joined to the detector that emits it) should be listed under a
family in the pinned `benchmarks/support-matrix.json`, so a new detector cannot
land without a `redact-secret-benchmarks` family. The matrix keys families to
detector ids, so the join is finding type -> detector -> family.

Two kinds of gap exist today: shipped detectors with no family ("unmeasured",
the "not yet measured" set in `docs/support-matrix.md`) and matrix entries
naming a detector the inventory lacks ("stale").

Every current gap is recorded with a reason in
`docs/coverage/detector-family-coverage-allowlist.json`. The report always
lists all gaps and marks the allowlisted ones. `--strict` (the CI mode) exits 1
on any gap that is not allowlisted, so a new detector without a family fails,
and also on an allowlist entry that is no longer a gap or has no reason, so the
list can only shrink as the pinned matrix is refreshed. Without `--strict` the
exit status is always 0.

    python3 -B scripts/check-detector-family-coverage.py
    python3 -B scripts/check-detector-family-coverage.py --strict

Offline and deterministic: no network, no timestamps, sorted output.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
MATRIX_PATH = ROOT / "benchmarks" / "support-matrix.json"
ALLOWLIST_PATH = ROOT / "docs" / "coverage" / "detector-family-coverage-allowlist.json"


def inventory_detectors(inventory: dict) -> dict[str, list[str]]:
    """Detector id -> the finding types it emits, from the inventory."""
    by_detector: dict[str, list[str]] = {}
    for entry in inventory["types"]:
        by_detector.setdefault(entry["detector"], []).append(entry["type"])
    return {detector: sorted(types) for detector, types in by_detector.items()}


def matrix_detectors(matrix: dict) -> dict[str, list[str]]:
    """Detector id -> the matrix families that list it."""
    by_detector: dict[str, list[str]] = {}
    for family in matrix["families"]:
        for detector in family.get("detectors", []):
            by_detector.setdefault(detector, []).append(family["family"])
    return {detector: sorted(families) for detector, families in by_detector.items()}


def compare(inventory: dict, matrix: dict) -> tuple[dict[str, list[str]], list[str]]:
    """Return (detectors with no matrix family -> their finding types,
    matrix-listed detectors the inventory does not know)."""
    shipped = inventory_detectors(inventory)
    measured = matrix_detectors(matrix)
    unmapped = {detector: types for detector, types in sorted(shipped.items()) if detector not in measured}
    stale = sorted(detector for detector in measured if detector not in shipped)
    return unmapped, stale


def check_allowlist(
    allowlist: dict, unmapped: dict[str, list[str]], stale: list[str]
) -> tuple[list[str], list[str], list[str]]:
    """Return (unmeasured detectors not allowlisted, stale detectors not
    allowlisted, allowlist problems: entries without a reason or no longer a gap)."""
    allowed_unmeasured = allowlist.get("unmeasured", {})
    allowed_stale = allowlist.get("stale", {})
    new_unmapped = [detector for detector in unmapped if detector not in allowed_unmeasured]
    new_stale = [detector for detector in stale if detector not in allowed_stale]
    problems: list[str] = []
    for kind, entries, current in (("unmeasured", allowed_unmeasured, unmapped), ("stale", allowed_stale, stale)):
        for detector, reason in sorted(entries.items()):
            if not isinstance(reason, str) or not reason.strip():
                problems.append(f"allowlist {kind} entry `{detector}` has no reason")
            if detector not in current:
                problems.append(f"allowlist {kind} entry `{detector}` is no longer a gap; remove it")
    return new_unmapped, new_stale, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST_PATH)
    parser.add_argument("--strict", action="store_true", help="fail on any gap that is not allowlisted")
    args = parser.parse_args(argv)

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
    allowlist = json.loads(args.allowlist.read_text(encoding="utf-8")) if args.allowlist.exists() else {}
    unmapped, stale = compare(inventory, matrix)
    new_unmapped, new_stale, problems = check_allowlist(allowlist, unmapped, stale)

    for detector in stale:
        status = "error" if args.strict and detector in new_stale else "report"
        note = "" if detector in new_stale else " (allowlisted)"
        print(f"{status}: support-matrix.json lists detector `{detector}` that detector-inventory.json does not{note}")
    if unmapped:
        print(
            f"report: {len(unmapped)} detector(s) have no family in the pinned support matrix, {len(new_unmapped)} not allowlisted:"
        )
        for detector, types in unmapped.items():
            mark = "NEW " if detector in new_unmapped else ""
            print(f"  {mark}{detector} ({', '.join(types)})")
    else:
        print("every inventory detector maps to a pinned support-matrix family")
    for problem in problems:
        print(f"{'error' if args.strict else 'report'}: {problem}")

    if args.strict and (new_unmapped or new_stale or problems):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
