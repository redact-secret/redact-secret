#!/usr/bin/env python3
"""Report detectors whose family is missing from the pinned support matrix
(issue #995, part of redact-secret-benchmarks#473).

Every detector in `docs/coverage/detector-inventory.json` (one entry per
finding type, joined to the detector that emits it) should be listed under a
family in the pinned `benchmarks/support-matrix.json`, so a new detector cannot
land without a `redact-secret-benchmarks` family. The matrix keys families to
detector ids, so the join is finding type -> detector -> family.

Report-only by default: detectors that ship without a measured family (the
"not yet measured" set in `docs/support-matrix.md`) are listed and the exit
status stays 0. `--strict` exits 1 when any such detector exists; switch CI to
it once the pinned matrix covers every shipped detector. A matrix entry naming a
detector the inventory lacks (the pinned matrix and the inventory disagree)
is reported the same way; the pinned matrix has such entries today.

    python3 -B scripts/check-detector-family-coverage.py
    python3 -B scripts/check-detector-family-coverage.py --strict

Offline and deterministic: no network, no timestamps, sorted output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
MATRIX_PATH = ROOT / "benchmarks" / "support-matrix.json"


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--strict", action="store_true", help="fail when any detector has no matrix family")
    args = parser.parse_args(argv)

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
    unmapped, stale = compare(inventory, matrix)

    level = "error" if args.strict else "report"
    for detector in stale:
        print(f"{level}: support-matrix.json lists detector `{detector}` that detector-inventory.json does not")
    if unmapped:
        print(f"{level}: {len(unmapped)} detector(s) have no family in the pinned support matrix:")
        for detector, types in unmapped.items():
            print(f"  {detector} ({', '.join(types)})")
    else:
        print("every inventory detector maps to a pinned support-matrix family")

    if args.strict and (stale or unmapped):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
