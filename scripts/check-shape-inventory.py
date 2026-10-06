#!/usr/bin/env python3
"""Check the negative-shape inventory against the synchronous corpus (issue #475).

``docs/contracts/precision/shape-inventory.json`` is the reviewed inventory of
valid-but-non-secret shapes the structural and contextual detectors
(``generic-token``, ``bearer-token``, ``connection-string``, ``jwt``)
recognize. Each shape cites the fixtures that prove it. This check fails when
a citation no longer matches the corpus, so the inventory cannot drift
silently:

- every shape id is unique within its detector;
- the cited implementation file and every ``decision`` basis document exist;
- every cited fixture id exists in
  ``conformance/fixtures/synchronous-corpus.json`` for the same detector;
- ``negative`` ids cite ``kind: "negative"`` fixtures with an empty
  ``expected``; ``positive`` ids cite ``kind: "positive"`` fixtures with a
  non-empty ``expected``; ``boundary`` ids cite ``kind: "boundary"`` fixtures;
- the file never cites a path under ``docs/audits/`` (a live contract must not
  depend on the retiring audit archive).

The inventory records no credential value; the check reads only ids, kinds
and whether ``expected`` is empty. The Rust ``canonical_corpus`` test remains
the enforcement boundary for the detector behavior itself.

    python3 -B scripts/check-shape-inventory.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "contracts" / "precision" / "shape-inventory.json"
CORPUS_PATH = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"

ROLE_KIND = {"negative": "negative", "positive": "positive", "boundary": "boundary"}
BASIS_KINDS = ("code", "decision")


def check_inventory(inventory: dict, corpus: dict, root: Path = ROOT, text: str = "") -> list[str]:
    errors: list[str] = []
    if "docs/audits" in text:
        errors.append("the inventory cites a path under docs/audits/; live contracts must not")
    fixtures = {f["id"]: f for f in corpus["fixtures"]}
    seen_detectors: set[str] = set()
    for entry in inventory.get("detectors", []):
        detector = entry.get("detector", "")
        if detector in seen_detectors:
            errors.append(f"{detector}: listed twice")
        seen_detectors.add(detector)
        if not (root / entry.get("implementation", "")).is_file():
            errors.append(f"{detector}: implementation {entry.get('implementation')!r} does not exist")
        shape_ids: set[str] = set()
        for shape in entry.get("shapes", []):
            where = f"{detector}/{shape.get('id')}"
            if shape.get("id") in shape_ids:
                errors.append(f"{where}: duplicate shape id")
            shape_ids.add(shape.get("id"))
            basis = shape.get("basis", {})
            if basis.get("kind") not in BASIS_KINDS:
                errors.append(f"{where}: basis.kind must be one of {BASIS_KINDS}")
            if basis.get("kind") == "decision":
                document = str(basis.get("ref", "")).split(" ", 1)[0]
                if not document or not (root / document).is_file():
                    errors.append(f"{where}: decision basis {document!r} does not exist")
            for role, ids in shape.get("fixtures", {}).items():
                if role not in ROLE_KIND:
                    errors.append(f"{where}: unknown fixture role {role!r}")
                    continue
                for fixture_id in ids:
                    fixture = fixtures.get(fixture_id)
                    if fixture is None:
                        errors.append(f"{where}: fixture {fixture_id!r} is not in the synchronous corpus")
                        continue
                    if fixture.get("detector") != detector:
                        errors.append(f"{where}: fixture {fixture_id!r} belongs to {fixture.get('detector')!r}")
                    if fixture.get("kind") != ROLE_KIND[role]:
                        errors.append(f"{where}: {role} fixture {fixture_id!r} has kind {fixture.get('kind')!r}")
                    empty = not fixture.get("expected")
                    if role == "negative" and not empty:
                        errors.append(f"{where}: negative fixture {fixture_id!r} has a non-empty expected")
                    if role != "negative" and empty:
                        errors.append(f"{where}: {role} fixture {fixture_id!r} has an empty expected")
    return errors


def main() -> int:
    text = INVENTORY_PATH.read_text(encoding="utf-8")
    errors = check_inventory(json.loads(text), json.loads(CORPUS_PATH.read_text(encoding="utf-8")), ROOT, text)
    for error in errors:
        print(f"{INVENTORY_PATH.relative_to(ROOT)}: {error}", file=sys.stderr)
    if errors:
        return 1
    print("Shape inventory check complete: 0 error(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
