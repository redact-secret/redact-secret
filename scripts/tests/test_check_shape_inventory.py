#!/usr/bin/env python3
"""The negative-shape inventory and its corpus-reconciliation check (issue #475)."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-shape-inventory.py"
spec = importlib.util.spec_from_file_location("check_shape_inventory", SCRIPT)
assert spec and spec.loader
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)

INVENTORY_TEXT = CHECK.INVENTORY_PATH.read_text(encoding="utf-8")
INVENTORY = json.loads(INVENTORY_TEXT)
CORPUS = json.loads(CHECK.CORPUS_PATH.read_text(encoding="utf-8"))


def first_shape(inventory: dict) -> dict:
    return inventory["detectors"][0]["shapes"][0]


class ShapeInventoryTests(unittest.TestCase):
    def test_the_committed_inventory_matches_the_corpus(self) -> None:
        self.assertEqual(CHECK.check_inventory(INVENTORY, CORPUS, ROOT, INVENTORY_TEXT), [])

    def test_the_inventory_lives_outside_the_audit_archive(self) -> None:
        self.assertFalse(CHECK.INVENTORY_PATH.is_relative_to(ROOT / "docs" / "audits"))

    def test_a_missing_fixture_is_an_error(self) -> None:
        mutated = copy.deepcopy(INVENTORY)
        first_shape(mutated)["fixtures"]["negative"].append("no-such-fixture")
        errors = CHECK.check_inventory(mutated, CORPUS, ROOT, INVENTORY_TEXT)
        self.assertTrue(any("not in the synchronous corpus" in e for e in errors))

    def test_a_kind_disagreement_is_an_error(self) -> None:
        mutated = copy.deepcopy(INVENTORY)
        shape = first_shape(mutated)
        shape["fixtures"]["positive"].append(shape["fixtures"]["negative"][0])
        errors = CHECK.check_inventory(mutated, CORPUS, ROOT, INVENTORY_TEXT)
        self.assertTrue(any("has kind 'negative'" in e for e in errors))

    def test_a_wrong_detector_is_an_error(self) -> None:
        mutated = copy.deepcopy(INVENTORY)
        mutated["detectors"][1]["shapes"][0]["fixtures"]["negative"].append(
            first_shape(INVENTORY)["fixtures"]["negative"][0]
        )
        errors = CHECK.check_inventory(mutated, CORPUS, ROOT, INVENTORY_TEXT)
        self.assertTrue(any("belongs to" in e for e in errors))

    def test_an_audit_archive_citation_is_an_error(self) -> None:
        errors = CHECK.check_inventory(INVENTORY, CORPUS, ROOT, "see docs/audits/evidence/1/x.md")
        self.assertTrue(any("docs/audits" in e for e in errors))

    def test_a_missing_decision_document_is_an_error(self) -> None:
        mutated = copy.deepcopy(INVENTORY)
        for entry in mutated["detectors"]:
            for shape in entry["shapes"]:
                if shape["basis"]["kind"] == "decision":
                    shape["basis"]["ref"] = "docs/decisions/missing.md (x)"
        errors = CHECK.check_inventory(mutated, CORPUS, ROOT, INVENTORY_TEXT)
        self.assertTrue(any("decision basis" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
