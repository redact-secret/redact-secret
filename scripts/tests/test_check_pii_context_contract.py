#!/usr/bin/env python3
"""Tests for the pii-context/v1 live contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-pii-context-contract.py"
SPEC = importlib.util.spec_from_file_location("check_pii_context_contract", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)

CONTRACT = json.loads((ROOT / CHECK.ARTIFACT).read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / CHECK.SCHEMA).read_text(encoding="utf-8"))
RANGES = CHECK.governed_invisible_ranges(ROOT)


class RepositoryContract(unittest.TestCase):
    def test_the_committed_contract_and_fixtures_pass(self) -> None:
        self.assertEqual(CHECK.validate(ROOT), [])

    def test_compiled_runtime_table_is_generated_from_the_reviewed_contract(self) -> None:
        contract = json.loads((ROOT / CHECK.ARTIFACT).read_text(encoding="utf-8"))
        expected = CHECK._TABLE_SUPPORT.render(contract)
        self.assertEqual((ROOT / CHECK._TABLE_SUPPORT.OUTPUT).read_text(encoding="utf-8"), expected)

    def test_english_case_separator_and_korean_nfc_normalize_together(self) -> None:
        self.assertEqual(CHECK.normalize("EMAIL_KEY", "en"), "email key")
        self.assertEqual(CHECK.normalize("이메일", "ko"), "이메일")
        self.assertEqual(CHECK.normalize("이\u200b메일", "ko"), "이메일")
        self.assertEqual(CHECK.normalize("이\ufe0f메일", "ko"), "이메일")
        self.assertEqual(unicodedata.category("\ufe0f"), "Mn")

    def test_both_languages_have_ambiguity_controls_that_cannot_establish_sensitivity(self) -> None:
        controls = {
            fixture["language"]
            for fixture in CONTRACT["fixtures"]
            for association in fixture["expectedAssociations"]
            if association["effect"] == "not-established-without-identity"
        }
        self.assertEqual(controls, {"en", "ko"})

    def test_both_languages_exercise_every_semantic_class(self) -> None:
        entries = {entry["id"]: entry for entry in CONTRACT["entries"]}
        for language in ("en", "ko"):
            effects = {
                association["effect"]
                for fixture in CONTRACT["fixtures"]
                if fixture["language"] == language
                for association in fixture["expectedAssociations"]
                if association["matches"]
            }
            self.assertEqual(effects, {"positive-evidence", "negative-evidence", "neutral-evidence", "not-established-without-identity"})
            self.assertTrue(
                all(
                    match in entries
                    for fixture in CONTRACT["fixtures"]
                    for association in fixture["expectedAssociations"]
                    for match in association["matches"]
                )
            )

    def test_domain_precedence_and_multi_candidate_association_are_executed(self) -> None:
        fixtures = {fixture["id"]: fixture for fixture in CONTRACT["fixtures"]}
        for fixture_id in (
            "entry-domain-must-cover-candidate",
            "en-overlap-prefers-longest-form",
            "candidate-blocks-association-past-it",
            "equidistant-context-is-unassociated",
        ):
            actual, errors = CHECK.fixture_associations(CONTRACT, fixtures[fixture_id], RANGES)
            self.assertEqual(errors, [], fixture_id)
            expected = {
                association["candidate"]: {
                    "matches": association["matches"],
                    "effect": association["effect"],
                }
                for association in fixtures[fixture_id]["expectedAssociations"]
            }
            self.assertEqual(actual, expected, fixture_id)


class SchemaAndSemantics(unittest.TestCase):
    def test_mixed_domain_equidistant_candidates_associate_with_neither(self) -> None:
        occurrence = {
            "start": 5,
            "end": 12,
            "entry": {
                "kind": "natural-language-label",
                "domains": ["email"],
            },
        }
        candidates = {
            "email": {"domain": "email"},
            "card": {"domain": "payment-card"},
        }
        self.assertIsNone(
            CHECK.associate_occurrence(
                occurrence,
                "TEST contact TEST",
                {"email": 0, "card": 17},
                candidates,
            )
        )

    def test_unknown_fields_and_runtime_status_drift_are_rejected(self) -> None:
        changed = copy.deepcopy(CONTRACT)
        changed["runtimeVocabulary"] = True
        self.assertTrue(CHECK._SCHEMA_SUPPORT.validate_schema(changed, SCHEMA, SCHEMA))
        changed = copy.deepcopy(CONTRACT)
        changed["use"]["loadedAtRuntime"] = True
        self.assertTrue(CHECK._SCHEMA_SUPPORT.validate_schema(changed, SCHEMA, SCHEMA))

    def test_fixture_drift_is_rejected(self) -> None:
        changed = copy.deepcopy(CONTRACT)
        changed["fixtures"][0]["expectedAssociations"][0]["matches"] = []
        self.assertTrue(CHECK.check_contract(changed, RANGES))

    def test_unbounded_association_and_changed_precedence_are_rejected(self) -> None:
        changed = copy.deepcopy(CONTRACT)
        changed["association"]["maxDistance"] = 65
        self.assertTrue(CHECK._SCHEMA_SUPPORT.validate_schema(changed, SCHEMA, SCHEMA))
        changed = copy.deepcopy(CONTRACT)
        changed["precedence"].reverse()
        self.assertTrue(CHECK.check_contract(changed, RANGES))

    def test_fixture_markers_must_name_every_candidate_exactly_once(self) -> None:
        changed = copy.deepcopy(CONTRACT)
        changed["fixtures"][0]["template"] = "email only"
        self.assertTrue(CHECK.check_contract(changed, RANGES))


if __name__ == "__main__":
    unittest.main()
