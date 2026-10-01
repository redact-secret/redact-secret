from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-coverage-inventory.py"
SPEC = importlib.util.spec_from_file_location("generate_coverage_inventory", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]


def fixture(
    id_: str,
    detector: str,
    *,
    kind: str,
    support: str,
    expected_types: list[str] | None = None,
    contexts: list[str] | None = None,
    note: str = "",
) -> dict:
    expected = (
        [
            {
                "detector": detector,
                "type": type_name,
                "confidence": "high",
                "specificity": "provider",
                "start": 0,
                "end": 1,
            }
            for type_name in expected_types
        ]
        if expected_types
        else []
    )
    return {
        "id": id_,
        "detector": detector,
        "kind": kind,
        "support": support,
        "tier": "canonical",
        "contexts": contexts or ["plain-text"],
        "input": "irrelevant-to-the-inventory",
        "expected": expected,
        "note": note,
    }


class RowStateTests(unittest.TestCase):
    def test_positive_supported_fixture_yields_supported(self) -> None:
        fixtures = [fixture("pos-1", "widget", kind="positive", support="supported", expected_types=["widget_token"])]
        state, ids = GEN.row_state(fixtures, "widget_token")
        self.assertEqual(state, "supported")
        self.assertEqual(ids, ["pos-1"])

    def test_intentionally_unsupported_fixture_yields_that_state(self) -> None:
        fixtures = [fixture("gap-1", "widget", kind="boundary", support="intentionally-unsupported")]
        state, ids = GEN.row_state(fixtures, "widget_token")
        self.assertEqual(state, "intentionally-unsupported")
        self.assertEqual(ids, ["gap-1"])

    def test_no_evidence_yields_unresolved(self) -> None:
        fixtures = [fixture("neg-1", "widget", kind="negative", support="supported")]
        state, ids = GEN.row_state(fixtures, "widget_token")
        self.assertEqual(state, "unresolved")
        self.assertEqual(ids, [])

    def test_positive_kind_but_intentionally_unsupported_support_does_not_count(self) -> None:
        # A "positive"-shaped fixture whose support is intentionally-unsupported
        # is a declared non-match, not evidence of detection working.
        fixtures = [
            fixture(
                "shape-only",
                "widget",
                kind="positive",
                support="intentionally-unsupported",
                expected_types=["widget_token"],
            )
        ]
        state, _ids = GEN.row_state(fixtures, "widget_token")
        self.assertEqual(state, "intentionally-unsupported")

    def test_ambiguous_keyword_prevents_one_type_borrowing_another_types_gap(self) -> None:
        # A detector with two finding types (mirrors generic-token) must not
        # let an intentionally-unsupported fixture about one type justify the
        # other's total absence of evidence.
        fixtures = [
            fixture(
                "contextual-boundary-short",
                "generic-token",
                kind="boundary",
                support="intentionally-unsupported",
                note="Contextual assignment below the minimum length is ignored.",
            )
        ]
        state, _ids = GEN.row_state(fixtures, "authorization_credential", ambiguous_keyword="authorization")
        self.assertEqual(state, "unresolved")

        state, ids = GEN.row_state(fixtures, "contextual_secret", ambiguous_keyword="contextual")
        self.assertEqual(state, "intentionally-unsupported")
        self.assertEqual(ids, ["contextual-boundary-short"])

    def test_scheme_filters_by_id_and_note_text(self) -> None:
        fixtures = [
            fixture(
                "conn-postgres",
                "connection-string",
                kind="positive",
                support="supported",
                expected_types=["connection_string_password"],
                note="A postgres authority.",
            ),
            fixture(
                "conn-mysql-gap",
                "connection-string",
                kind="boundary",
                support="intentionally-unsupported",
                note="mysql is not yet exercised.",
            ),
        ]
        state, ids = GEN.row_state(fixtures, "connection_string_password", scheme="postgres")
        self.assertEqual((state, ids), ("supported", ["conn-postgres"]))

        state, ids = GEN.row_state(fixtures, "connection_string_password", scheme="mysql")
        self.assertEqual((state, ids), ("intentionally-unsupported", ["conn-mysql-gap"]))

        state, ids = GEN.row_state(fixtures, "connection_string_password", scheme="mariadb")
        self.assertEqual((state, ids), ("unresolved", []))


class BuildReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "types": [
                {
                    "type": "widget_token",
                    "detector": "widget",
                    "policyClass": "always-redact",
                    "reconciliationTrigger": "widget-trigger",
                    "schemes": None,
                },
                {
                    "type": "gadget_a",
                    "detector": "gadget",
                    "policyClass": "always-redact",
                    "reconciliationTrigger": "gadget-a-trigger",
                    "schemes": None,
                },
                {
                    "type": "gadget_b",
                    "detector": "gadget",
                    "policyClass": "confidence-gated",
                    "reconciliationTrigger": "gadget-b-trigger",
                    "schemes": ["north", "south"],
                },
            ],
            "consumers": [
                {"path": "scripts/generate-coverage-inventory.py", "role": "self"},
                {"path": "scripts/does-not-exist.py", "role": "missing on purpose"},
            ],
        }
        self.corpus = {
            "fixtures": [
                fixture("w-1", "widget", kind="positive", support="supported", expected_types=["widget_token"]),
                fixture("g-a", "gadget", kind="positive", support="supported", expected_types=["gadget_a"]),
                fixture(
                    "g-b-north",
                    "gadget",
                    kind="positive",
                    support="supported",
                    expected_types=["gadget_b"],
                    note="the north scheme",
                ),
            ]
        }

    def test_one_row_per_declared_type(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        self.assertEqual(len(report["rows"]), 3)
        self.assertEqual({row["type"] for row in report["rows"]}, {"widget_token", "gadget_a", "gadget_b"})

    def test_states_are_restricted_to_the_declared_four(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        for row in report["rows"]:
            self.assertIn(row["state"], GEN.ROW_STATES)
            if row["schemeRows"] != "not-applicable":
                for scheme_row in row["schemeRows"]:
                    self.assertIn(scheme_row["state"], GEN.ROW_STATES)

    def test_scheme_dimension_is_not_applicable_when_the_type_has_no_schemes(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        widget_row = next(row for row in report["rows"] if row["type"] == "widget_token")
        self.assertEqual(widget_row["schemeRows"], "not-applicable")

    def test_scheme_rows_report_per_scheme_evidence(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        gadget_b = next(row for row in report["rows"] if row["type"] == "gadget_b")
        north = next(s for s in gadget_b["schemeRows"] if s["scheme"] == "north")
        south = next(s for s in gadget_b["schemeRows"] if s["scheme"] == "south")
        self.assertEqual(north["state"], "supported")
        self.assertEqual(south["state"], "unresolved")

    def test_report_carries_no_fixture_input(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        serialized = json.dumps(report)
        self.assertNotIn("irrelevant-to-the-inventory", serialized)

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertNotIn("input", value)
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(report)

    def test_missing_consumer_path_is_reported_but_still_recorded(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        missing = next(c for c in report["consumers"] if c["path"] == "scripts/does-not-exist.py")
        present = next(c for c in report["consumers"] if c["path"] == "scripts/generate-coverage-inventory.py")
        self.assertFalse(missing["exists"])
        self.assertTrue(present["exists"])

    def test_structural_errors_flag_missing_consumer_and_detector_drift(self) -> None:
        report = GEN.build_report(self.manifest, self.corpus, ROOT)
        errors = GEN.structural_errors(report)
        self.assertTrue(any("does-not-exist.py" in error for error in errors))

    def test_declared_detector_missing_from_corpus_is_structural_drift(self) -> None:
        corpus_without_gadget = {"fixtures": [f for f in self.corpus["fixtures"] if f["detector"] != "gadget"]}
        report = GEN.build_report(self.manifest, corpus_without_gadget, ROOT)
        self.assertIn("gadget", report["reconciliation"]["declaredDetectorsMissingFromCorpus"])
        errors = GEN.structural_errors(report)
        self.assertTrue(any("gadget" in error for error in errors))


class DeterminismTests(unittest.TestCase):
    def test_repeated_runs_are_byte_identical(self) -> None:
        manifest = GEN.load_json(GEN.MANIFEST_PATH)
        corpus = GEN.load_json(GEN.CORPUS_PATH)
        first = json.dumps(GEN.build_report(manifest, corpus, ROOT), indent=2, sort_keys=True)
        second = json.dumps(GEN.build_report(manifest, corpus, ROOT), indent=2, sort_keys=True)
        self.assertEqual(first, second)


class RealRepoReconciliationTests(unittest.TestCase):
    """These exercise the committed baseline against the real corpus, so a
    change to either without updating the other is caught the same way
    `python3 -B scripts/generate-coverage-inventory.py` would catch it."""

    def test_committed_baseline_has_no_structural_drift(self) -> None:
        manifest = GEN.load_json(GEN.MANIFEST_PATH)
        corpus = GEN.load_json(GEN.CORPUS_PATH)
        report = GEN.build_report(manifest, corpus, ROOT)
        self.assertEqual(GEN.structural_errors(report), [])

    def test_committed_baseline_declares_a_row_per_type(self) -> None:
        manifest = GEN.load_json(GEN.MANIFEST_PATH)
        types = [entry["type"] for entry in manifest["types"]]
        self.assertEqual(len(types), len(set(types)), "declared finding types must be unique")

    def test_committed_inventory_report_is_up_to_date(self) -> None:
        """A built-in capability (detector, finding type, corpus evidence)
        added or removed without regenerating and committing
        ``docs/coverage/inventory-report.json`` fails here -- issue #104's
        drift-as-a-CI-failure guarantee for the generated inventory report."""
        manifest = GEN.load_json(GEN.MANIFEST_PATH)
        corpus = GEN.load_json(GEN.CORPUS_PATH)
        report = GEN.build_report(manifest, corpus, ROOT)
        fresh = json.dumps(report, indent=2, sort_keys=True) + "\n"
        committed = (ROOT / "docs" / "coverage" / "inventory-report.json").read_text(encoding="utf-8")
        self.assertEqual(
            fresh,
            committed,
            "docs/coverage/inventory-report.json is out of date; regenerate it with "
            "`python3 -B scripts/generate-coverage-inventory.py "
            "--out docs/coverage/inventory-report.json`",
        )


if __name__ == "__main__":
    unittest.main()
