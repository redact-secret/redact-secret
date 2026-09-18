from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-precision-context-matrix.py"
SPEC = importlib.util.spec_from_file_location("generate_precision_context_matrix", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)


def sync_fixture(
    id_: str,
    detector: str,
    *,
    kind: str = "positive",
    tier: str = "canonical",
    support: str = "supported",
    contexts: list[str] | None = None,
    expected_count: int = 1,
) -> dict:
    expected = (
        [
            {
                "detector": detector,
                "type": f"{detector}_type",
                "confidence": "high",
                "specificity": "provider",
                "start": 0,
                "end": 1,
            }
        ]
        * expected_count
        if expected_count
        else []
    )
    return {
        "id": id_,
        "detector": detector,
        "kind": kind,
        "support": support,
        "tier": tier,
        "contexts": contexts or ["plain-text"],
        "input": "irrelevant-to-the-matrix",
        "expected": expected,
        "note": "a safe note",
    }


def incr_fixture(id_: str, *, expected_count: int = 1) -> dict:
    expected = [{"detector": "x", "type": "y", "confidence": "high", "specificity": "provider", "start": 0, "end": 1}] * expected_count
    return {"id": id_, "input": "irrelevant", "text": "irrelevant", "expected": expected, "note": "a safe note"}


def empty_baseline() -> dict:
    return {"pairs": []}


class SynchronousRowTests(unittest.TestCase):
    def test_flagged_fixture_reports_finding_count_and_no_before_claim(self) -> None:
        row = GEN.synchronous_row(sync_fixture("widget-positive-a", "widget"))
        self.assertEqual(row["result"], "flagged")
        self.assertEqual(row["findingCount"], 1)
        self.assertEqual(row["scanMode"], "synchronous")
        self.assertNotIn("before", row)

    def test_silent_fixture_reports_zero_findings(self) -> None:
        row = GEN.synchronous_row(sync_fixture("widget-negative-a", "widget", kind="negative", tier="negative", expected_count=0))
        self.assertEqual(row["result"], "silent")
        self.assertEqual(row["findingCount"], 0)

    def test_carries_support_and_contexts_through(self) -> None:
        row = GEN.synchronous_row(
            sync_fixture(
                "widget-boundary-a",
                "widget",
                kind="boundary",
                tier="malformed",
                support="intentionally-unsupported",
                contexts=["json", "log"],
                expected_count=0,
            )
        )
        self.assertEqual(row["support"], "intentionally-unsupported")
        self.assertEqual(row["contexts"], ["json", "log"])


class BuildMatrixTests(unittest.TestCase):
    def test_incremental_fixtures_are_attributed_by_id_prefix(self) -> None:
        sync_corpus = {"fixtures": [sync_fixture("widget-positive-a", "widget")]}
        incremental_corpus = {"fixtures": [incr_fixture("widget-discriminating-boundary"), incr_fixture("gadget-discriminating-boundary")]}
        matrix = GEN.build_matrix(sync_corpus, incremental_corpus, empty_baseline(), ["widget"])
        ids = [r["fixtureId"] for r in matrix["rows"] if r["scanMode"] == "incremental"]
        self.assertEqual(ids, ["widget-discriminating-boundary"])

    def test_unknown_detector_raises(self) -> None:
        sync_corpus = {"fixtures": [sync_fixture("widget-positive-a", "widget")]}
        with self.assertRaises(ValueError):
            GEN.build_matrix(sync_corpus, {"fixtures": []}, empty_baseline(), ["nonexistent-detector"])

    def test_explicitly_unsupported_fixture_ids_are_listed(self) -> None:
        sync_corpus = {
            "fixtures": [
                sync_fixture("widget-positive-a", "widget"),
                sync_fixture(
                    "widget-boundary-a",
                    "widget",
                    kind="boundary",
                    tier="malformed",
                    support="intentionally-unsupported",
                    expected_count=0,
                ),
            ]
        }
        matrix = GEN.build_matrix(sync_corpus, {"fixtures": []}, empty_baseline(), ["widget"])
        self.assertEqual(matrix["explicitlyUnsupportedFixtureIds"], ["widget-boundary-a"])

    def test_row_count_matches_rows_length(self) -> None:
        sync_corpus = {"fixtures": [sync_fixture("widget-positive-a", "widget")]}
        matrix = GEN.build_matrix(sync_corpus, {"fixtures": []}, empty_baseline(), ["widget"])
        self.assertEqual(matrix["rowCount"], len(matrix["rows"]))


class Beta4TwinBaselineRowsTests(unittest.TestCase):
    def test_projects_before_and_after_from_actual_ranges(self) -> None:
        baseline = {
            "pairs": [
                {
                    "family": "widget-token",
                    "variant": "legacy",
                    "context": "plain",
                    "mutation": "one byte short",
                    "contractView": {"twinFlaggedByContract": False},
                    "negative": {
                        "id": "widget-token-legacy-plain-twin",
                        "actualBeta4": [{"start": 0, "end": 10}],
                        "expected": [],
                    },
                    "positive": {
                        "id": "widget-token-legacy-plain",
                        "actualBeta4": [{"start": 0, "end": 10}],
                        "expected": [{"start": 0, "end": 10}],
                    },
                }
            ]
        }
        rows = GEN.beta4_twin_baseline_rows(baseline, ["widget-token"])
        self.assertEqual(len(rows), 2)
        negative_row = next(r for r in rows if r["side"] == "negative")
        self.assertEqual(negative_row["beforeResult"], "flagged")
        self.assertEqual(negative_row["afterResult"], "silent")
        positive_row = next(r for r in rows if r["side"] == "positive")
        self.assertEqual(positive_row["beforeResult"], "flagged")
        self.assertEqual(positive_row["afterResult"], "flagged")

    def test_pairs_outside_the_requested_detectors_are_excluded(self) -> None:
        baseline = {
            "pairs": [
                {
                    "family": "other-token",
                    "variant": "v",
                    "context": "plain",
                    "mutation": "m",
                    "contractView": {},
                    "negative": {"id": "a", "actualBeta4": [], "expected": []},
                    "positive": {"id": "b", "actualBeta4": [{"start": 0, "end": 1}], "expected": [{"start": 0, "end": 1}]},
                }
            ]
        }
        rows = GEN.beta4_twin_baseline_rows(baseline, ["widget-token"])
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
