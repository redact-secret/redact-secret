from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-fp-fn-summary.py"
SPEC = importlib.util.spec_from_file_location("generate_fp_fn_summary", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)


def fixture(id_: str, detector: str, *, kind: str, contexts: list[str] | None = None) -> dict:
    expected = (
        [{"detector": detector, "type": f"{detector}_type", "confidence": "high", "specificity": "provider", "start": 0, "end": 1}]
        if kind == "positive"
        else []
    )
    return {
        "id": id_,
        "detector": detector,
        "kind": kind,
        "support": "supported",
        "tier": "canonical" if kind == "positive" else "negative",
        "contexts": contexts or ["plain-text"],
        "input": "irrelevant-to-the-summary",
        "expected": expected,
        "note": "",
    }


class BuildDetectorRowTests(unittest.TestCase):
    def test_tallies_negative_and_positive_fixtures_separately(self) -> None:
        fixtures = [
            fixture("widget-negative-a", "widget", kind="negative"),
            fixture("widget-negative-b", "widget", kind="negative"),
            fixture("widget-positive-a", "widget", kind="positive"),
            fixture("gadget-positive-a", "gadget", kind="positive"),
        ]
        row = GEN.build_detector_row("widget", fixtures)
        self.assertEqual(row["falsePositiveGuards"]["count"], 2)
        self.assertEqual(row["falsePositiveGuards"]["fixtureIds"], ["widget-negative-a", "widget-negative-b"])
        self.assertEqual(row["falsePositiveGuards"]["actualFalsePositives"], 0)
        self.assertEqual(row["falseNegativeGuards"]["count"], 1)
        self.assertEqual(row["falseNegativeGuards"]["fixtureIds"], ["widget-positive-a"])
        self.assertEqual(row["falseNegativeGuards"]["actualFalseNegatives"], 0)

    def test_host_contexts_exercised_is_the_union_across_both_kinds(self) -> None:
        fixtures = [
            fixture("widget-negative-a", "widget", kind="negative", contexts=["shell"]),
            fixture("widget-positive-a", "widget", kind="positive", contexts=["dotenv"]),
            fixture("widget-positive-b", "widget", kind="positive", contexts=["plain-text"]),
        ]
        row = GEN.build_detector_row("widget", fixtures)
        self.assertEqual(row["hostContextsExercised"], ["dotenv", "plain-text", "shell"])

    def test_negative_fixture_with_non_empty_expected_is_rejected(self) -> None:
        broken = fixture("widget-negative-a", "widget", kind="negative")
        broken["expected"] = [{"detector": "widget", "type": "x", "confidence": "high", "specificity": "provider", "start": 0, "end": 1}]
        with self.assertRaises(ValueError):
            GEN.build_detector_row("widget", [broken])

    def test_positive_fixture_with_empty_expected_is_rejected(self) -> None:
        broken = fixture("widget-positive-a", "widget", kind="positive")
        broken["expected"] = []
        with self.assertRaises(ValueError):
            GEN.build_detector_row("widget", [broken])


class BuildReportTests(unittest.TestCase):
    def test_report_covers_every_requested_detector_sorted(self) -> None:
        corpus = {
            "fixtures": [
                fixture("gadget-negative-a", "gadget", kind="negative"),
                fixture("widget-positive-a", "widget", kind="positive"),
            ]
        }
        report = GEN.build_report(corpus, ["widget", "gadget"])
        self.assertEqual([row["detector"] for row in report["detectors"]], ["gadget", "widget"])
        self.assertEqual(report["provenance"]["corpus"], "conformance/fixtures/synchronous-corpus.json")
        self.assertIn("canonical_corpus.rs", report["provenance"]["enforcedBy"])

    def test_missing_detector_raises(self) -> None:
        corpus = {"fixtures": [fixture("widget-positive-a", "widget", kind="positive")]}
        with self.assertRaises(ValueError):
            GEN.build_report(corpus, ["widget", "not-a-real-detector"])

    def test_provenance_issue_defaults_to_a_single_string(self) -> None:
        corpus = {"fixtures": [fixture("widget-positive-a", "widget", kind="positive")]}
        report = GEN.build_report(corpus, ["widget"])
        self.assertEqual(report["provenance"]["issue"], GEN.DEFAULT_ISSUE)

    def test_provenance_issue_is_a_list_when_multiple_issues_are_reported(self) -> None:
        corpus = {"fixtures": [fixture("widget-positive-a", "widget", kind="positive")]}
        report = GEN.build_report(
            corpus,
            ["widget"],
            issues=[GEN.DEFAULT_ISSUE, "https://github.com/redact-secret/redact-secret/issues/317"],
        )
        self.assertEqual(
            report["provenance"]["issue"],
            [GEN.DEFAULT_ISSUE, "https://github.com/redact-secret/redact-secret/issues/317"],
        )


if __name__ == "__main__":
    unittest.main()
