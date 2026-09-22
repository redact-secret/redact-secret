from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-fp-fn-summary.py"
SPEC = importlib.util.spec_from_file_location("generate_fp_fn_summary", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]

# The exact detector/issue set docs/coverage/README.md documents as the
# live, all-detector command -- the only fp-fn-summary output this repo
# commits (issue #595 removed the per-issue `fp-fn-summary-NNN.json`
# snapshots that used to duplicate slices of it).
COMMITTED_DETECTORS = [
    "anthropic-token",
    "aws-access-key",
    "bearer-token",
    "cloudflare-token",
    "connection-string",
    "digitalocean-token",
    "docker-token",
    "jwt",
    "openai-token",
    "otpauth-uri",
    "shopify-token",
    "stripe-token",
    "supabase-token",
    "vault-token",
    "vercel-token",
]
COMMITTED_ISSUES = [
    f"https://github.com/redact-secret/redact-secret/issues/{n}"
    for n in (316, 317, 318, 320, 323, 324, 325, 370, 513)
]


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

    def test_single_provenance_issue_can_be_overridden(self) -> None:
        corpus = {"fixtures": [fixture("widget-positive-a", "widget", kind="positive")]}
        other_issue = "https://github.com/redact-secret/redact-secret/issues/319"
        report = GEN.build_report(corpus, ["widget"], issues=[other_issue])
        self.assertEqual(report["provenance"]["issue"], other_issue)


class RealRepoReconciliationTests(unittest.TestCase):
    """Exercises the committed report against the real corpus, so a corpus
    change that drops or renames a fixture without regenerating
    ``docs/coverage/fp-fn-summary.json`` is caught the same way
    ``python3 -B scripts/generate-fp-fn-summary.py`` would catch it."""

    def test_committed_fp_fn_summary_is_up_to_date(self) -> None:
        corpus = GEN.load_json(GEN.CORPUS_PATH)
        report = GEN.build_report(corpus, COMMITTED_DETECTORS, COMMITTED_ISSUES)
        fresh = json.dumps(report, indent=2, sort_keys=True) + "\n"
        committed = (ROOT / "docs" / "coverage" / "fp-fn-summary.json").read_text(encoding="utf-8")
        self.assertEqual(
            fresh,
            committed,
            "docs/coverage/fp-fn-summary.json is out of date; regenerate it with the "
            "command in docs/coverage/README.md",
        )


if __name__ == "__main__":
    unittest.main()
