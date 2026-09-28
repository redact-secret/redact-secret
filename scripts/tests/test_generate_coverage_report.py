from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-coverage-report.py"
SPEC = importlib.util.spec_from_file_location("generate_coverage_report", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]


def dimension(name: str, state: str, *, backlog_id: str | None = None) -> dict:
    row = {"dimension": name, "state": state, "evidenceFixtureIds": []}
    if state == "pending":
        row["exception"] = {"code": "pending", "backlogId": backlog_id or f"{name}-gap"}
    elif state == "not-applicable":
        row["exception"] = {"code": "no-concept"}
    return row


class BuildReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory_report = {
            "rows": [
                {
                    "type": "widget_token",
                    "detector": "widget",
                    "state": "supported",
                    "schemeRows": "not-applicable",
                },
                {
                    "type": "gadget_token",
                    "detector": "gadget",
                    "state": "unresolved",
                    "schemeRows": [
                        {"scheme": "north", "state": "supported"},
                        {"scheme": "south", "state": "unresolved"},
                    ],
                },
            ],
            "summary": {"supported": 1, "intentionally-unsupported": 0, "not-applicable": 0, "unresolved": 1},
        }
        self.declarations_doc = {
            "declarations": [
                {
                    "type": "widget_token",
                    "detector": "widget",
                    "behaviorClass": "provider",
                    "dimensions": [
                        dimension("positive", "supported"),
                        dimension("host-context", "pending", backlog_id="widget-host-context"),
                    ],
                    "note": "widget",
                },
                {
                    "type": "gadget_token",
                    "detector": "gadget",
                    "behaviorClass": "provider",
                    "dimensions": [
                        dimension("positive", "supported"),
                        dimension("incremental", "not-applicable"),
                    ],
                    "note": "gadget",
                },
                {
                    "type": "incremental",
                    "detector": "unassigned",
                    "behaviorClass": "incremental",
                    "dimensions": [dimension("incremental", "supported")],
                    "note": "cross-cutting",
                },
            ]
        }

    def test_groups_by_detector(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        detectors = {entry["detector"]: entry for entry in report["byDetector"]}
        self.assertEqual(detectors["widget"]["stateCounts"]["supported"], 1)
        self.assertEqual(detectors["gadget"]["stateCounts"]["unresolved"], 1)

    def test_groups_by_finding_type_and_joins_declaration(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        widget = next(row for row in report["byFindingType"] if row["type"] == "widget_token")
        self.assertEqual(widget["behaviorClass"], "provider")
        self.assertEqual(widget["pendingDimensions"], ["host-context"])

    def test_incremental_row_is_excluded_from_finding_types(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        types = {row["type"] for row in report["byFindingType"]}
        self.assertNotIn("incremental", types)

    def test_groups_by_scheme(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        self.assertEqual(
            [(row["scheme"], row["state"]) for row in report["byScheme"]],
            [("north", "supported"), ("south", "unresolved")],
        )

    def test_groups_by_evidence_dimension(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        by_name = {entry["dimension"]: entry for entry in report["byEvidenceDimension"]}
        self.assertEqual(by_name["positive"]["supported"], 2)
        self.assertEqual(by_name["host-context"]["pending"], 1)
        self.assertEqual(by_name["incremental"]["not-applicable"], 1)
        self.assertEqual(by_name["incremental"]["supported"], 1)

    def test_reports_unresolved_state(self) -> None:
        report = GEN.build_report(self.inventory_report, self.declarations_doc)
        self.assertEqual(report["unresolved"]["types"], ["gadget_token"])
        self.assertEqual(report["unresolved"]["schemes"], ["gadget_token/south"])
        self.assertEqual(
            report["unresolved"]["pendingDimensions"],
            [("widget_token.host-context", "widget-host-context")],
        )

    def test_report_carries_no_fixture_input_marker(self) -> None:
        markdown = GEN.render_markdown(GEN.build_report(self.inventory_report, self.declarations_doc))
        self.assertNotIn("evidenceFixtureIds", markdown)

    def test_supported_ratio_is_generated_from_the_row_counts(self) -> None:
        markdown = GEN.render_markdown(GEN.build_report(self.inventory_report, self.declarations_doc))
        self.assertIn("1/2 supported does not mean", markdown)


class ReconciliationTests(unittest.TestCase):
    def test_no_errors_when_types_and_detectors_agree(self) -> None:
        inventory_report = {
            "rows": [{"type": "widget_token", "detector": "widget", "state": "supported", "schemeRows": "not-applicable"}]
        }
        declarations_doc = {
            "declarations": [
                {
                    "type": "widget_token",
                    "detector": "widget",
                    "behaviorClass": "provider",
                    "dimensions": [],
                    "note": "",
                }
            ]
        }
        self.assertEqual(GEN.reconciliation_errors(inventory_report, declarations_doc), [])

    def test_type_missing_from_declarations_is_an_error(self) -> None:
        inventory_report = {
            "rows": [{"type": "widget_token", "detector": "widget", "state": "supported", "schemeRows": "not-applicable"}]
        }
        declarations_doc = {"declarations": []}
        errors = GEN.reconciliation_errors(inventory_report, declarations_doc)
        self.assertTrue(any("widget_token" in error for error in errors))

    def test_type_missing_from_inventory_is_an_error(self) -> None:
        inventory_report = {"rows": []}
        declarations_doc = {
            "declarations": [
                {
                    "type": "widget_token",
                    "detector": "widget",
                    "behaviorClass": "provider",
                    "dimensions": [],
                    "note": "",
                }
            ]
        }
        errors = GEN.reconciliation_errors(inventory_report, declarations_doc)
        self.assertTrue(any("widget_token" in error for error in errors))

    def test_mismatched_detector_is_an_error(self) -> None:
        inventory_report = {
            "rows": [{"type": "widget_token", "detector": "widget", "state": "supported", "schemeRows": "not-applicable"}]
        }
        declarations_doc = {
            "declarations": [
                {
                    "type": "widget_token",
                    "detector": "widget-v2",
                    "behaviorClass": "provider",
                    "dimensions": [],
                    "note": "",
                }
            ]
        }
        errors = GEN.reconciliation_errors(inventory_report, declarations_doc)
        self.assertTrue(any("widget_token" in error for error in errors))

    def test_binding_edge_and_incremental_rows_are_not_finding_types(self) -> None:
        """A ``binding-edge`` or ``incremental`` declaration row (consumer
        paths, the cross-cutting incremental surface) has no inventory
        counterpart by design and must not be flagged as drift."""
        inventory_report = {"rows": []}
        declarations_doc = {
            "declarations": [
                {
                    "type": "crates/secret-scan-core/tests/adversarial_bounds.rs",
                    "detector": "unassigned",
                    "behaviorClass": "binding-edge",
                    "dimensions": [],
                    "note": "",
                },
                {
                    "type": "incremental",
                    "detector": "unassigned",
                    "behaviorClass": "incremental",
                    "dimensions": [],
                    "note": "",
                },
            ]
        }
        self.assertEqual(GEN.reconciliation_errors(inventory_report, declarations_doc), [])


class DeterminismTests(unittest.TestCase):
    def test_repeated_runs_are_byte_identical(self) -> None:
        inventory_report = GEN.load_json(GEN.INVENTORY_REPORT_PATH)
        declarations_doc = GEN.load_json(GEN.DECLARATIONS_PATH)
        first = GEN.render_markdown(GEN.build_report(inventory_report, declarations_doc))
        second = GEN.render_markdown(GEN.build_report(inventory_report, declarations_doc))
        self.assertEqual(first, second)


class RealRepoReconciliationTests(unittest.TestCase):
    """Exercises the generator over the real, committed source documents, the
    same way `python3 -B scripts/generate-coverage-report.py` would."""

    def test_committed_source_documents_reconcile(self) -> None:
        inventory_report = GEN.load_json(GEN.INVENTORY_REPORT_PATH)
        declarations_doc = GEN.load_json(GEN.DECLARATIONS_PATH)
        self.assertEqual(GEN.reconciliation_errors(inventory_report, declarations_doc), [])

    def test_committed_coverage_report_is_up_to_date(self) -> None:
        inventory_report = GEN.load_json(GEN.INVENTORY_REPORT_PATH)
        declarations_doc = GEN.load_json(GEN.DECLARATIONS_PATH)
        fresh = GEN.render_markdown(GEN.build_report(inventory_report, declarations_doc))
        committed = (ROOT / "docs" / "coverage" / "coverage-report.md").read_text(encoding="utf-8")
        self.assertEqual(
            fresh,
            committed,
            "docs/coverage/coverage-report.md is out of date; regenerate it with "
            "`python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md`",
        )


if __name__ == "__main__":
    unittest.main()
