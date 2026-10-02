from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "report-detection-support.py"
SPEC = importlib.util.spec_from_file_location("report_detection_support", SCRIPT)
assert SPEC and SPEC.loader
REPORT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPORT
SPEC.loader.exec_module(REPORT)

REVISION = "0" * 40


class ReportInvariantTests(unittest.TestCase):
    """Invariants over the checked-in inventory and pinned matrix, so the test
    stays valid when either is refreshed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = REPORT.build(REVISION)

    def test_every_detector_is_counted_exactly_once(self) -> None:
        counts = self.report["credentialDetectorsByWeakestStatus"]
        self.assertEqual(sum(counts.values()), self.report["shipped"]["credentialDetectors"])
        self.assertEqual(len(self.report["detectors"]), self.report["shipped"]["credentialDetectors"])

    def test_matrix_family_counts_add_up(self) -> None:
        matrix = self.report["matrix"]
        self.assertEqual(sum(matrix["familiesByStatus"].values()), matrix["families"])

    def test_unmeasured_list_matches_its_count(self) -> None:
        listed = self.report["shippedButUnmeasuredCredentialDetectors"]
        self.assertEqual(len(listed), self.report["credentialDetectorsByWeakestStatus"]["shipped-but-unmeasured"])

    def test_pii_families_come_from_code_and_are_all_documented(self) -> None:
        rows = self.report["piiFamilies"]
        self.assertEqual(len(rows), self.report["shipped"]["piiFamilies"])
        self.assertGreater(len(rows), 0)
        for row in rows:
            self.assertTrue(row["family"].startswith("pii:"))
            self.assertIsNotNone(row["documentedStatus"], row["family"])

    def test_every_folded_matrix_id_is_owned_by_a_shipped_detector(self) -> None:
        shipped = {row["detector"] for row in self.report["detectors"]}
        self.assertEqual(self.report["matrix"]["detectorIdsNotInInventory"], [])
        for owner in self.report["matrix"]["foldedDetectorIds"].values():
            self.assertIn(owner, shipped)

    def test_output_is_deterministic(self) -> None:
        self.assertEqual(REPORT.markdown(REPORT.build(REVISION)), REPORT.markdown(self.report))
        self.assertIn(REVISION, REPORT.markdown(self.report))


if __name__ == "__main__":
    unittest.main()
