from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-detector-family-coverage.py"
SPEC = importlib.util.spec_from_file_location("check_detector_family_coverage", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

INVENTORY = {
    "types": [
        {"type": "alpha_token", "detector": "alpha-token"},
        {"type": "beta_key", "detector": "beta-key"},
        {"type": "beta_secret", "detector": "beta-key"},
    ]
}
MATRIX = {"families": [{"family": "alpha:token", "detectors": ["alpha-token"]}]}


class CompareTests(unittest.TestCase):
    def test_finds_unmapped_detector_with_all_its_types(self) -> None:
        unmapped, stale = CHECK.compare(INVENTORY, MATRIX)
        self.assertEqual(unmapped, {"beta-key": ["beta_key", "beta_secret"]})
        self.assertEqual(stale, [])

    def test_finds_stale_matrix_detector(self) -> None:
        matrix = {"families": [{"family": "x:y", "detectors": ["alpha-token", "gone"]}]}
        _, stale = CHECK.compare(INVENTORY, matrix)
        self.assertEqual(stale, ["gone"])

    def test_family_without_detectors_key_is_tolerated(self) -> None:
        matrix = {"families": [{"family": "x:y"}, {"family": "a:b", "detectors": ["alpha-token", "beta-key"]}]}
        self.assertEqual(CHECK.compare(INVENTORY, matrix), ({}, []))


class MainTests(unittest.TestCase):
    def run_main(self, matrix: dict, *extra: str) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            inv, mat = Path(tmp, "inv.json"), Path(tmp, "mat.json")
            inv.write_text(json.dumps(INVENTORY), encoding="utf-8")
            mat.write_text(json.dumps(matrix), encoding="utf-8")
            return CHECK.main(["--inventory", str(inv), "--matrix", str(mat), *extra])

    def test_report_only_exits_zero_on_gap(self) -> None:
        self.assertEqual(self.run_main(MATRIX), 0)

    def test_strict_fails_on_gap(self) -> None:
        self.assertEqual(self.run_main(MATRIX, "--strict"), 1)

    def test_strict_passes_when_covered(self) -> None:
        full = {"families": [{"family": "a:b", "detectors": ["alpha-token", "beta-key"]}]}
        self.assertEqual(self.run_main(full, "--strict"), 0)

    def test_stale_entry_is_reported_and_fails_only_strict(self) -> None:
        stale = {"families": [{"family": "a:b", "detectors": ["alpha-token", "beta-key", "gone"]}]}
        self.assertEqual(self.run_main(stale), 0)
        self.assertEqual(self.run_main(stale, "--strict"), 1)


if __name__ == "__main__":
    unittest.main()
