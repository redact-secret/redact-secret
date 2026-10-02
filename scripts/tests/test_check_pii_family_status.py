from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-pii-family-status.py"
SPEC = importlib.util.spec_from_file_location("check_pii_family_status", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)

CORE = "a" * 40
BENCH = "b" * 40
SHIPPED = {"pii:global:email", "pii:us:ssn"}
BINDING = {
    "qualification": {"coreRevision": CORE, "benchmarksRevision": BENCH},
    "codeChangedSinceQualification": [],
    "families": {"pii:global:email": "provisional", "pii:us:ssn": "pending"},
}
DOC = (
    f"{CORE} {BENCH}\n"
    "| `pii:global:email` | `pii` | global | `provisional` |\n"
    "| `pii:us:ssn` | `pii:us` | US | `pending` |\n"
)


def run(shipped=SHIPPED, binding=BINDING, doc=DOC, matrix=None) -> list[str]:
    return GATE.check(set(shipped), copy.deepcopy(binding), doc, matrix or {})


class GateTests(unittest.TestCase):
    def test_consistent_inputs_pass(self) -> None:
        self.assertEqual(run(), [])

    def test_shipped_family_without_row_fails(self) -> None:
        errors = run(shipped=SHIPPED | {"pii:global:new"})
        self.assertEqual(len([e for e in errors if "pii:global:new" in e]), 2)

    def test_documented_status_drift_fails(self) -> None:
        self.assertTrue(run(doc=DOC.replace("`pending`", "`provisional`")))

    def test_unknown_status_fails(self) -> None:
        binding = copy.deepcopy(BINDING)
        binding["families"]["pii:us:ssn"] = "great"
        self.assertTrue(any("not one of" in e for e in run(binding=binding)))

    def test_matrix_disagreement_fails(self) -> None:
        self.assertTrue(run(matrix={"pii:us:ssn": "stable"}))

    def test_short_or_undocumented_revision_fails(self) -> None:
        binding = copy.deepcopy(BINDING)
        binding["qualification"]["coreRevision"] = "8b6a5fde"
        self.assertTrue(run(binding=binding))
        self.assertTrue(run(doc=DOC.replace(BENCH, "")))

    def test_changed_file_must_exist_and_be_named(self) -> None:
        binding = copy.deepcopy(BINDING)
        binding["codeChangedSinceQualification"] = ["crates/secret-scan-core/src/pii/pii_email.rs"]
        self.assertTrue(any("does not name" in e for e in run(binding=binding)))
        binding["codeChangedSinceQualification"] = ["crates/nope.rs"]
        self.assertTrue(any("missing file" in e for e in run(binding=binding)))


class RepositoryTests(unittest.TestCase):
    def test_checked_in_state_passes(self) -> None:
        binding = json.loads(GATE.BINDING.read_text(encoding="utf-8"))
        matrix = json.loads(GATE.MATRIX.read_text(encoding="utf-8"))
        matrix_pii = {f["family"]: f["status"] for f in matrix["families"] if f["family"].startswith("pii:")}
        shipped = GATE.shipped_families()
        self.assertGreater(len(shipped), 0)
        self.assertEqual(GATE.check(shipped, binding, GATE.DOC.read_text(encoding="utf-8"), matrix_pii), [])


if __name__ == "__main__":
    unittest.main()
