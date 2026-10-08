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


def run(shipped=SHIPPED, binding=BINDING, doc=DOC, matrix=None, **identity) -> list[str]:
    return GATE.check(set(shipped), copy.deepcopy(binding), doc, matrix, **identity)


MATRIX_DOC = DOC + "The PII statuses are not re-qualified on any later core commit.\n"
MATRIX_BINDING = {key: value for key, value in BINDING.items() if key != "families"}
MATRIX_ROWS = {"pii:global:email": "provisional", "pii:us:ssn": "pending"}
MATRIX_QUALIFICATION = {
    "qualifiedAt": {"coreCommit": CORE},
    "benchmarks": {"recordRevision": BENCH},
    "requalification": {"state": "not-requalified"},
}
MATRIX_DISTRIBUTION = {"stable": 0, "provisional": 1, "pending": 1, "unsupported": 0}


def run_matrix(**overrides) -> list[str]:
    arguments = {
        "shipped": SHIPPED,
        "binding": MATRIX_BINDING,
        "doc": MATRIX_DOC,
        "matrix": MATRIX_ROWS,
        "matrix_qualification": MATRIX_QUALIFICATION,
        "matrix_distribution": MATRIX_DISTRIBUTION,
    }
    arguments.update(overrides)
    return run(**arguments)


class MatrixSourceTests(unittest.TestCase):
    def test_matrix_rows_are_the_status_source(self) -> None:
        self.assertEqual(run_matrix(), [])

    def test_shipped_family_missing_from_the_matrix_fails(self) -> None:
        errors = run_matrix(shipped=SHIPPED | {"pii:global:new"})
        self.assertTrue(any("pii:global:new" in e and "pinned matrix" in e for e in errors))

    def test_matrix_row_for_an_unshipped_family_fails(self) -> None:
        errors = run_matrix(matrix={**MATRIX_ROWS, "pii:global:gone": "pending"})
        self.assertTrue(any("pii:global:gone" in e and "not shipped" in e for e in errors))

    def test_documented_table_must_agree_with_the_matrix(self) -> None:
        errors = run_matrix(matrix={**MATRIX_ROWS, "pii:us:ssn": "provisional"})
        self.assertTrue(any("differs from the pinned matrix" in e for e in errors))

    def test_binding_families_map_is_rejected_once_the_matrix_has_rows(self) -> None:
        self.assertTrue(any("only status source" in e for e in run_matrix(binding=BINDING)))

    def test_distribution_must_match_the_rows(self) -> None:
        errors = run_matrix(matrix_distribution={**MATRIX_DISTRIBUTION, "provisional": 2})
        self.assertTrue(any("piiDistribution" in e for e in errors))

    def test_requalified_state_fails(self) -> None:
        qualification = {**MATRIX_QUALIFICATION, "requalification": {"state": "requalified"}}
        self.assertTrue(
            any("not-requalified" in e or "re-qualified" in e for e in run_matrix(matrix_qualification=qualification))
        )

    def test_qualification_must_match_the_binding_revisions(self) -> None:
        wrong_core = {**MATRIX_QUALIFICATION, "qualifiedAt": {"coreCommit": "c" * 40}}
        self.assertTrue(any("coreCommit" in e for e in run_matrix(matrix_qualification=wrong_core)))
        wrong_record = {**MATRIX_QUALIFICATION, "benchmarks": {"recordRevision": "c" * 40}}
        self.assertTrue(any("recordRevision" in e for e in run_matrix(matrix_qualification=wrong_record)))

    def test_page_must_say_not_requalified(self) -> None:
        self.assertTrue(any("re-qualified" in e for e in run_matrix(doc=DOC)))

    def test_missing_identity_in_the_matrix_fails(self) -> None:
        self.assertTrue(run_matrix(matrix_qualification=None))
        self.assertTrue(run_matrix(matrix_distribution=None))


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
        historical = GATE.historical_pii_matrix(matrix)
        shipped = GATE.shipped_families()
        self.assertGreater(len(shipped), 0)
        errors = GATE.check(
            shipped,
            binding,
            GATE.DOC.read_text(encoding="utf-8"),
            GATE.matrix_pii_statuses(historical),
            matrix_qualification=historical.get("piiQualification"),
            matrix_distribution=historical.get("piiDistribution"),
        )
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
