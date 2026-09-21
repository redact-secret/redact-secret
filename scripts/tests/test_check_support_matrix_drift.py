from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-support-matrix-drift.py"
SPEC = importlib.util.spec_from_file_location("check_support_matrix_drift", SCRIPT)
assert SPEC and SPEC.loader
DRIFT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIFT
SPEC.loader.exec_module(DRIFT)

SCHEMA = {
    "properties": {
        "families": {"items": {"properties": {"status": {"enum": ["stable", "provisional", "pending", "unsupported"]}}}},
    }
}


def family(family_id, status, *, provider="widget", name=None, reason=None, provider_source=None, tier="T1"):
    return {
        "provider": provider,
        "family": family_id,
        "familyName": name or family_id,
        "status": status,
        "evidenceTier": tier if status != "unsupported" else None,
        "providerSource": provider_source,
        "corroboratingScanners": [],
        "twinCoverage": None,
        "unresolvedCriticalItems": None,
        "detectors": ["widget-token"] if status != "unsupported" else [],
        "reason": reason if status != "stable" else None,
    }


def matrix(families, *, dirty=False):
    return {
        "schemaVersion": 1,
        "taxonomySchemaVersion": 1,
        "sourceReport": {
            "schemaVersion": 1,
            "generatedAt": "2026-09-21T00:00:00.000Z",
            "runId": "test-run",
            "revision": "0" * 40,
            "dirty": dirty,
            "criteriaSchemaVersion": 1,
        },
        "providerCount": len({f["provider"] for f in families if f["provider"]}),
        "familyCount": len(families),
        "distribution": {},
        "families": families,
    }


class ValidateMatrixTests(unittest.TestCase):
    def test_accepts_a_well_formed_matrix(self) -> None:
        self.assertEqual(DRIFT.validate_matrix("candidate", matrix([family("widget:token", "stable")]), SCHEMA), [])

    def test_rejects_a_status_outside_the_vocabulary(self) -> None:
        m = matrix([family("widget:token", "stable")])
        m["families"][0]["status"] = "beta"
        errors = DRIFT.validate_matrix("candidate", m, SCHEMA)
        self.assertTrue(any("is not in" in e for e in errors))

    def test_rejects_a_missing_status(self) -> None:
        m = matrix([family("widget:token", "stable")])
        del m["families"][0]["status"]
        errors = DRIFT.validate_matrix("candidate", m, SCHEMA)
        self.assertTrue(any("is not in" in e for e in errors))

    def test_rejects_a_duplicate_family(self) -> None:
        m = matrix([family("widget:token", "stable"), family("widget:token", "stable")])
        errors = DRIFT.validate_matrix("candidate", m, SCHEMA)
        self.assertTrue(any("duplicate family" in e for e in errors))


class BuildDriftTests(unittest.TestCase):
    def test_a_family_dropping_out_of_stable_is_a_regression(self) -> None:
        baseline = matrix([family("widget:token", "stable")])
        candidate = matrix([family("widget:token", "provisional", reason="corpus regressed")])
        drift = DRIFT.build_drift(baseline, candidate)
        self.assertEqual(len(drift["regressions"]), 1)
        self.assertEqual(drift["regressions"][0]["reason"], "corpus regressed")
        self.assertEqual(drift["improvements"], [])

    def test_a_regression_with_no_reason_raises(self) -> None:
        baseline = matrix([family("widget:token", "stable")])
        candidate = matrix([family("widget:token", "provisional", reason=None)])
        with self.assertRaises(ValueError):
            DRIFT.build_drift(baseline, candidate)

    def test_a_family_reaching_stable_is_an_improvement_carrying_evidence(self) -> None:
        baseline = matrix([family("widget:token", "provisional", reason="T2 only")])
        candidate = matrix([family("widget:token", "stable")])
        drift = DRIFT.build_drift(baseline, candidate)
        self.assertEqual(len(drift["improvements"]), 1)
        self.assertEqual(drift["improvements"][0]["evidence"]["evidenceTier"], "T1")
        self.assertEqual(drift["regressions"], [])

    def test_a_family_absent_from_the_baseline_is_new_and_unclassified(self) -> None:
        baseline = matrix([])
        candidate = matrix([family("widget:token", "pending", reason="no contract yet")])
        drift = DRIFT.build_drift(baseline, candidate)
        self.assertEqual(drift["newAndUnclassified"], [{"provider": "widget", "family": "widget:token", "familyName": "widget:token", "status": "pending"}])

    def test_unchanged_status_with_differing_provider_source_is_stale_provenance(self) -> None:
        old_source = {"url": "https://old", "observedAt": "2026-01-01", "formatVersion": "1", "covers": "prefix"}
        new_source = {"url": "https://new", "observedAt": "2026-06-01", "formatVersion": "2", "covers": "prefix"}
        baseline = matrix([family("widget:token", "provisional", reason="T2 only", provider_source=old_source)])
        candidate = matrix([family("widget:token", "provisional", reason="T2 only", provider_source=new_source)])
        drift = DRIFT.build_drift(baseline, candidate)
        self.assertEqual(len(drift["staleProviderProvenance"]), 1)
        self.assertEqual(drift["staleProviderProvenance"][0]["baselineProviderSource"], old_source)
        self.assertEqual(drift["staleProviderProvenance"][0]["candidateProviderSource"], new_source)

    def test_unchanged_status_with_same_provider_source_is_quiet(self) -> None:
        source = {"url": "https://same", "observedAt": "2026-01-01", "formatVersion": "1", "covers": "prefix"}
        baseline = matrix([family("widget:token", "stable", provider_source=source)])
        candidate = matrix([family("widget:token", "stable", provider_source=source)])
        drift = DRIFT.build_drift(baseline, candidate)
        self.assertEqual(drift["regressions"], [])
        self.assertEqual(drift["improvements"], [])
        self.assertEqual(drift["staleProviderProvenance"], [])

    def test_a_family_dropped_by_the_candidate_is_out_of_scope(self) -> None:
        baseline = matrix([family("widget:token", "stable"), family("gadget:key", "stable")])
        candidate = matrix([family("widget:token", "stable")])
        drift = DRIFT.build_drift(baseline, candidate)
        for kind in drift.values():
            self.assertEqual(kind, [])


class CheckRegressionsTests(unittest.TestCase):
    def make_regression(self, **overrides):
        regression = {"family": "widget:token", "baselineStatus": "stable", "candidateStatus": "provisional", "reason": "corpus regressed"}
        regression.update(overrides)
        return regression

    def test_unacknowledged_regression_fails(self) -> None:
        problems = DRIFT.check_regressions([self.make_regression()], {})
        self.assertTrue(any("UNACKNOWLEDGED" in p for p in problems))

    def test_acknowledged_regression_passes(self) -> None:
        regression = self.make_regression()
        fingerprint = DRIFT.regression_fingerprint(
            regression["family"], regression["baselineStatus"], regression["candidateStatus"], regression["reason"]
        )
        acknowledgements = {fingerprint: {"rationale": "known corpus flake, tracked in #999"}}
        self.assertEqual(DRIFT.check_regressions([regression], acknowledgements), [])

    def test_acknowledgement_with_no_rationale_fails(self) -> None:
        regression = self.make_regression()
        fingerprint = DRIFT.regression_fingerprint(
            regression["family"], regression["baselineStatus"], regression["candidateStatus"], regression["reason"]
        )
        problems = DRIFT.check_regressions([regression], {fingerprint: {}})
        self.assertTrue(any("no rationale recorded" in p for p in problems))

    def test_acknowledgement_does_not_cover_a_different_reason(self) -> None:
        regression = self.make_regression()
        fingerprint = DRIFT.regression_fingerprint(
            regression["family"], regression["baselineStatus"], regression["candidateStatus"], "a different reason"
        )
        acknowledgements = {fingerprint: {"rationale": "covers the wrong reason"}}
        problems = DRIFT.check_regressions([regression], acknowledgements)
        self.assertTrue(any("UNACKNOWLEDGED" in p for p in problems))


class MainTests(unittest.TestCase):
    def write(self, tmp: Path, name: str, data: dict) -> Path:
        path = tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_passes_with_no_regressions_and_writes_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = self.write(tmp, "candidate.json", matrix([family("widget:token", "stable")]))
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            out = tmp / "drift.json"
            status = DRIFT.main(
                ["--baseline", str(baseline), "--candidate", str(candidate), "--schema", str(schema), "--out", str(out)]
            )
            self.assertEqual(status, 0)
            record = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(record["summary"]["regressions"], 0)

    def test_unacknowledged_regression_fails_but_still_writes_the_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = self.write(
                tmp, "candidate.json", matrix([family("widget:token", "provisional", reason="corpus regressed")])
            )
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            acknowledgements = self.write(tmp, "acknowledgements.json", {})
            out = tmp / "drift.json"
            status = DRIFT.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--schema",
                    str(schema),
                    "--acknowledgements",
                    str(acknowledgements),
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertTrue(out.exists())
            record = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(record["summary"]["regressions"], 1)

    def test_acknowledged_regression_passes_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = self.write(
                tmp, "candidate.json", matrix([family("widget:token", "provisional", reason="corpus regressed")])
            )
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            fingerprint = DRIFT.regression_fingerprint("widget:token", "stable", "provisional", "corpus regressed")
            acknowledgements = self.write(
                tmp, "acknowledgements.json", {fingerprint: {"rationale": "known corpus flake, tracked in #999"}}
            )
            status = DRIFT.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--schema",
                    str(schema),
                    "--acknowledgements",
                    str(acknowledgements),
                ]
            )
            self.assertEqual(status, 0)

    def test_dirty_candidate_is_rejected_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = self.write(tmp, "candidate.json", matrix([family("widget:token", "stable")], dirty=True))
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            status = DRIFT.main(["--baseline", str(baseline), "--candidate", str(candidate), "--schema", str(schema)])
            self.assertEqual(status, 1)

    def test_dirty_candidate_is_allowed_with_the_escape_hatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = self.write(tmp, "candidate.json", matrix([family("widget:token", "stable")], dirty=True))
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            status = DRIFT.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--schema",
                    str(schema),
                    "--allow-dirty-candidate",
                ]
            )
            self.assertEqual(status, 0)

    def test_invalid_candidate_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            baseline = self.write(tmp, "baseline.json", matrix([family("widget:token", "stable")]))
            candidate = tmp / "candidate.json"
            candidate.write_text("not json", encoding="utf-8")
            schema = self.write(tmp, "schema.json", DRIFT.load_json(DRIFT.SCHEMA_PATH))
            status = DRIFT.main(["--baseline", str(baseline), "--candidate", str(candidate), "--schema", str(schema)])
            self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
