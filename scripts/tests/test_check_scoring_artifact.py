#!/usr/bin/env python3
"""The reviewed shadow scoring artifact and its drift check (issue #798)."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-scoring-artifact.py"
spec = importlib.util.spec_from_file_location("check_scoring_artifact", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


ARTIFACT = load(check.ARTIFACT)
SCHEMA = load(check.SCHEMA)
LITERAL, _ = check.reviewed_literal((ROOT / check.DRIFT_TEST).read_text(encoding="utf-8"))


def mutated_model(artifact: dict, *, new_id: str | None = None) -> dict:
    """`artifact` with its high band threshold raised by one, fingerprint and
    ledger updated as a careless editor would, keeping or changing the id."""
    changed = copy.deepcopy(artifact)
    changed["model"]["aggregation"]["bands"]["high"] += 1
    changed["modelFingerprint"] = check.fingerprint(changed["model"])
    if new_id is None:
        changed["identityLedger"][-1]["modelFingerprint"] = changed["modelFingerprint"]
    else:
        changed["model"]["aggregation"]["id"] = new_id
        changed["modelFingerprint"] = check.fingerprint(changed["model"])
        changed["identityLedger"].append(
            {
                "model": new_id,
                "featureSchema": changed["model"]["featureSchema"]["id"],
                "modelFingerprint": changed["modelFingerprint"],
                "introducedInRevision": changed["artifact"]["revision"] + 1,
            }
        )
    changed["artifact"]["revision"] += 1
    return changed


class RepositoryArtifact(unittest.TestCase):
    def test_the_committed_artifact_passes(self) -> None:
        self.assertEqual(check.validate(ROOT), [])

    def test_the_artifact_matches_the_compiled_rendering(self) -> None:
        self.assertIsNotNone(LITERAL)
        self.assertEqual(ARTIFACT["model"], LITERAL)

    def test_the_manifest_binds_the_current_identities(self) -> None:
        model = ARTIFACT["model"]
        self.assertEqual(model["aggregation"]["id"], "evidence-aggregation/v2")
        self.assertEqual(model["featureSchema"]["id"], "evidence-features/v1")
        self.assertEqual(ARTIFACT["artifact"]["revision"], 3)
        self.assertEqual(
            ARTIFACT["modelFingerprint"],
            "4104fb2c6f046169f63e991dd7594c099af5fcea01deecae7afe1c7015579975",
        )
        self.assertEqual(
            ARTIFACT["calibration"]["featureDataset"]["datasetHash"],
            "4ea0a82f61b719b4611f8e7e2caafd01edda5b5dfa7c2691bffd6ac17d0e199c",
        )
        self.assertEqual(
            ARTIFACT["calibration"]["selection"]["sourceHash"],
            "23683daf5738b9cf3de583ade589f06677cfb2bcf581bff38e889b1eddae9509",
        )
        self.assertEqual(
            ARTIFACT["calibration"]["scoring"]["identity"],
            "838aa57db8e2331c8540a42da823ffda8802d681952f4dc7af20e6001c5693a2",
        )
        self.assertEqual(
            ARTIFACT["calibration"]["commit"],
            "e18efa2d0802c030925b9306a5dca33057185936",
        )
        self.assertEqual(ARTIFACT["tuningManifest"]["status"], "pending")
        self.assertIsNone(ARTIFACT["tuningManifest"]["hash"])

    def test_the_validation_cap_is_recorded_as_a_placeholder(self) -> None:
        ids = {item["id"] for item in ARTIFACT["knownLimitations"]}
        self.assertIn("validation-cap-placeholder", ids)
        self.assertIn("poor-generalization", ids)


class Schema(unittest.TestCase):
    def errors(self, artifact: dict) -> list[str]:
        return check.validate_schema(artifact, SCHEMA, SCHEMA)

    def test_the_artifact_validates(self) -> None:
        self.assertEqual(self.errors(ARTIFACT), [])

    def test_a_public_or_enforcing_claim_is_rejected(self) -> None:
        for key, value in (("publicApi", True), ("enforcing", True), ("loadedAtRuntime", True), ("findingFields", ["score"])):
            artifact = copy.deepcopy(ARTIFACT)
            artifact["use"][key] = value
            self.assertTrue(self.errors(artifact), key)

    def test_unknown_keys_and_bad_hashes_are_rejected(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["probability"] = 0.5
        self.assertTrue(self.errors(artifact))
        artifact = copy.deepcopy(ARTIFACT)
        artifact["calibration"]["commit"] = "101f674"
        self.assertTrue(self.errors(artifact))

    def test_a_bound_manifest_needs_a_hash_and_a_pending_one_has_none(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["tuningManifest"]["status"] = "bound"
        self.assertTrue(check.check_tuning_manifest(artifact))
        artifact = copy.deepcopy(ARTIFACT)
        artifact["tuningManifest"]["hash"] = "0" * 64
        self.assertTrue(check.check_tuning_manifest(artifact))


class Drift(unittest.TestCase):
    def test_an_artifact_value_the_compiled_scorer_lacks_is_drift(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["model"]["aggregation"]["groups"][3]["cap"] = 20
        errors = check.check_model(artifact, LITERAL)
        self.assertTrue(any("differs from the compiled scorer" in error for error in errors), errors)

    def test_a_compiled_value_the_artifact_lacks_is_drift(self) -> None:
        literal = copy.deepcopy(LITERAL)
        literal["featureSchema"]["goldenVectors"][1]["vector"][5] += 1
        errors = check.check_model(ARTIFACT, literal)
        self.assertTrue(any("differs from the compiled scorer" in error for error in errors), errors)

    def test_the_fingerprint_must_match(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["modelFingerprint"] = "0" * 64
        self.assertTrue(check.check_model(artifact, LITERAL))

    def test_a_changed_model_under_the_same_identity_fails_the_ledger(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["model"]["aggregation"]["bands"]["high"] += 1
        artifact["modelFingerprint"] = check.fingerprint(artifact["model"])
        errors = check.check_ledger(artifact)
        self.assertTrue(any("need a new model identity" in error for error in errors), errors)

    def test_a_model_identity_is_never_listed_twice(self) -> None:
        artifact = copy.deepcopy(ARTIFACT)
        artifact["identityLedger"].append(copy.deepcopy(artifact["identityLedger"][-1]))
        self.assertTrue(check.check_ledger(artifact))

    def test_spec_sections_end_at_the_next_heading(self) -> None:
        text = "# T\n\n## A\n\nalpha\n\n### A1\n\nbeta\n\n## B\n\ngamma\n"
        self.assertEqual(check.spec_section(text, "A"), "## A\n\nalpha\n\n### A1\n\nbeta\n")
        self.assertEqual(check.spec_section(text, "B"), "## B\n\ngamma\n")
        self.assertIsNone(check.spec_section(text, "C"))

    def test_the_reviewed_literal_is_found_with_any_raw_string_depth(self) -> None:
        body = '{"a": "#"}'
        source = f'const REVIEWED_MODEL_JSON: &str = r##"{body}"##;'
        self.assertEqual(check.reviewed_literal(source), ({"a": "#"}, None))
        self.assertIsNotNone(check.reviewed_literal("const OTHER: &str = \"\";")[1])


class BaseComparison(unittest.TestCase):
    def test_an_unchanged_artifact_passes(self) -> None:
        self.assertEqual(check.compare_with_base(ARTIFACT, copy.deepcopy(ARTIFACT)), [])

    def test_a_first_artifact_passes(self) -> None:
        self.assertEqual(check.compare_with_base(None, ARTIFACT), [])

    def test_any_change_needs_a_higher_revision(self) -> None:
        head = copy.deepcopy(ARTIFACT)
        head["calibration"]["reproduction"] += " Edited."
        errors = check.compare_with_base(ARTIFACT, head)
        self.assertTrue(any("artifact.revision" in error for error in errors), errors)
        head["artifact"]["revision"] += 1
        self.assertEqual(check.compare_with_base(ARTIFACT, head), [])

    def test_a_changed_constant_with_an_unchanged_model_identity_fails(self) -> None:
        head = mutated_model(ARTIFACT)
        self.assertEqual(check.check_ledger(head), [])
        errors = check.compare_with_base(ARTIFACT, head)
        self.assertTrue(any("same model identity" in error for error in errors), errors)
        self.assertTrue(any("append-only" in error for error in errors), errors)

    def test_a_changed_constant_with_a_new_model_identity_passes(self) -> None:
        head = mutated_model(ARTIFACT, new_id="evidence-aggregation/v3")
        self.assertEqual(check.check_ledger(head), [])
        self.assertEqual(check.compare_with_base(ARTIFACT, head), [])

    def test_changed_feature_semantics_need_a_new_feature_schema_identity(self) -> None:
        head = copy.deepcopy(ARTIFACT)
        head["model"]["featureSchema"]["maxAnalysedChars"] = 512
        head["model"]["aggregation"]["id"] = "evidence-aggregation/v2"
        head["artifact"]["revision"] += 1
        errors = check.compare_with_base(ARTIFACT, head)
        self.assertTrue(any("feature schema identity" in error for error in errors), errors)


class Packaging(unittest.TestCase):
    def test_no_package_file_list_ships_the_artifact(self) -> None:
        self.assertEqual(check.check_not_packaged(ROOT), [])


if __name__ == "__main__":
    unittest.main()
