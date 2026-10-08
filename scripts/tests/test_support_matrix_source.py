from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support_matrix_source as source


def canonical():
    return {
        "schema": source.VIEW_SCHEMA,
        "mode": "published",
        "publication": "public",
        "source": {
            "view": {"policyRevision": "rs-policy-1:sha256:" + "a" * 64},
            "publishedPackage": {"packageName": "@redact-secret/core", "version": "0.1.0-beta.14"},
            "populations": [
                {
                    "population": p,
                    "runClass": "public",
                    "semanticDigest": "sha256:" + "b" * 64,
                    "artifactDigest": "sha256:" + "c" * 64,
                    "scannerBuilds": {s: "released" for s in source.REQUIRED_SCANNERS},
                    "scannerVersions": {
                        s: "0.1.0-beta.14" if s == "redact-secret" else "1.0.0" for s in source.REQUIRED_SCANNERS
                    },
                }
                for p in sorted(source.POPULATIONS)
            ],
        },
    }


class SourceTest(unittest.TestCase):
    def test_native_identity_has_no_invented_legacy_run_or_product_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "benchmarks").mkdir()
            (root / "benchmarks/pin-source.json").write_text(json.dumps({"benchmarkCommit": "d" * 40}))
            identity = source.matrix_source(canonical(), root)
            self.assertEqual(identity["revision"], "d" * 40)
            self.assertEqual(identity["productVersion"], "0.1.0-beta.14")
            for key in ("generatedAt", "runId", "productRevision", "dirty"):
                self.assertIsNone(identity[key])
            self.assertNotIn("sourceReport", identity)

    def test_missing_candidate_optional_or_duplicate_scanner_population_fails(self):
        for mutate in (
            lambda m: m["source"]["populations"][0]["scannerBuilds"].update({"redact-secret": "candidate"}),
            lambda m: m["source"]["populations"][0]["scannerVersions"].pop("trufflehog"),
            lambda m: m["source"]["populations"][0]["scannerBuilds"].update({"openredaction": "released"}),
            lambda m: m["source"]["populations"].append(copy.deepcopy(m["source"]["populations"][0])),
        ):
            value = canonical()
            mutate(value)
            self.assertTrue(source.view_source_errors(value))

    def test_malformed_nested_rosters_fail_closed(self):
        for replacement in (None, [], "released"):
            value = canonical()
            value["source"]["populations"][0]["scannerBuilds"] = replacement
            self.assertTrue(source.view_source_errors(value))
        value = canonical()
        value["source"]["populations"][0] = None
        self.assertTrue(source.view_source_errors(value))

    def test_actual_published_version_must_agree_across_populations(self):
        value = canonical()
        value["source"]["populations"][0]["scannerVersions"]["redact-secret"] = "0.1.0-beta.13"
        self.assertTrue(source.view_source_errors(value))

    def test_historical_pii_is_separate_and_never_current_relabelled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "benchmarks").mkdir()
            historical = {
                "sourceReport": {"revision": "e" * 40},
                "piiFamilies": [{"family": "synthetic:email", "status": "provisional"}],
            }
            (root / source.HISTORICAL_PII).write_text(json.dumps(historical))
            self.assertEqual(source.historical_pii_matrix(canonical(), root), historical)
            self.assertIs(source.historical_pii_matrix(historical, root), historical)

    def test_unpinned_current_schema_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(source.matrix_schema_errors(canonical(), Path(directory)))
