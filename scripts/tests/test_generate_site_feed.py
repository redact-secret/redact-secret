from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-site-feed.py"
SPEC = importlib.util.spec_from_file_location("generate_site_feed", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]
SOURCE = "a" * 40
BENCH = "b" * 40
PRODUCT = "c" * 40
ARTIFACTS = ["crate:redact-secret", "npm:@redact-secret/core", "pypi:redact-secret"]


def manifest(version: str, *, observed="2026-09-20", state=None, pypi_file=None, matrix_run="run-1"):
    python = GEN.pep440(version)
    return {
        "version": version,
        "source_revision": SOURCE,
        "artifact_set": list(ARTIFACTS),
        "registry_state": state or {artifact: "published" for artifact in ARTIFACTS},
        "artifact_digests": {
            "pypi:redact-secret": [{"file": pypi_file or f"redact_secret-{python}.tar.gz"}],
        },
        "support_matrix_drift": {"candidate": {"revision": BENCH, "runId": matrix_run}},
        "release_evidence": {
            "observed_at": observed,
            "tag": {"name": f"v{version}", "object": "d" * 40, "target": SOURCE},
        },
    }


def family(provider, family_id, name, status, tier="T1", profile="documented"):
    return {
        "provider": provider,
        "family": family_id,
        "familyName": name,
        "status": status,
        "evidenceTier": tier,
        "qualificationProfile": profile,
        # Owner-only fields that must never reach the feed.
        "reason": "internal review note",
        "detectors": ["widget-token"],
        "providerSource": {"url": "https://example.invalid/docs"},
    }


def matrix(generated_at="2026-09-18T01:02:03.456Z"):
    families = [
        family("widget", "widget:api-key", "API key", "stable"),
        family(None, "generic:jwt", "JSON Web Token", "provisional", "T3", None),
        family("gadget", "gadget:legacy-token", "Legacy token", "unsupported", None, None),
    ]
    return {
        "schemaVersion": 1,
        "sourceReport": {
            "generatedAt": generated_at,
            "runId": "run-1",
            "revision": BENCH,
            "dirty": False,
            "product": {"sourceCommit": PRODUCT, "declaredVersion": "0.1.0-beta.7"},
        },
        "providerCount": 2,
        "familyCount": len(families),
        "distribution": {"stable": 1, "provisional": 1, "pending": 0, "unsupported": 1},
        "families": families,
    }


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / GEN.FEED_DIR).mkdir(parents=True)
        shutil.copyfile(ROOT / GEN.SCHEMA_PATH, self.root / GEN.SCHEMA_PATH)
        self.write_matrix(matrix())

    def write_release(self, value: dict):
        directory = self.root / GEN.RELEASES_DIR / value["version"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "manifest.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def write_matrix(self, value: dict):
        path = self.root / GEN.MATRIX_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def generate(self) -> int:
        return GEN.main(["--root", str(self.root)])

    def feed_text(self) -> str:
        return (self.root / GEN.FEED_PATH).read_text(encoding="utf-8")

    def close(self):
        self.tmp.cleanup()


class SiteFeedTest(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.addCleanup(self.fixture.close)
        self.fixture.write_release(manifest("0.1.0-beta.9", observed="2026-09-10"))
        self.fixture.write_release(manifest("0.1.0-beta.10"))

    def test_regeneration_without_input_change_is_byte_identical(self):
        self.assertEqual(self.fixture.generate(), 0)
        first = self.fixture.feed_text()
        self.assertEqual(self.fixture.generate(), 0)
        self.assertEqual(self.fixture.feed_text(), first)
        self.assertEqual(GEN.check(self.fixture.root), [])

    def test_generated_at_is_the_latest_input_timestamp_not_wall_clock(self):
        feed = GEN.build_feed(self.fixture.root)
        self.assertEqual(feed["generatedAt"], "2026-09-20T00:00:00Z")
        self.fixture.write_matrix(matrix("2026-09-21T08:09:10.999Z"))
        feed = GEN.build_feed(self.fixture.root)
        self.assertEqual(feed["generatedAt"], "2026-09-21T08:09:10Z")
        self.assertEqual(feed["supportMatrix"]["generatedAt"], "2026-09-21T08:09:10Z")

    def test_latest_release_uses_semver_precedence(self):
        feed = GEN.build_feed(self.fixture.root)
        self.assertEqual(feed["release"]["version"], "0.1.0-beta.10")
        self.assertEqual(feed["sources"][0]["path"], "docs/releases/0.1.0-beta.10/manifest.json")
        self.fixture.write_release(manifest("0.1.0", observed="2026-10-01"))
        self.assertEqual(GEN.build_feed(self.fixture.root)["release"]["version"], "0.1.0")

    def test_packages_carry_each_registry_spelling(self):
        packages = GEN.build_feed(self.fixture.root)["release"]["packages"]
        self.assertEqual(
            packages,
            [
                {"ecosystem": "npm", "name": "@redact-secret/core", "version": "0.1.0-beta.10"},
                {"ecosystem": "crates", "name": "redact-secret", "version": "0.1.0-beta.10"},
                {"ecosystem": "pypi", "name": "redact-secret", "version": "0.1.0b10"},
            ],
        )

    def test_only_claimable_family_fields_are_copied(self):
        support = GEN.build_feed(self.fixture.root)["supportMatrix"]
        self.assertEqual(support["distribution"], {"stable": 1, "provisional": 1, "pending": 0, "unsupported": 1})
        self.assertTrue(support["gatedLatestRelease"])
        self.assertEqual(support["measuredProductVersion"], "0.1.0-beta.7")
        for entry in support["families"]:
            self.assertEqual(
                set(entry), {"provider", "family", "name", "status", "evidenceTier", "qualificationProfile"}
            )
        self.assertNotIn("internal review note", GEN.render(GEN.build_feed(self.fixture.root)))

    def test_matrix_not_gated_by_the_release_is_reported(self):
        self.fixture.write_release(manifest("0.1.0-beta.10", matrix_run="another-run"))
        self.assertFalse(GEN.build_feed(self.fixture.root)["supportMatrix"]["gatedLatestRelease"])

    def test_partial_release_fails_closed(self):
        state = {artifact: "published" for artifact in ARTIFACTS}
        state["npm:@redact-secret/core"] = "unpublished"
        self.fixture.write_release(manifest("0.1.0-beta.10", state=state))
        with self.assertRaisesRegex(GEN.FeedError, "not recorded as published"):
            GEN.build_feed(self.fixture.root)

    def test_pypi_spelling_must_match_the_recorded_distribution(self):
        self.fixture.write_release(manifest("0.1.0-beta.10", pypi_file="redact_secret-0.1.0b9.tar.gz"))
        with self.assertRaisesRegex(GEN.FeedError, "source distribution"):
            GEN.build_feed(self.fixture.root)

    def test_record_without_release_evidence_is_not_final(self):
        value = manifest("0.1.0-beta.10")
        del value["release_evidence"]
        self.fixture.write_release(value)
        with self.assertRaisesRegex(GEN.FeedError, "not final"):
            GEN.build_feed(self.fixture.root)

    def test_check_fails_on_a_stale_feed(self):
        self.assertEqual(self.fixture.generate(), 0)
        changed = matrix()
        changed["families"][0]["status"] = "provisional"
        changed["distribution"] = {"stable": 0, "provisional": 2, "pending": 0, "unsupported": 1}
        self.fixture.write_matrix(changed)
        errors = GEN.check(self.fixture.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("out of date", errors[0])

    def test_check_fails_when_the_feed_is_missing(self):
        self.assertIn("missing", GEN.check(self.fixture.root)[0])

    def test_schema_rejects_free_text_and_unknown_fields(self):
        feed = GEN.build_feed(self.fixture.root)
        self.assertEqual(GEN.schema_errors(feed, self.fixture.root), [])
        bad = copy.deepcopy(feed)
        bad["supportMatrix"]["families"][0]["name"] = "x" * 200
        bad["release"]["notes"] = "anything"
        errors = GEN.schema_errors(bad, self.fixture.root)
        self.assertTrue(any("families[0].name" in error for error in errors), errors)
        self.assertTrue(any("unexpected key notes" in error for error in errors), errors)

    def test_generate_refuses_a_schema_invalid_feed(self):
        value = matrix()
        value["families"][0]["familyName"] = "a name; with = free text"
        self.fixture.write_matrix(value)
        self.assertEqual(self.fixture.generate(), 1)
        self.assertFalse((self.fixture.root / GEN.FEED_PATH).exists())


class RepositoryFeedTest(unittest.TestCase):
    def test_committed_feed_is_current_and_valid(self):
        self.assertEqual(GEN.check(ROOT), [])


if __name__ == "__main__":
    unittest.main()
