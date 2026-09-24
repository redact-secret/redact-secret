from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-benchmark-pins.py"
SPEC = importlib.util.spec_from_file_location("check_benchmark_pins", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


MANIFEST = {
    "schemaVersion": 1,
    "revision": "r" * 40,
    "pins": {
        "sourceRevision": "a" * 40,
        "redactSecretRevision": "a" * 40,
        "redactSecretVersion": "0.1.0-beta.5",
        "packageVersion": "0.1.0-beta.5",
    },
    "corpusHashes": {"reference-syntax": "1" * 64, "detector-coverage": "2" * 64},
    "fixtureIds": ["reference-syntax--windows-env", "detector-coverage--generic-token-api-key-quoted"],
}


def ledger_with(*records: dict) -> dict:
    return {"schemaVersion": 1, "lifecycleAuthority": "https://example.invalid", "records": list(records)}


def gates(*, productConformance: str = "pending", benchmarkRevalidation: str = "pending") -> dict:
    return {
        "productConformance": {"status": productConformance, "evidence": []},
        "benchmarkRevalidation": {"status": benchmarkRevalidation, "evidence": []},
    }


def record(**overrides) -> dict:
    base = {
        "id": "benchmark-gap-1",
        "benchmarkFixtureIds": ["reference-syntax--windows-env"],
        "corpusHashes": ["1" * 64],
    }
    base.update(overrides)
    return base


# -- checks 1 and 2: dangling-reference reconciliation (pure, offline) -----


class ReconciliationTests(unittest.TestCase):
    def test_passes_when_every_reference_resolves(self) -> None:
        ledger = ledger_with(record())
        self.assertEqual(CHECK.check_reconciliation(MANIFEST, ledger), [])

    def test_flags_a_corpus_hash_not_in_the_pinned_revision(self) -> None:
        ledger = ledger_with(record(corpusHashes=["9" * 64]))
        errors = CHECK.check_reconciliation(MANIFEST, ledger)
        self.assertEqual(len(errors), 1)
        self.assertIn("9" * 64, errors[0])
        self.assertIn("corpusHashes", errors[0])

    def test_flags_a_dangling_fixture_id(self) -> None:
        ledger = ledger_with(record(benchmarkFixtureIds=["does-not-exist--anywhere"]))
        errors = CHECK.check_reconciliation(MANIFEST, ledger)
        self.assertEqual(len(errors), 1)
        self.assertIn("does-not-exist--anywhere", errors[0])
        self.assertIn("benchmarkFixtureIds", errors[0])

    def test_reports_every_record_independently(self) -> None:
        ledger = ledger_with(
            record(id="benchmark-gap-1", corpusHashes=["9" * 64]),
            record(id="benchmark-gap-2", benchmarkFixtureIds=["missing--fixture"]),
        )
        errors = CHECK.check_reconciliation(MANIFEST, ledger)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("benchmark-gap-1" in e for e in errors))
        self.assertTrue(any("benchmark-gap-2" in e for e in errors))

    def test_freezes_corpus_hashes_once_benchmark_revalidation_passed(self) -> None:
        """A closed record's corpusHashes are the identity of the corpus that
        was measured; the upstream digest changes on every corpus edit, so
        re-checking it against the current pin would fail forever (#637).
        The record is anchored by its benchmarkCommit (check 3) instead."""
        ledger = ledger_with(record(corpusHashes=["9" * 64], gates=gates(benchmarkRevalidation="passed")))
        self.assertEqual(CHECK.check_reconciliation(MANIFEST, ledger), [])

    def test_still_flags_a_stale_corpus_hash_while_benchmark_revalidation_is_pending(self) -> None:
        ledger = ledger_with(record(corpusHashes=["9" * 64], gates=gates(benchmarkRevalidation="pending")))
        errors = CHECK.check_reconciliation(MANIFEST, ledger)
        self.assertEqual(len(errors), 1)
        self.assertIn("re-pin", errors[0])

    def test_still_flags_a_dangling_fixture_id_for_a_closed_record(self) -> None:
        """Fixture ids are stable identities, not content digests: they stay checked."""
        ledger = ledger_with(
            record(benchmarkFixtureIds=["gone--fixture"], gates=gates(benchmarkRevalidation="passed"))
        )
        errors = CHECK.check_reconciliation(MANIFEST, ledger)
        self.assertEqual(len(errors), 1)
        self.assertIn("gone--fixture", errors[0])


class CollectBenchmarkCommitsTests(unittest.TestCase):
    def test_deduplicates_and_sorts(self) -> None:
        ledger = ledger_with(
            record(id="a", benchmarkCommit="b" * 40),
            record(id="b", benchmarkCommit="a" * 40),
            record(id="c", benchmarkCommit="b" * 40),
            record(id="d"),
        )
        self.assertEqual(CHECK.collect_benchmark_commits(ledger), ["a" * 40, "b" * 40])


class ProductLocalRefTests(unittest.TestCase):
    def test_resolves_ancestry_against_the_origin_tracking_branch(self) -> None:
        """actions/checkout (fetch-depth: 0, pull_request trigger) fetches every
        branch into refs/remotes/origin/* and checks out a detached PR merge
        ref -- it never creates a local `main` branch. Resolving ancestry
        against bare `main` silently and incorrectly reports every PR's
        pins.sourceRevision as not-an-ancestor."""
        self.assertEqual(CHECK.PRODUCT_LOCAL_REF, "origin/main")


# -- checks 3 and 4: ancestry, given pre-computed facts (pure) -------------


class AncestryTests(unittest.TestCase):
    def test_passes_when_every_fact_resolves_clean(self) -> None:
        ledger = ledger_with(record(benchmarkCommit="c" * 40))
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={"c" * 40: True},
        )
        self.assertEqual(findings.errors, [])
        self.assertEqual(findings.warnings, [])

    def test_flags_a_source_revision_that_is_not_an_ancestor(self) -> None:
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(),
            source_revision_is_ancestor=False,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(len(findings.errors), 1)
        self.assertIn("is not an ancestor", findings.errors[0])
        self.assertEqual(findings.warnings, [])

    def test_flags_detectors_changed_since_source_revision_as_a_warning_not_an_error(self) -> None:
        """Non-blocking: the product repo cannot itself refresh the benchmarks
        repo's snapshot, so this must not fail the build (see #427)."""
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(),
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=True,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(findings.errors, [])
        self.assertEqual(len(findings.warnings), 1)
        self.assertIn("crates/secret-scan-core/src/detectors", findings.warnings[0])

    def test_flags_a_benchmark_commit_that_is_not_an_ancestor(self) -> None:
        ledger = ledger_with(record(benchmarkCommit="d" * 40))
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={"d" * 40: False},
        )
        self.assertEqual(len(findings.errors), 1)
        self.assertIn("d" * 40, findings.errors[0])
        self.assertIn("benchmark-gap-1", findings.errors[0])

    def test_treats_an_unrecorded_benchmark_commit_as_failing(self) -> None:
        """Fail closed: absence of proof is not proof of ancestry."""
        ledger = ledger_with(record(benchmarkCommit="e" * 40))
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(len(findings.errors), 1)

    def test_ignores_records_without_a_benchmark_commit(self) -> None:
        findings = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(record()),
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(findings.errors, [])


# -- check 7: pinned version vs this repository's product version (pure) ---


class SemverTests(unittest.TestCase):
    def test_orders_pre_releases_numerically_not_lexically(self) -> None:
        self.assertEqual(CHECK.compare_semver("0.1.0-beta.10", "0.1.0-beta.9"), 1)
        self.assertEqual(CHECK.compare_semver("0.1.0-beta.6", "0.1.0-beta.6"), 0)
        self.assertEqual(CHECK.compare_semver("0.1.0-beta.3", "0.1.0-beta.6"), -1)

    def test_a_release_sorts_after_its_pre_releases_and_before_the_next_core(self) -> None:
        self.assertEqual(CHECK.compare_semver("0.1.0", "0.1.0-rc.1"), 1)
        self.assertEqual(CHECK.compare_semver("0.1.0-rc.1", "0.1.0"), -1)
        self.assertEqual(CHECK.compare_semver("0.1.0", "0.1.1-beta.1"), -1)

    def test_alphanumeric_identifiers_sort_after_numeric_and_prefixes_sort_first(self) -> None:
        self.assertEqual(CHECK.compare_semver("1.0.0-alpha", "1.0.0-alpha.1"), -1)
        self.assertEqual(CHECK.compare_semver("1.0.0-1", "1.0.0-alpha"), -1)
        self.assertEqual(CHECK.compare_semver("1.0.0-alpha.beta", "1.0.0-beta"), -1)

    def test_rejects_a_non_semver_string(self) -> None:
        with self.assertRaises(ValueError):
            CHECK.parse_semver("v0.1.0")


class PinnedVersionTests(unittest.TestCase):
    def test_silent_when_the_pin_matches_the_product_version(self) -> None:
        self.assertEqual(CHECK.check_pinned_version(MANIFEST, "0.1.0-beta.5"), [])

    def test_silent_when_the_pin_is_newer_than_this_checkout(self) -> None:
        self.assertEqual(CHECK.check_pinned_version(MANIFEST, "0.1.0-beta.4"), [])

    def test_warns_when_the_pin_is_older_than_the_product_version(self) -> None:
        """#637: the vendored manifest carried 0.1.0-beta.3 while main was at
        0.1.0-beta.6 and nothing said so. A warning, not an error: an rc
        branch bumps package.json before the benchmarks repo can pin it."""
        warnings = CHECK.check_pinned_version(MANIFEST, "0.1.0-beta.6")
        self.assertEqual(len(warnings), 1)
        self.assertIn("0.1.0-beta.5", warnings[0])
        self.assertIn("0.1.0-beta.6", warnings[0])
        self.assertIn("benchmark-pins:sync", warnings[0])

    def test_warns_instead_of_crashing_on_an_unparseable_version(self) -> None:
        manifest = {**MANIFEST, "pins": {**MANIFEST["pins"], "redactSecretVersion": "beta"}}
        warnings = CHECK.check_pinned_version(manifest, "0.1.0-beta.6")
        self.assertEqual(len(warnings), 1)
        self.assertIn("cannot compare", warnings[0])

    def test_warns_when_the_pin_has_no_version(self) -> None:
        manifest = {**MANIFEST, "pins": {}}
        warnings = CHECK.check_pinned_version(manifest, "0.1.0-beta.6")
        self.assertEqual(len(warnings), 1)


# -- check 5: vendored support-matrix-schema.json drift (pure) -------------


class SchemaDriftTests(unittest.TestCase):
    def test_passes_when_identical(self) -> None:
        self.assertEqual(CHECK.check_schema_drift("{}\n", "{}\n", live_source="x@y:z"), [])

    def test_flags_a_drifted_copy(self) -> None:
        errors = CHECK.check_schema_drift('{"a": 1}\n', '{"a": 2}\n', live_source="redact-secret-benchmarks@r:schemas/support-matrix-v1.json")
        self.assertEqual(len(errors), 1)
        self.assertIn(str(CHECK.SUPPORT_MATRIX_SCHEMA_PATH), errors[0])
        self.assertIn("redact-secret-benchmarks@r:schemas/support-matrix-v1.json", errors[0])


# -- check 6: vendored pin-manifest.json provenance, given facts (pure) ----


def provenance(**overrides) -> dict:
    facts = {
        "revision_is_ancestor": True,
        "revision_has_manifest": True,
        "local_content": '{"revision": "r"}\n',
        "live_content": '{"revision": "r"}\n',
        "live_source": "redact-secret-benchmarks@main:benchmarks/pin-manifest.json",
    }
    facts.update(overrides)
    return facts


class ManifestProvenanceTests(unittest.TestCase):
    def test_passes_when_the_revision_is_real_carries_the_manifest_and_content_matches(self) -> None:
        self.assertEqual(CHECK.check_manifest_provenance(MANIFEST, **provenance()), [])

    def test_flags_a_revision_that_is_not_in_the_benchmarks_history(self) -> None:
        errors = CHECK.check_manifest_provenance(MANIFEST, **provenance(revision_is_ancestor=False))
        self.assertEqual(len(errors), 1)
        self.assertIn("r" * 40, errors[0])
        self.assertIn("not a recorded ancestor", errors[0])

    def test_does_not_also_report_a_missing_file_for_a_revision_outside_the_history(self) -> None:
        """A commit outside main has no tree to look in; one error, not two."""
        errors = CHECK.check_manifest_provenance(
            MANIFEST, **provenance(revision_is_ancestor=False, revision_has_manifest=False)
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("not a recorded ancestor", errors[0])

    def test_flags_a_revision_that_predates_the_manifest(self) -> None:
        """#637's `f1d4fac`: a real benchmarks commit at which
        benchmarks/pin-manifest.json did not exist yet."""
        errors = CHECK.check_manifest_provenance(MANIFEST, **provenance(revision_has_manifest=False))
        self.assertEqual(len(errors), 1)
        self.assertIn("does not contain benchmarks/pin-manifest.json", errors[0])

    def test_flags_vendored_content_that_drifted_from_the_benchmarks_copy(self) -> None:
        errors = CHECK.check_manifest_provenance(MANIFEST, **provenance(live_content='{"revision": "s"}\n'))
        self.assertEqual(len(errors), 1)
        self.assertIn(str(CHECK.MANIFEST_PATH), errors[0])
        self.assertIn("redact-secret-benchmarks@main:benchmarks/pin-manifest.json", errors[0])
        self.assertIn("benchmark-pins:sync", errors[0])

    def test_reports_provenance_and_drift_independently(self) -> None:
        errors = CHECK.check_manifest_provenance(
            MANIFEST, **provenance(revision_has_manifest=False, live_content="different\n")
        )
        self.assertEqual(len(errors), 2)

    def test_both_vendored_files_are_under_the_same_byte_identity_rule(self) -> None:
        """#637 acceptance: the schema (check 5) and the manifest (check 6c)
        share one drift rule, and `--sync` rewrites exactly those files."""
        self.assertEqual(
            [str(local) for local, _, _ in CHECK.VENDORED_FILES],
            [str(CHECK.MANIFEST_PATH), str(CHECK.SUPPORT_MATRIX_SCHEMA_PATH)],
        )
        drift = CHECK.check_vendored_file_drift(CHECK.MANIFEST_PATH, "a", "b", live_source="x")
        self.assertEqual(len(drift), 1)
        self.assertEqual(CHECK.check_schema_drift("a", "b", live_source="x")[0].split(" has drifted")[0], str(CHECK.SUPPORT_MATRIX_SCHEMA_PATH))


class SyncVendoredFilesTests(unittest.TestCase):
    def test_rewrites_every_vendored_copy_from_its_declared_ref(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "benchmarks").mkdir()
        (root / CHECK.MANIFEST_PATH).write_text("stale\n", encoding="utf-8")
        requested: list[tuple[str, str, str]] = []

        def fetch(repo: str, ref: str, path: str) -> str:
            requested.append((repo, ref, path))
            return f"fresh {path}\n"

        written = CHECK.sync_vendored_files(root, fetch)
        self.assertEqual(
            written,
            [
                (CHECK.MANIFEST_PATH, CHECK.BENCHMARKS_BRANCH),
                (CHECK.SUPPORT_MATRIX_SCHEMA_PATH, CHECK.BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF),
            ],
        )
        self.assertEqual(
            requested,
            [
                (CHECK.BENCHMARKS_REPO, CHECK.BENCHMARKS_BRANCH, CHECK.BENCHMARKS_MANIFEST_PATH),
                (
                    CHECK.BENCHMARKS_REPO,
                    CHECK.BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF,
                    CHECK.BENCHMARKS_SUPPORT_MATRIX_SCHEMA_PATH,
                ),
            ],
        )
        self.assertEqual((root / CHECK.MANIFEST_PATH).read_text(encoding="utf-8"), "fresh benchmarks/pin-manifest.json\n")
        self.assertEqual(
            (root / CHECK.SUPPORT_MATRIX_SCHEMA_PATH).read_text(encoding="utf-8"),
            "fresh schemas/support-matrix-v1.json\n",
        )


# -- local git ancestry helpers, against a real, deterministic history -----


class LocalGitHelperTests(unittest.TestCase):
    """Mirrors test_reconcile_guard.py's real-git-history fixture."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "check-benchmark-pins-tests@example.invalid")
        self._git("config", "user.name", "check-benchmark-pins-tests")
        self.source_revision = self._commit("source.txt", "source", touch_detectors=True)
        self.unrelated = self._commit("unrelated.txt", "unrelated")
        self._git("checkout", "-q", "-b", "off-main")
        self.off_main = self._commit("off.txt", "off main")
        self._git("checkout", "-q", "main")

    def _git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def _commit(self, filename: str, contents: str, *, touch_detectors: bool = False) -> str:
        if touch_detectors:
            detectors = self.repo / CHECK.DETECTORS_PATH
            detectors.mkdir(parents=True, exist_ok=True)
            (detectors / "aws.rs").write_text(contents, encoding="utf-8")
            self._git("add", str((detectors / "aws.rs").relative_to(self.repo)))
        (self.repo / filename).write_text(contents, encoding="utf-8")
        self._git("add", filename)
        self._git("commit", "-q", "-m", filename)
        result = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    def test_local_is_ancestor_true_for_an_ancestor_commit(self) -> None:
        self.assertTrue(CHECK.local_is_ancestor(self.repo, self.source_revision, "main"))

    def test_local_is_ancestor_false_for_a_commit_off_main(self) -> None:
        self.assertFalse(CHECK.local_is_ancestor(self.repo, self.off_main, "main"))

    def test_local_path_changed_since_is_false_when_untouched(self) -> None:
        # `unrelated.txt` never touches DETECTORS_PATH after source_revision.
        self.assertFalse(
            CHECK.local_path_changed_since(self.repo, self.source_revision, "main", CHECK.DETECTORS_PATH)
        )

    def test_local_path_changed_since_is_true_when_touched_again(self) -> None:
        self._commit("second-detectors-touch.rs", "changed", touch_detectors=True)
        self.assertTrue(
            CHECK.local_path_changed_since(self.repo, self.source_revision, "main", CHECK.DETECTORS_PATH)
        )


if __name__ == "__main__":
    unittest.main()
