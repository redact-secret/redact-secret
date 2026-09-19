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


class CollectBenchmarkCommitsTests(unittest.TestCase):
    def test_deduplicates_and_sorts(self) -> None:
        ledger = ledger_with(
            record(id="a", benchmarkCommit="b" * 40),
            record(id="b", benchmarkCommit="a" * 40),
            record(id="c", benchmarkCommit="b" * 40),
            record(id="d"),
        )
        self.assertEqual(CHECK.collect_benchmark_commits(ledger), ["a" * 40, "b" * 40])


# -- checks 3 and 4: ancestry, given pre-computed facts (pure) -------------


class AncestryTests(unittest.TestCase):
    def test_passes_when_every_fact_resolves_clean(self) -> None:
        ledger = ledger_with(record(benchmarkCommit="c" * 40))
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={"c" * 40: True},
        )
        self.assertEqual(errors, [])

    def test_flags_a_source_revision_that_is_not_an_ancestor(self) -> None:
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(),
            source_revision_is_ancestor=False,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("is not an ancestor", errors[0])

    def test_flags_detectors_changed_since_source_revision_as_a_failure(self) -> None:
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(),
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=True,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("crates/secret-scan-core/src/detectors", errors[0])

    def test_flags_a_benchmark_commit_that_is_not_an_ancestor(self) -> None:
        ledger = ledger_with(record(benchmarkCommit="d" * 40))
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={"d" * 40: False},
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("d" * 40, errors[0])
        self.assertIn("benchmark-gap-1", errors[0])

    def test_treats_an_unrecorded_benchmark_commit_as_failing(self) -> None:
        """Fail closed: absence of proof is not proof of ancestry."""
        ledger = ledger_with(record(benchmarkCommit="e" * 40))
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger,
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(len(errors), 1)

    def test_ignores_records_without_a_benchmark_commit(self) -> None:
        errors = CHECK.check_ancestry(
            MANIFEST,
            ledger_with(record()),
            source_revision_is_ancestor=True,
            detectors_changed_since_source_revision=False,
            benchmark_commit_is_ancestor={},
        )
        self.assertEqual(errors, [])


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
