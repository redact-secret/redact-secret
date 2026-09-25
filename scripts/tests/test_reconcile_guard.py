from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "reconcile-guard.py"
SPEC = importlib.util.spec_from_file_location("reconcile_guard", SCRIPT)
assert SPEC and SPEC.loader
RECONCILE_GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECONCILE_GUARD
SPEC.loader.exec_module(RECONCILE_GUARD)


VERSION = "0.1.0-beta.1"


class ReconcileGuardTests(unittest.TestCase):
    """Exercises the guard against a real, deterministic git history.

    Main contains ancestor -> tip. A sibling branch carries a commit outside
    main's recovery history.
    No test creates a tag or publishes anything.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "reconcile-guard-tests@example.invalid")
        self._git("config", "user.name", "reconcile-guard-tests")
        self.base = self._commit("base.txt", "base")
        self.ancestor = self._commit("ancestor.txt", "ancestor")
        self.tip = self._commit("tip.txt", "tip")
        self._git("checkout", "-q", "-b", "off-main", self.base)
        self.off_candidate = self._commit("off.txt", "other candidate")
        self._git("checkout", "-q", "main")

    def _git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def _commit(self, filename: str, contents: str) -> str:
        (self.repo / filename).write_text(contents, encoding="utf-8")
        self._git("add", filename)
        self._git("commit", "-q", "-m", filename)
        result = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def _manifest_path(self, manifest: dict) -> Path:
        path = self.repo / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def _tags(self) -> list[str]:
        result = subprocess.run(
            ["git", "-C", str(self.repo), "tag"], check=True, capture_output=True, text=True
        )
        return [line for line in result.stdout.splitlines() if line]

    # -- fixture 1: an ancestor commit ------------------------------------

    def test_ancestor_commit_is_verified(self) -> None:
        manifest = self._manifest_path({"version": VERSION, "source_revision": self.ancestor})
        result = RECONCILE_GUARD.evaluate(
            RECONCILE_GUARD.load_manifest(manifest),
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.source_revision, self.ancestor)
        self.assertEqual(self._tags(), [])

    def test_ancestor_check_still_accepts_the_exact_tip(self) -> None:
        # Ancestor-of-candidate includes equal-to-tip, so this only widens the
        # repair window (F-08) -- it never narrows the case that already worked.
        manifest = self._manifest_path({"version": VERSION, "source_revision": self.tip})
        result = RECONCILE_GUARD.evaluate(
            RECONCILE_GUARD.load_manifest(manifest),
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
        )
        self.assertTrue(result.ok)
        self.assertEqual(self._tags(), [])

    # -- fixture 2: a non-ancestor commit ----------------------------------

    def test_non_ancestor_commit_is_rejected(self) -> None:
        manifest = self._manifest_path({"version": VERSION, "source_revision": self.off_candidate})
        result = RECONCILE_GUARD.evaluate(
            RECONCILE_GUARD.load_manifest(manifest),
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.source_revision)
        self.assertIn("not an ancestor", result.reason)
        self.assertEqual(self._tags(), [])

    # -- fixture 3: a missing record ---------------------------------------

    def test_missing_record_is_rejected(self) -> None:
        missing = self.repo / "does-not-exist.json"
        result = RECONCILE_GUARD.evaluate(
            RECONCILE_GUARD.load_manifest(missing),
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.source_revision)
        self.assertIn("no release manifest record", result.reason)
        self.assertEqual(self._tags(), [])

    # -- supporting behavior --------------------------------------------

    def test_mismatched_manifest_version_is_rejected(self) -> None:
        manifest = self._manifest_path({"version": "9.9.9", "source_revision": self.ancestor})
        result = RECONCILE_GUARD.evaluate(
            RECONCILE_GUARD.load_manifest(manifest),
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
        )
        self.assertFalse(result.ok)
        self.assertEqual(self._tags(), [])

    def test_source_commit_input_overrides_a_missing_manifest(self) -> None:
        result = RECONCILE_GUARD.evaluate(
            None,
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
            source_commit_override=self.ancestor,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.source_revision, self.ancestor)
        self.assertEqual(self._tags(), [])

    def test_source_commit_input_is_still_verified_as_an_ancestor(self) -> None:
        result = RECONCILE_GUARD.evaluate(
            None,
            repo=self.repo,
            candidate_ref="refs/heads/main",
            version=VERSION,
            source_commit_override=self.off_candidate,
        )
        self.assertFalse(result.ok)
        self.assertEqual(self._tags(), [])

    # -- CLI ---------------------------------------------------------------

    def test_cli_reports_ok_and_exits_zero(self) -> None:
        manifest = self._manifest_path({"version": VERSION, "source_revision": self.ancestor})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = RECONCILE_GUARD.main(
                [
                    "--manifest",
                    str(manifest),
                    "--repo",
                    str(self.repo),
                    "--candidate-ref",
                    self.tip,
                    "--version",
                    VERSION,
                ]
            )
        self.assertEqual(status, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["source_revision"], self.ancestor)
        self.assertEqual(self._tags(), [])

    def test_cli_reports_failure_and_exits_nonzero_for_a_missing_record(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = RECONCILE_GUARD.main(
                ["--repo", str(self.repo), "--candidate-ref", self.tip, "--version", VERSION]
            )
        self.assertEqual(status, 1)
        payload = json.loads(buffer.getvalue())
        self.assertFalse(payload["ok"])
        self.assertIsNone(payload["source_revision"])
        self.assertEqual(self._tags(), [])


if __name__ == "__main__":
    unittest.main()
