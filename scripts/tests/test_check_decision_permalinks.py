from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-decision-permalinks.py"
SPEC = importlib.util.spec_from_file_location("check_decision_permalinks", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def record(full_record: str | None) -> str:
    frontmatter = (
        "decision_id: decision-example\n"
        "status: accepted\n"
        "scope: workspace\n"
        "title: Example\n"
        "spec: engine\n"
    )
    if full_record is not None:
        frontmatter += f"full_record: {full_record}\n"
    return f"---\n{frontmatter}---\n\n# Example\n\n## Decision\n\nExample.\n"


class CollectPermalinkCommitsTests(unittest.TestCase):
    """Pure, offline: parsing full_record shas out of ADR frontmatter."""

    def test_no_full_record_field_yields_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            decision_dir = Path(temp) / "docs" / "decisions"
            decision_dir.mkdir(parents=True)
            (decision_dir / "2026-09-09-example.md").write_text(record(None), encoding="utf-8")
            self.assertEqual(CHECK.collect_permalink_commits(decision_dir), {})

    def test_full_record_field_is_collected(self) -> None:
        sha = "a" * 40
        with tempfile.TemporaryDirectory() as temp:
            decision_dir = Path(temp) / "docs" / "decisions"
            decision_dir.mkdir(parents=True)
            record_path = decision_dir / "2026-09-09-example.md"
            record_path.write_text(
                record(f"https://github.com/redact-secret/redact-secret/blob/{sha}/docs/decisions/x.md"),
                encoding="utf-8",
            )
            self.assertEqual(CHECK.collect_permalink_commits(decision_dir), {sha: [record_path]})

    def test_missing_decisions_directory_yields_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(CHECK.collect_permalink_commits(Path(temp) / "docs" / "decisions"), {})


class GitHistoryTests(unittest.TestCase):
    """Exercises the ancestry check against a real, deterministic git history."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "check-decision-permalinks-tests@example.invalid")
        self._git("config", "user.name", "check-decision-permalinks-tests")
        self.commit = self._commit("seed.txt")

    def _git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def _commit(self, filename: str) -> str:
        (self.repo / filename).write_text("seed\n", encoding="utf-8")
        self._git("add", filename)
        self._git("commit", "-q", "-m", filename)
        result = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        )
        return result.stdout.strip()

    def add_record(self, name: str, full_record: str) -> None:
        decision_dir = self.repo / "docs" / "decisions"
        decision_dir.mkdir(parents=True, exist_ok=True)
        (decision_dir / name).write_text(record(full_record), encoding="utf-8")

    def test_a_real_local_commit_passes(self) -> None:
        self.add_record(
            "2026-09-09-example.md",
            f"https://github.com/redact-secret/redact-secret/blob/{self.commit}/docs/decisions/x.md",
        )
        self.assertEqual(CHECK.validate(self.repo), [])

    def test_a_commit_not_in_local_history_is_rejected(self) -> None:
        missing = "f" * 40
        self.add_record(
            "2026-09-09-example.md",
            f"https://github.com/redact-secret/redact-secret/blob/{missing}/docs/decisions/x.md",
        )
        errors = CHECK.validate(self.repo)
        self.assertEqual(len(errors), 1)
        self.assertIn(missing, errors[0])
        self.assertIn("not reachable in local history", errors[0])

    def test_no_permalinks_is_a_clean_no_op(self) -> None:
        self.add_record("2026-09-09-example.md", None)  # type: ignore[arg-type]
        self.assertEqual(CHECK.validate(self.repo), [])


if __name__ == "__main__":
    unittest.main()
