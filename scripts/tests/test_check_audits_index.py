from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-audits-index.py"
SPEC = importlib.util.spec_from_file_location("check_audits_index", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class CheckAuditsIndexTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.audits_dir = Path(self.directory.name)

    def write(self, relative: str, content: str = "") -> None:
        path = self.audits_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_a_fully_indexed_tree_passes(self) -> None:
        self.write("beta4-release-readiness-review.md", "# Beta.4\n")
        self.write("evidence/144/README.md", "# 144\n")
        index = "# Audit archive\n\n[Beta.4](beta4-release-readiness-review.md)\n\n[#144](evidence/144/README.md)\n"
        self.assertEqual(CHECK.validate(self.audits_dir, index), [])

    def test_an_unindexed_standalone_doc_is_rejected(self) -> None:
        self.write("ci-maintenance-review.md", "# CI\n")
        errors = CHECK.validate(self.audits_dir, "# Audit archive\n")
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("docs/audits/ci-maintenance-review.md is not indexed", errors[0])

    def test_an_unindexed_evidence_unit_is_rejected(self) -> None:
        self.write("evidence/462/README.md", "# 462\n")
        errors = CHECK.validate(self.audits_dir, "# Audit archive\n")
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("docs/audits/evidence/462/ is not indexed", errors[0])

    def test_readme_itself_is_never_required_to_index_itself(self) -> None:
        self.write("README.md", "# Audit archive\n")
        self.assertEqual(CHECK.validate(self.audits_dir, "# Audit archive\n"), [])

    def test_a_bare_issue_number_mention_does_not_count_as_indexed(self) -> None:
        self.write("evidence/145/README.md", "# 145\n")
        index = "# Audit archive\n\nSee #145 for background, but no link.\n"
        errors = CHECK.validate(self.audits_dir, index)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("docs/audits/evidence/145/ is not indexed", errors[0])

    def test_a_link_to_a_file_inside_the_evidence_folder_counts_as_indexed(self) -> None:
        self.write("evidence/462/README.md", "# 462\n")
        index = "# Audit archive\n\n[462](evidence/462/README.md)\n"
        self.assertEqual(CHECK.validate(self.audits_dir, index), [])

    def test_an_evidence_unit_with_a_non_dash_slug_name_is_supported(self) -> None:
        self.write("evidence/beta2-final-review/reproduce.mjs", "// ok\n")
        index = "# Audit archive\n\n[beta.2 evidence](evidence/beta2-final-review/reproduce.mjs)\n"
        self.assertEqual(CHECK.validate(self.audits_dir, index), [])


class TemporaryUnitIndexTest(unittest.TestCase):
    """A declared temporary unit is tracked by the lifecycle check, not the index (#1266)."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.audits_dir = self.root / "docs" / "audits"

    def write(self, relative: str, status: str, retire: str) -> None:
        path = self.audits_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "---\nowner: #1266\nreviewed_source: "
            + "a" * 40
            + "\nstatus: {status}\nretire_on: {retire}\n---\n\n# Review\n".format(status=status, retire=retire),
            encoding="utf-8",
        )

    def test_in_progress_and_final_units_need_no_index_row(self) -> None:
        self.write("wip.md", "in-progress", "before-qualification")
        self.write("evidence/5/README.md", "final", "before-qualification")
        self.assertEqual(CHECK.validate(self.audits_dir, "# Index\n"), [])

    def test_deferred_and_retained_units_must_be_indexed(self) -> None:
        self.write("backlog.md", "deferred", "after-issue:#9")
        self.write("candidate.md", "retained", "after-release:0.1.0-beta.14")
        errors = CHECK.validate(self.audits_dir, "# Index\n")
        self.assertEqual(len(errors), 2, errors)
        self.assertEqual(CHECK.validate(self.audits_dir, "[a](backlog.md) [b](candidate.md)\n"), [])

    def test_a_unit_without_a_block_must_still_be_indexed(self) -> None:
        path = self.audits_dir / "old.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Old\n", encoding="utf-8")
        self.assertEqual(len(CHECK.validate(self.audits_dir, "# Index\n")), 1)


if __name__ == "__main__":
    unittest.main()
