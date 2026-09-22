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
        index = (
            "# Audit archive\n\n"
            "[Beta.4](beta4-release-readiness-review.md)\n\n"
            "[#144](evidence/144/README.md)\n"
        )
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


if __name__ == "__main__":
    unittest.main()
