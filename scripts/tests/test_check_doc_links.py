from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-doc-links.py"
SPEC = importlib.util.spec_from_file_location("check_doc_links", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class Repository:
    """A minimal tracked-file set for `validate`, without a real `git` repo."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: list[str] = []

    def write(self, relative: str, content: str) -> str:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.files.append(relative)
        return relative


class CheckDocLinksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Repository(Path(self.directory.name))

    def validate(self) -> list[str]:
        return CHECK.validate(self.repo.root, self.repo.files)

    def assertOneError(self, fragment: str) -> None:
        errors = self.validate()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(fragment, errors[0])

    def test_a_valid_relative_link_passes(self) -> None:
        self.repo.write("docs/target.md", "# Target\n")
        self.repo.write("docs/source.md", "[link](target.md)\n")
        self.assertEqual(self.validate(), [])

    def test_a_deliberately_broken_link_target_is_rejected(self) -> None:
        self.repo.write("docs/source.md", "[link](does-not-exist.md)\n")
        self.assertOneError("broken relative link target 'does-not-exist.md'")

    def test_wrong_up_level_depth_is_rejected(self) -> None:
        self.repo.write("docs/audits/README.md", "# Audit archive\n")
        self.repo.write("docs/audits/evidence/441/README.md", "[archive](../README.md)\n")
        self.assertOneError("broken relative link target '../README.md'")

    def test_correct_up_level_depth_passes(self) -> None:
        self.repo.write("docs/audits/README.md", "# Audit archive\n")
        self.repo.write("docs/audits/evidence/441/README.md", "[archive](../../README.md)\n")
        self.assertEqual(self.validate(), [])

    def test_a_valid_anchor_passes(self) -> None:
        self.repo.write("docs/target.md", "# My Heading\n")
        self.repo.write("docs/source.md", "[link](target.md#my-heading)\n")
        self.assertEqual(self.validate(), [])

    def test_a_deliberately_broken_anchor_is_rejected(self) -> None:
        self.repo.write("docs/target.md", "# My Heading\n")
        self.repo.write("docs/source.md", "[link](target.md#not-a-real-heading)\n")
        self.assertOneError("broken anchor '#not-a-real-heading'")

    def test_github_slug_rules_strip_punctuation_without_collapsing_spaces(self) -> None:
        # Regression for issue #593: "Closed validator enum (`PostCheck`)"
        # slugs to "closed-validator-enum-postcheck", not "...-post-check".
        self.repo.write("docs/target.md", "### Closed validator enum (`PostCheck`)\n")
        self.repo.write("docs/source.md", "[link](target.md#closed-validator-enum-postcheck)\n")
        self.assertEqual(self.validate(), [])

    def test_github_slug_rules_turn_each_space_into_its_own_hyphen(self) -> None:
        # Regression for issue #593: "Current application — 2026-09-12 (#181, #182)"
        # slugs to "current-application--2026-09-12-181-182" (double hyphen
        # where the em dash's surrounding spaces both survive).
        self.repo.write("docs/target.md", "## Current application — 2026-09-12 (#181, #182)\n")
        self.repo.write(
            "docs/source.md",
            "[link](target.md#current-application--2026-09-12-181-182)\n",
        )
        self.assertEqual(self.validate(), [])

    def test_a_repeated_heading_gets_a_numeric_suffix(self) -> None:
        self.repo.write("docs/target.md", "## Notes\n\ntext\n\n## Notes\n")
        self.repo.write("docs/source.md", "[link](target.md#notes-1)\n")
        self.assertEqual(self.validate(), [])

    def test_a_same_file_anchor_is_checked_against_its_own_headings(self) -> None:
        self.repo.write("docs/source.md", "## Section\n\n[back](#section)\n")
        self.assertEqual(self.validate(), [])

    def test_a_same_file_broken_anchor_is_rejected(self) -> None:
        self.repo.write("docs/source.md", "## Section\n\n[back](#missing)\n")
        self.assertOneError("broken anchor '#missing'")

    def test_a_link_inside_a_fenced_code_block_is_not_checked(self) -> None:
        self.repo.write(
            "docs/source.md",
            "```md\n[example](nowhere.md)\n```\n",
        )
        self.assertEqual(self.validate(), [])

    def test_a_link_inside_an_inline_code_span_is_not_checked(self) -> None:
        self.repo.write("docs/source.md", "Write `[text](nowhere.md)` like this.\n")
        self.assertEqual(self.validate(), [])

    def test_a_heading_inside_a_fenced_code_block_does_not_create_a_real_anchor(self) -> None:
        self.repo.write("docs/target.md", "```bash\n# not a heading\n```\n")
        self.repo.write("docs/source.md", "[link](target.md#not-a-heading)\n")
        self.assertOneError("broken anchor '#not-a-heading'")

    def test_an_external_link_is_never_checked(self) -> None:
        self.repo.write("docs/source.md", "[external](https://example.com/nowhere)\n")
        self.assertEqual(self.validate(), [])

    def test_a_leading_slash_link_resolves_from_the_repository_root(self) -> None:
        self.repo.write("CHANGELOG.md", "# Changelog\n")
        self.repo.write("docs/guides/nested.md", "[changelog](/CHANGELOG.md)\n")
        self.assertEqual(self.validate(), [])

    def test_a_directory_link_is_valid_without_an_anchor_check(self) -> None:
        self.repo.write("docs/releases/status.md", "# Status\n")
        self.repo.write("docs/README.md", "[releases](releases/)\n")
        self.assertEqual(self.validate(), [])

    def test_an_image_link_is_checked_the_same_way(self) -> None:
        self.repo.write("docs/source.md", "![diagram](missing.png)\n")
        self.assertOneError("broken relative link target 'missing.png'")


if __name__ == "__main__":
    unittest.main()
