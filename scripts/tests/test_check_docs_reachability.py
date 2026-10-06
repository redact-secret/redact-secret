from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-docs-reachability.py"
SPEC = importlib.util.spec_from_file_location("check_docs_reachability", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class ReachabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_pages_reached_directly_and_transitively_pass(self) -> None:
        self.write("docs/README.md", "[a](a.md)\n")
        self.write("docs/a.md", "[b](sub/b.md#top)\n")
        self.write("docs/sub/b.md", "leaf\n")
        self.assertEqual(CHECK.validate(self.root, {}), [])

    def test_an_unlinked_page_fails(self) -> None:
        self.write("docs/README.md", "[a](a.md)\n")
        self.write("docs/a.md", "leaf\n")
        self.write("docs/specs/engine.md", "orphan\n")
        errors = CHECK.validate(self.root, {})
        self.assertEqual(len(errors), 1)
        self.assertIn("docs/specs/engine.md", errors[0])

    def test_a_prose_or_code_span_mention_is_not_a_link(self) -> None:
        self.write("docs/README.md", "See `docs/specs/engine.md` in prose.\n```\n[x](specs/engine.md)\n```\n")
        self.write("docs/specs/engine.md", "orphan\n")
        self.assertEqual(len(CHECK.validate(self.root, {})), 1)

    def test_an_exempt_page_is_allowed_but_a_stale_exemption_fails(self) -> None:
        self.write("docs/README.md", "[a](a.md)\n")
        self.write("docs/a.md", "leaf\n")
        self.write("docs/hidden.md", "off-index\n")
        self.assertEqual(CHECK.validate(self.root, {"docs/hidden.md": "reason"}), [])
        stale = CHECK.validate(self.root, {"docs/hidden.md": "r", "docs/a.md": "r"})
        self.assertEqual(len(stale), 1)
        self.assertIn("remove the exemption", stale[0])
        gone = CHECK.validate(self.root, {"docs/hidden.md": "r", "docs/gone.md": "r"})
        self.assertEqual(len(gone), 1)
        self.assertIn("not a tracked docs page", gone[0])

    def test_missing_index_fails(self) -> None:
        self.assertEqual(len(CHECK.validate(self.root, {})), 1)


class TemporaryAuditUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name: str, text: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def unit(self, name: str, status: str, retire: str) -> None:
        self.write(
            name,
            "---\nowner: #1266\nreviewed_source: "
            + "a" * 40
            + "\nstatus: {status}\nretire_on: {retire}\n---\n\n# Review\n".format(status=status, retire=retire),
        )

    def test_a_temporary_unit_page_needs_no_navigation_link(self) -> None:
        self.write("docs/README.md", "index\n")
        self.unit("docs/audits/wip.md", "in-progress", "before-qualification")
        self.unit("docs/audits/evidence/3/README.md", "final", "before-qualification")
        self.write("docs/audits/evidence/3/notes.md", "extra page\n")
        self.assertEqual(CHECK.validate(self.root, {}), [])

    def test_a_retained_unit_page_must_be_reachable(self) -> None:
        self.write("docs/README.md", "index\n")
        self.unit("docs/audits/candidate.md", "retained", "after-release:0.1.0-beta.14")
        self.assertEqual(len(CHECK.validate(self.root, {})), 1)

    def test_a_page_outside_the_audit_tree_is_unaffected(self) -> None:
        self.write("docs/README.md", "index\n")
        self.write("docs/specs/engine.md", "orphan\n")
        self.assertEqual(len(CHECK.validate(self.root, {})), 1)


if __name__ == "__main__":
    unittest.main()
