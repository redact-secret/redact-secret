from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "generate-decisions-index.py"
SPEC = importlib.util.spec_from_file_location("generate_decisions_index", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)


class DecisionsIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "docs" / "decisions").mkdir(parents=True)

    def record(self, name: str, spec: str, title: str) -> None:
        (self.root / "docs" / "decisions" / name).write_text(
            f"---\ndecision_id: decision-{name[:-3]}\nstatus: accepted\nscope: workspace\nspec: {spec}\n---\n\n# {title}\n\n## Decision\n\nx\n",
            encoding="utf-8",
        )

    def test_records_are_grouped_by_spec_in_filename_order_with_h1_titles(self) -> None:
        self.record("2026-09-02-b.md", "engine", "Second engine")
        self.record("2026-09-01-a.md", "engine", "First engine")
        self.record("2026-09-03-c.md", "distribution", "Ship it")
        text = GEN.render(self.root)
        self.assertLess(text.index("## Engine"), text.index("## Distribution"))
        self.assertLess(text.index("[First engine](2026-09-01-a.md)"), text.index("[Second engine](2026-09-02-b.md)"))
        self.assertLess(text.index("## Distribution"), text.index("[Ship it](2026-09-03-c.md)"))

    def test_check_passes_when_generated_and_fails_on_hand_edit(self) -> None:
        self.record("2026-09-01-a.md", "engine", "First engine")
        self.assertEqual(GEN.main([str(self.root)]), 0)
        self.assertEqual(GEN.main([str(self.root), "--check"]), 0)
        index = self.root / "docs" / "decisions" / "DECISIONS.md"
        index.write_text(index.read_text(encoding="utf-8") + "- [Rogue](rogue.md)\n", encoding="utf-8")
        self.assertEqual(GEN.main([str(self.root), "--check"]), 1)

    def test_check_fails_when_a_record_changes_spec_without_regeneration(self) -> None:
        self.record("2026-09-01-a.md", "engine", "First engine")
        GEN.main([str(self.root)])
        self.record("2026-09-01-a.md", "distribution", "First engine")
        self.assertEqual(GEN.main([str(self.root), "--check"]), 1)

    def test_alias_index_maps_a_folded_id_to_its_survivor_and_permalink(self) -> None:
        sha = "b" * 40
        (self.root / "docs" / "decisions" / "2026-09-01-a.md").write_text(
            "---\ndecision_id: decision-a\nstatus: accepted\nscope: workspace\nspec: engine\naliases: decision-old\n---\n\n# Survivor\n\n"
            f"| `decision-old` | [full record](https://github.com/redact-secret/redact-secret/blob/{sha}/docs/decisions/old.md) |\n",
            encoding="utf-8",
        )
        text = GEN.render_aliases(self.root)
        self.assertIn(f"| `decision-old` | [Survivor](decisions/2026-09-01-a.md) | [permalink](https://github.com/redact-secret/redact-secret/blob/{sha}/docs/decisions/old.md) |", text)

    def test_alias_without_a_permalink_row_is_rejected(self) -> None:
        (self.root / "docs" / "decisions" / "2026-09-01-a.md").write_text(
            "---\ndecision_id: decision-a\nstatus: accepted\nscope: workspace\nspec: engine\naliases: decision-old\n---\n\n# Survivor\n",
            encoding="utf-8",
        )
        self.assertEqual(GEN.main([str(self.root), "--check"]), 1)

    def test_an_unknown_spec_is_rejected(self) -> None:
        self.record("2026-09-01-a.md", "nonsense", "T")
        self.assertEqual(GEN.main([str(self.root), "--check"]), 1)


if __name__ == "__main__":
    unittest.main()
