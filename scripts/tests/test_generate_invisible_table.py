from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-invisible-table.py"
SPEC = importlib.util.spec_from_file_location("generate_invisible_table", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

DERIVED = """\
# DerivedCoreProperties-17.0.0.txt
00AD          ; Default_Ignorable_Code_Point # Cf       SOFT HYPHEN
200B..200F    ; Default_Ignorable_Code_Point # Cf   [5] ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK
2060..2064    ; Default_Ignorable_Code_Point # Cf   [5] WORD JOINER..INVISIBLE PLUS
0041..005A    ; Uppercase # L&  [26] LATIN CAPITAL LETTER A..LATIN CAPITAL LETTER Z
"""

UNICODE_DATA = """\
0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;
00AD;SOFT HYPHEN;Cf;0;BN;;;;;N;;;;;
0600;ARABIC NUMBER SIGN;Cf;0;AN;;;;;N;;;;;
2065;<reserved>;Cn;0;BN;;;;;N;;;;;
FFF9;INTERLINEAR ANNOTATION ANCHOR;Cf;0;ON;;;;;N;;;;;
E0020;<Tag, First>;Cf;0;BN;;;;;N;;;;;
E007F;<Tag, Last>;Cf;0;BN;;;;;N;;;;;
"""


class DeriveRangesTest(unittest.TestCase):
    def test_union_of_property_and_category_is_sorted_and_merged(self) -> None:
        self.assertEqual(
            GEN.derive_ranges(DERIVED, UNICODE_DATA),
            [
                (0x00AD, 0x00AD),
                (0x0600, 0x0600),
                (0x200B, 0x200F),
                (0x2060, 0x2064),
                (0xFFF9, 0xFFF9),
                (0xE0020, 0xE007F),
            ],
        )

    def test_other_properties_and_categories_are_ignored(self) -> None:
        ranges = GEN.derive_ranges(DERIVED, UNICODE_DATA)
        self.assertFalse(any(first <= 0x41 <= last for first, last in ranges))
        self.assertFalse(any(first <= 0x2065 <= last for first, last in ranges))

    def test_adjacent_and_overlapping_ranges_merge(self) -> None:
        self.assertEqual(
            GEN.merge_ranges([(0x2060, 0x2064), (0x2065, 0x2065), (0x2062, 0x206F), (0x3164, 0x3164)]),
            [(0x2060, 0x206F), (0x3164, 0x3164)],
        )

    def test_an_ascii_member_is_rejected(self) -> None:
        with self.assertRaises(GEN.TableError):
            GEN.derive_ranges("007F ; Default_Ignorable_Code_Point # Cc\n", "")

    def test_an_empty_set_is_rejected(self) -> None:
        with self.assertRaises(GEN.TableError):
            GEN.derive_ranges("", "")

    def test_an_unterminated_range_pair_is_rejected(self) -> None:
        with self.assertRaises(GEN.TableError):
            GEN.category_ranges("E0020;<Tag, First>;Cf;0;BN;;;;;N;;;;;\n")


class RenderTableTest(unittest.TestCase):
    def test_render_is_deterministic_and_names_the_version(self) -> None:
        table = GEN.render_table([(0xAD, 0xAD), (0xE0000, 0xE0FFF)], "17.0.0")
        self.assertEqual(table, GEN.render_table([(0xAD, 0xAD), (0xE0000, 0xE0FFF)], "17.0.0"))
        self.assertIn('pub(crate) const UCD_VERSION: &str = "17.0.0";', table)
        self.assertIn("    (0x00AD, 0x00AD),\n    (0xE0000, 0xE0FFF),\n];\n", table)
        self.assertIn("2 ranges, 4097 code points.", table)


class CheckedInTableTest(unittest.TestCase):
    def test_checked_in_table_matches_a_regeneration(self) -> None:
        self.assertEqual(GEN.TABLE.read_text(encoding="utf-8"), GEN.generated_table())

    def test_checked_in_extracts_hold_only_the_kept_lines(self) -> None:
        derived = (GEN.EXTRACT_DIR / "DerivedCoreProperties.txt").read_text(encoding="utf-8")
        data = (GEN.EXTRACT_DIR / "UnicodeData.txt").read_text(encoding="utf-8")
        for text, keep in ((derived, GEN.is_property_line), (data, GEN.is_category_line)):
            for line in text.splitlines():
                self.assertTrue(line.startswith("#") or keep(line), line)
        for name, text in (("DerivedCoreProperties.txt", derived), ("UnicodeData.txt", data)):
            self.assertIn(f"Database {GEN.UCD_VERSION}.", text.splitlines()[0])
            self.assertIn(GEN.UCD_SHA256[name], text)


if __name__ == "__main__":
    unittest.main()
