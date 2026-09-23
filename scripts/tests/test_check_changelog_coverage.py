#!/usr/bin/env python3
"""Changelog coverage for detector and binding changes (issue #633)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-changelog-coverage.py"
spec = importlib.util.spec_from_file_location("check_changelog_coverage", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

BASE = """# Changelog

## Unreleased

### Added

- Something earlier.

## 0.1.0-beta.6
"""

WITH_ENTRY = """# Changelog

## Unreleased

### Added

- Something earlier.
- A new `example-token` detector.

## 0.1.0-beta.6
"""

RELEASED_ONLY = """# Changelog

## Unreleased

### Added

- Something earlier.

## 0.1.0-beta.6

- An edit to an already released section.
"""

DETECTOR = "crates/secret-scan-core/src/detectors/okta.rs"
BINDING = "bindings/python/src/lib.rs"
UNRELATED = "docs/specs/detector-families.md"


class Guarded(unittest.TestCase):
    def test_detector_and_binding_sources_are_guarded(self) -> None:
        self.assertEqual(check.guarded([DETECTOR, UNRELATED, BINDING]), [BINDING, DETECTOR])

    def test_policy_file_is_guarded_but_its_neighbours_are_not(self) -> None:
        self.assertEqual(
            check.guarded(
                ["crates/secret-scan-core/src/policy.rs", "crates/secret-scan-core/src/lib.rs"]
            ),
            ["crates/secret-scan-core/src/policy.rs"],
        )

    def test_tests_and_documentation_are_not_guarded(self) -> None:
        self.assertEqual(check.guarded([UNRELATED, "scripts/tests/test_x.py", "README.md"]), [])


class UnreleasedSection(unittest.TestCase):
    def test_reads_only_up_to_the_next_release_heading(self) -> None:
        self.assertEqual(
            check.unreleased_section(BASE),
            "### Added\n\n- Something earlier.",
        )

    def test_a_changelog_without_the_heading_has_no_section(self) -> None:
        self.assertEqual(check.unreleased_section("# Changelog\n\n## 0.1.0\n\n- old\n"), "")


class Evaluate(unittest.TestCase):
    def test_detector_change_with_an_entry_passes(self) -> None:
        self.assertEqual(check.evaluate([DETECTOR], BASE, WITH_ENTRY, []), [])

    def test_detector_change_without_an_entry_fails(self) -> None:
        errors = check.evaluate([DETECTOR], BASE, BASE, [])
        self.assertEqual(len(errors), 1)
        self.assertIn(DETECTOR, errors[0])
        self.assertIn(check.WAIVER_LABEL, errors[0])

    def test_editing_an_already_released_section_is_not_an_entry(self) -> None:
        self.assertEqual(len(check.evaluate([DETECTOR], BASE, RELEASED_ONLY, [])), 1)

    def test_the_waiver_label_passes_without_an_entry(self) -> None:
        self.assertEqual(check.evaluate([DETECTOR], BASE, BASE, [check.WAIVER_LABEL]), [])

    def test_an_unrelated_label_does_not_waive(self) -> None:
        self.assertEqual(len(check.evaluate([DETECTOR], BASE, BASE, ["documentation"])), 1)

    def test_an_unrelated_change_needs_no_entry(self) -> None:
        self.assertEqual(check.evaluate([UNRELATED], BASE, BASE, []), [])

    def test_a_binding_change_without_an_entry_fails(self) -> None:
        self.assertEqual(len(check.evaluate([BINDING], BASE, BASE, [])), 1)

    def test_many_guarded_files_are_summarized(self) -> None:
        paths = [f"crates/secret-scan-core/src/detectors/d{index}.rs" for index in range(12)]
        errors = check.evaluate(paths, BASE, BASE, [])
        self.assertIn("12 guarded file(s)", errors[0])
        self.assertIn("and 2 more", errors[0])


if __name__ == "__main__":
    unittest.main()
