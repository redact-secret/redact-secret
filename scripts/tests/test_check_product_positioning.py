from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-product-positioning.py"
SPEC = importlib.util.spec_from_file_location("check_product_positioning", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

P = CHECK.POSITIONING

GOOD_INTRO = (
    f"# pkg\n\n{P}.\n\n"
    "Redact Secret is not a DLP platform and does not detect every secret.\n"
    "It complements repository and history scanners rather than replacing them.\n"
    "See the [support matrix](docs/support-matrix.md).\n\n"
    "## Install\n"
)


class CheckProductPositioningTest(unittest.TestCase):
    def test_the_repository_passes(self) -> None:
        self.assertEqual(CHECK.validate(CHECK.ROOT), [])

    def test_manifest_descriptions_must_share_the_positioning(self) -> None:
        self.assertEqual(CHECK.check_manifest("p.json", f'{{"description": "{P}: more"}}', "json"), [])
        self.assertEqual(
            CHECK.check_manifest("Cargo.toml", '[package]\ndescription = "Secret scanner."\n', "cargo"),
            ["Cargo.toml description does not start with the shared positioning statement"],
        )
        self.assertEqual(
            CHECK.check_manifest("pyproject.toml", "[project]\nname = 'x'\n", "pyproject"),
            ["pyproject.toml has no description"],
        )

    def test_a_registry_readme_needs_every_scope_limit_in_its_intro(self) -> None:
        self.assertEqual(CHECK.check_registry_readme("R.md", GOOD_INTRO), [])
        moved = GOOD_INTRO.replace("See the [support matrix](docs/support-matrix.md).\n\n## Install\n", "## Install\n\n[support matrix](docs/support-matrix.md)\n")
        self.assertEqual(CHECK.check_registry_readme("R.md", moved), ["R.md intro is missing: support matrix link"])
        wrapped = GOOD_INTRO.replace("repository and history", "repository and\nhistory")
        self.assertEqual(CHECK.check_registry_readme("R.md", wrapped), [])

    def test_the_root_readme_first_section_names_every_use_case(self) -> None:
        text = f"# Redact Secret\n\n{P}.\n\n## What it is for\n\nlogs, persistence, telemetry, tool output, model context\n\n## Next\n"
        self.assertEqual(CHECK.check_root_readme(text), [])
        later = text.replace("model context\n\n## Next\n", "\n\n## Next\n\nmodel context\n")
        self.assertEqual(
            CHECK.check_root_readme(later),
            ["README.md first section does not name the use case: model context"],
        )

    def test_positive_coverage_claims_are_rejected_but_negations_are_not(self) -> None:
        self.assertEqual(CHECK.check_forbidden("R.md", "Redact Secret is not a complete DLP system."), [])
        self.assertEqual(len(CHECK.check_forbidden("R.md", "Provides complete secret coverage.")), 1)
        self.assertEqual(len(CHECK.check_forbidden("R.md", "It detects every secret you paste.")), 1)
        self.assertEqual(CHECK.check_forbidden("R.md", "It does not detect every secret."), [])


if __name__ == "__main__":
    unittest.main()
