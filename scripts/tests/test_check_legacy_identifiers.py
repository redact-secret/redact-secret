from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-legacy-identifiers.py"
SPEC = importlib.util.spec_from_file_location("check_legacy_identifiers", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

REPO_ROOT = Path(__file__).resolve().parents[2]


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


class CheckLegacyIdentifiersTest(unittest.TestCase):
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

    def test_a_clean_tree_passes(self) -> None:
        self.repo.write("src/lib.rs", "use redact_secret::scan;\n")
        self.assertEqual(self.validate(), [])

    def test_a_bare_kebab_hit_is_rejected(self) -> None:
        self.repo.write("README.md", "Install secret-scan from npm.\n")
        self.assertOneError("legacy identifier 'secret-scan' outside the allowlist")

    def test_a_bare_snake_hit_is_rejected(self) -> None:
        self.repo.write("example.py", "import secret_scan\n")
        self.assertOneError("legacy identifier 'secret_scan' outside the allowlist")

    def test_a_pascal_hit_is_rejected(self) -> None:
        self.repo.write("example.ts", "class SecretScanRuntime {}\n")
        self.assertOneError("legacy identifier 'SecretScan' outside the allowlist")

    def test_secret_scan_error_is_not_flagged(self) -> None:
        self.repo.write(
            "src/error.rs",
            "pub struct SecretScanError;\npub enum SecretScanErrorCode {}\n",
        )
        self.assertEqual(self.validate(), [])

    def test_a_preserved_core_directory_path_is_not_flagged(self) -> None:
        self.repo.write(
            "docs/note.md",
            "See `crates/secret-scan-core/src/lib.rs` and "
            "`crates/secret-scan-cli/src/main.rs`.\n",
        )
        self.assertEqual(self.validate(), [])

    def test_githubs_secret_scanning_product_name_is_not_flagged(self) -> None:
        self.repo.write(
            "docs/audits/evidence/note.md",
            "Corroborated against GitHub supported secret-scanning patterns "
            "(docs.github.com/en/code-security/secret-scanning/introduction/"
            "supported-secret-scanning-patterns).\n",
        )
        self.assertEqual(self.validate(), [])

    def test_the_legacy_github_path_is_rejected(self) -> None:
        self.repo.write(
            "docs/note.md",
            "https://github.com/omiologic/secret-scan/issues/1\n",
        )
        self.assertOneError("legacy identifier 'secret-scan' outside the allowlist")

    def test_the_legacy_wiki_sibling_reference_is_rejected(self) -> None:
        self.repo.write("note.txt", "checked out at ../secret-scan.wiki\n")
        self.assertOneError("legacy identifier 'secret-scan' outside the allowlist")

    def test_a_hit_on_an_allowlisted_path_passes(self) -> None:
        self.repo.write("docs/decisions/2026-09-10-adopt-redact-secret-naming-contract.md", "Previous identity: secret-scan.\n")
        self.assertEqual(self.validate(), [])

    def test_candidate_changelog_cannot_reintroduce_legacy_identity(self) -> None:
        self.repo.write("CHANGELOG.md", "Install @omiologic/secret-scan.\n")
        self.assertOneError("legacy identifier 'secret-scan' outside the allowlist")

    def test_an_allowlist_entry_naming_a_missing_file_is_rejected(self) -> None:
        original = dict(CHECK.LEGACY_IDENTIFIER_ALLOWLIST)
        CHECK.LEGACY_IDENTIFIER_ALLOWLIST["does/not/exist.md"] = "test-only entry"
        try:
            errors = CHECK.check_allowlist_shape(self.repo.root)
        finally:
            CHECK.LEGACY_IDENTIFIER_ALLOWLIST.clear()
            CHECK.LEGACY_IDENTIFIER_ALLOWLIST.update(original)
        self.assertTrue(
            any("does/not/exist.md: allowlisted but the file does not exist" in error for error in errors),
            errors,
        )

    def test_an_allowlist_entry_without_a_rationale_is_rejected(self) -> None:
        original = dict(CHECK.LEGACY_IDENTIFIER_ALLOWLIST)
        path = self.repo.write("scratch.md", "secret-scan\n")
        CHECK.LEGACY_IDENTIFIER_ALLOWLIST[path] = "   "
        try:
            errors = CHECK.check_allowlist_shape(self.repo.root)
        finally:
            CHECK.LEGACY_IDENTIFIER_ALLOWLIST.clear()
            CHECK.LEGACY_IDENTIFIER_ALLOWLIST.update(original)
        self.assertTrue(
            any(f"{path}: allowlist entry has no rationale" in error for error in errors),
            errors,
        )

    def test_every_allowlist_entry_is_well_formed_against_the_real_repository(self) -> None:
        self.assertEqual(CHECK.check_allowlist_shape(REPO_ROOT), [])

    def test_the_real_repository_passes(self) -> None:
        errors = CHECK.check_allowlist_shape(REPO_ROOT) + CHECK.validate(REPO_ROOT)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
