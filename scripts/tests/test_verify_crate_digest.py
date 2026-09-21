from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-crate-digest.py"
SPEC = importlib.util.spec_from_file_location("verify_crate_digest", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class VerifyCrateDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def _inventory(self, entries: list[dict]) -> Path:
        path = self.root / "artifact-inventory.json"
        path.write_text(json.dumps({"artifacts": entries}), encoding="utf-8")
        return path

    def test_matching_checksum_passes(self) -> None:
        digest = "a" * 64
        inventory = self._inventory(
            [{"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": digest}]
        )

        errors = CHECK.verify("redact-secret", CHECK.qualified_digest(inventory, "redact-secret"), digest)

        self.assertEqual(errors, [])

    def test_mismatched_checksum_names_both_digests(self) -> None:
        qualified = "a" * 64
        published = "b" * 64
        inventory = self._inventory(
            [{"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": qualified}]
        )

        errors = CHECK.verify("redact-secret", CHECK.qualified_digest(inventory, "redact-secret"), published)

        self.assertEqual(len(errors), 1)
        self.assertIn("redact-secret-0.1.0.crate", errors[0])
        self.assertIn(qualified, errors[0])
        self.assertIn(published, errors[0])

    def test_crate_missing_from_inventory_is_an_error(self) -> None:
        inventory = self._inventory([])

        errors = CHECK.verify("redact-secret", CHECK.qualified_digest(inventory, "redact-secret"), "a" * 64)

        self.assertEqual(len(errors), 1)
        self.assertIn("not present in the qualified artifact inventory", errors[0])

    def test_only_the_matching_crate_target_is_selected(self) -> None:
        inventory = self._inventory(
            [
                {"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": "0" * 64},
                {
                    "family": "crate",
                    "target": "redact-secret-cli",
                    "file": "redact-secret-cli-0.1.0.crate",
                    "sha256": "1" * 64,
                },
            ]
        )

        self.assertEqual(
            CHECK.qualified_digest(inventory, "redact-secret-cli"),
            ("redact-secret-cli-0.1.0.crate", "1" * 64),
        )

    def test_main_exits_zero_on_match(self) -> None:
        digest = "a" * 64
        inventory = self._inventory(
            [{"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": digest}]
        )

        old_argv = sys.argv
        sys.argv = [
            "verify-crate-digest.py",
            "--inventory",
            str(inventory),
            "--crate",
            "redact-secret",
            "--published-checksum",
            digest,
        ]
        try:
            self.assertEqual(CHECK.main(), 0)
        finally:
            sys.argv = old_argv

    def test_main_exits_nonzero_on_mismatch(self) -> None:
        inventory = self._inventory(
            [{"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": "a" * 64}]
        )

        old_argv = sys.argv
        sys.argv = [
            "verify-crate-digest.py",
            "--inventory",
            str(inventory),
            "--crate",
            "redact-secret",
            "--published-checksum",
            "b" * 64,
        ]
        try:
            self.assertEqual(CHECK.main(), 1)
        finally:
            sys.argv = old_argv

    def test_missing_inventory_file_is_an_error(self) -> None:
        old_argv = sys.argv
        sys.argv = [
            "verify-crate-digest.py",
            "--inventory",
            str(self.root / "missing.json"),
            "--crate",
            "redact-secret",
            "--published-checksum",
            "a" * 64,
        ]
        try:
            self.assertEqual(CHECK.main(), 1)
        finally:
            sys.argv = old_argv

    def test_empty_published_checksum_is_an_error(self) -> None:
        inventory = self._inventory(
            [{"family": "crate", "target": "redact-secret", "file": "redact-secret-0.1.0.crate", "sha256": "a" * 64}]
        )

        old_argv = sys.argv
        sys.argv = [
            "verify-crate-digest.py",
            "--inventory",
            str(inventory),
            "--crate",
            "redact-secret",
            "--published-checksum",
            "",
        ]
        try:
            self.assertEqual(CHECK.main(), 1)
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
