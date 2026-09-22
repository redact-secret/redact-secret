from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-python-digest.py"
SPEC = importlib.util.spec_from_file_location("verify_python_digest", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class VerifyPythonDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def _write(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def _inventory(self, entries: list[dict]) -> Path:
        path = self.root / "artifact-inventory.json"
        path.write_text(json.dumps({"artifacts": entries}), encoding="utf-8")
        return path

    def test_matching_wheel_and_sdist_digests_pass(self) -> None:
        wheel_bytes = b"wheel contents"
        sdist_bytes = b"sdist contents"
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", wheel_bytes)
        sdist = self._write("redact_secret-0.1.0.tar.gz", sdist_bytes)
        inventory = self._inventory(
            [
                {
                    "family": "python-wheel",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": wheel.name,
                    "sha256": digest(wheel_bytes),
                },
                {
                    "family": "python-sdist",
                    "target": None,
                    "file": sdist.name,
                    "sha256": digest(sdist_bytes),
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "redact-secret.linux-x64-gnu.node",
                    "sha256": "0" * 64,
                },
            ]
        )

        errors = CHECK.verify([wheel, sdist], CHECK.qualified_digests(inventory))

        self.assertEqual(errors, [])

    def test_mismatched_digest_is_an_error(self) -> None:
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", b"published bytes")
        inventory = self._inventory(
            [{"family": "python-wheel", "target": "x", "file": wheel.name, "sha256": digest(b"qualified bytes")}]
        )

        errors = CHECK.verify([wheel], CHECK.qualified_digests(inventory))

        self.assertEqual(len(errors), 1)
        self.assertIn("does not match the qualified digest", errors[0])

    def test_artifact_missing_from_inventory_is_an_error(self) -> None:
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", b"bytes")
        inventory = self._inventory([])

        errors = CHECK.verify([wheel], CHECK.qualified_digests(inventory))

        self.assertEqual(len(errors), 1)
        self.assertIn("not present in the qualified artifact inventory", errors[0])

    def test_qualified_artifact_missing_from_publish_set_is_an_error(self) -> None:
        inventory = self._inventory(
            [{"family": "python-sdist", "target": None, "file": "redact_secret-0.1.0.tar.gz", "sha256": digest(b"x")}]
        )

        errors = CHECK.verify([], CHECK.qualified_digests(inventory))

        self.assertEqual(len(errors), 1)
        self.assertIn("not present among the artifacts about to publish", errors[0])

    def test_non_python_families_are_ignored(self) -> None:
        inventory = self._inventory(
            [{"family": "node-addon", "target": "x", "file": "redact-secret.linux-x64-gnu.node", "sha256": "0" * 64}]
        )

        self.assertEqual(CHECK.qualified_digests(inventory), {})

    def test_missing_artifact_file_is_an_error(self) -> None:
        inventory = self._inventory([])

        errors = CHECK.verify([self.root / "missing.whl"], CHECK.qualified_digests(inventory))

        self.assertEqual(len(errors), 1)
        self.assertIn("not a file", errors[0])

    def test_main_exits_nonzero_on_mismatch(self) -> None:
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", b"published bytes")
        inventory = self._inventory(
            [{"family": "python-wheel", "target": "x", "file": wheel.name, "sha256": digest(b"qualified bytes")}]
        )

        old_argv = sys.argv
        sys.argv = ["verify-python-digest.py", str(wheel), "--inventory", str(inventory)]
        try:
            self.assertEqual(CHECK.main(), 1)
        finally:
            sys.argv = old_argv

    def test_main_exits_zero_on_match(self) -> None:
        wheel_bytes = b"published bytes"
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", wheel_bytes)
        inventory = self._inventory(
            [{"family": "python-wheel", "target": "x", "file": wheel.name, "sha256": digest(wheel_bytes)}]
        )

        old_argv = sys.argv
        sys.argv = ["verify-python-digest.py", str(wheel), "--inventory", str(inventory)]
        try:
            self.assertEqual(CHECK.main(), 0)
        finally:
            sys.argv = old_argv

    def test_family_filter_selects_a_non_python_family(self) -> None:
        addon_bytes = b"compiled addon"
        addon = self._write("redact-secret.darwin-arm64.node", addon_bytes)
        inventory = self._inventory(
            [
                {
                    "family": "node-addon",
                    "target": "aarch64-apple-darwin",
                    "file": addon.name,
                    "sha256": digest(addon_bytes),
                },
                {
                    "family": "python-sdist",
                    "target": None,
                    "file": "redact_secret-0.1.0.tar.gz",
                    "sha256": "0" * 64,
                },
            ]
        )

        qualified = CHECK.qualified_digests(inventory, ("node-addon",))
        errors = CHECK.verify([addon], qualified)

        self.assertEqual(qualified, {addon.name: digest(addon_bytes)})
        self.assertEqual(errors, [])

    def test_target_filter_excludes_other_targets_of_the_same_family(self) -> None:
        inventory = self._inventory(
            [
                {
                    "family": "node-addon",
                    "target": "aarch64-apple-darwin",
                    "file": "redact-secret.darwin-arm64.node",
                    "sha256": "0" * 64,
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "redact-secret.linux-x64-gnu.node",
                    "sha256": "1" * 64,
                },
            ]
        )

        qualified = CHECK.qualified_digests(inventory, ("node-addon",), target="aarch64-apple-darwin")

        self.assertEqual(qualified, {"redact-secret.darwin-arm64.node": "0" * 64})

    def test_cli_family_and_target_flags_select_the_matching_entry(self) -> None:
        addon_bytes = b"compiled addon"
        addon = self._write("redact-secret.darwin-arm64.node", addon_bytes)
        inventory = self._inventory(
            [
                {
                    "family": "node-addon",
                    "target": "aarch64-apple-darwin",
                    "file": addon.name,
                    "sha256": digest(addon_bytes),
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "redact-secret.linux-x64-gnu.node",
                    "sha256": "1" * 64,
                },
            ]
        )

        old_argv = sys.argv
        sys.argv = [
            "verify-python-digest.py",
            str(addon),
            "--inventory",
            str(inventory),
            "--family",
            "node-addon",
            "--target",
            "aarch64-apple-darwin",
        ]
        try:
            self.assertEqual(CHECK.main(), 0)
        finally:
            sys.argv = old_argv

    def _addon_leg_with_loader(self) -> tuple[Path, Path]:
        # The shape `record-artifact-inventory.py` actually records for one
        # `node-addon-<target>` upload: the compiled library plus napi's
        # generated loader, of which the platform package ships only the
        # library (rc/0.1.0-beta.6 rehearsal run 35742550228).
        addon_bytes = b"compiled addon"
        addon = self._write("redact-secret.linux-x64-gnu.node", addon_bytes)
        inventory = self._inventory(
            [
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": addon.name,
                    "sha256": digest(addon_bytes),
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "index.js",
                    "sha256": "2" * 64,
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "index.d.ts",
                    "sha256": "3" * 64,
                },
            ]
        )
        return addon, inventory

    def _run_addon_check(self, addon: Path, inventory: Path, *extra: str) -> int:
        old_argv = sys.argv
        sys.argv = [
            "verify-python-digest.py",
            str(addon),
            "--inventory",
            str(inventory),
            "--family",
            "node-addon",
            "--target",
            "x86_64-unknown-linux-gnu",
            *extra,
        ]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return CHECK.main()
        finally:
            sys.argv = old_argv

    def test_unshipped_loader_files_fail_the_addon_check_without_a_suffix(self) -> None:
        addon, inventory = self._addon_leg_with_loader()

        self.assertEqual(self._run_addon_check(addon, inventory), 1)

    def test_suffix_narrows_the_addon_check_to_the_shipped_library(self) -> None:
        addon, inventory = self._addon_leg_with_loader()

        self.assertEqual(self._run_addon_check(addon, inventory, "--suffix", ".node"), 0)

    def test_suffix_still_requires_every_matching_qualified_file(self) -> None:
        _, inventory = self._addon_leg_with_loader()

        qualified = CHECK.qualified_digests(
            inventory, ("node-addon",), target="x86_64-unknown-linux-gnu", suffix=".node"
        )

        self.assertEqual(
            CHECK.verify([], qualified),
            [
                "redact-secret.linux-x64-gnu.node: qualified by artifact-qualification.yml "
                "but not present among the artifacts about to publish"
            ],
        )

    def test_default_family_is_unchanged_when_no_flag_is_given(self) -> None:
        wheel_bytes = b"wheel contents"
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", wheel_bytes)
        inventory = self._inventory(
            [
                {
                    "family": "python-wheel",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": wheel.name,
                    "sha256": digest(wheel_bytes),
                },
                {
                    "family": "node-addon",
                    "target": "x86_64-unknown-linux-gnu",
                    "file": "redact-secret.linux-x64-gnu.node",
                    "sha256": "1" * 64,
                },
            ]
        )

        self.assertEqual(CHECK.qualified_digests(inventory), {wheel.name: digest(wheel_bytes)})

    def test_missing_inventory_file_is_an_error(self) -> None:
        wheel = self._write("redact_secret-0.1.0-cp310-abi3-linux.whl", b"bytes")

        old_argv = sys.argv
        sys.argv = ["verify-python-digest.py", str(wheel), "--inventory", str(self.root / "missing.json")]
        try:
            self.assertEqual(CHECK.main(), 1)
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
