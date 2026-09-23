from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REHEARSAL = load("rehearsal_version", "rehearsal-version.py")
WORKSPACE = load("check_rust_workspace_for_rehearsal", "check-rust-workspace.py")

THROWAWAY = "0.1.0-beta.9876543210"


def copy_lockstep_tree(destination: Path) -> None:
    """The files `apply` rewrites, copied from this checkout."""
    files = [
        REHEARSAL.CARGO_TOML,
        REHEARSAL.CARGO_LOCK,
        REHEARSAL.TYPESCRIPT_VERSION,
        *REHEARSAL.LOCKFILES,
        *REHEARSAL.DOC_PINS,
        *REHEARSAL.manifests(ROOT),
    ]
    for relative in files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


class DeriveTests(unittest.TestCase):
    def test_keeps_the_release_grammar_the_rest_of_the_path_parses(self) -> None:
        version = REHEARSAL.derive("9876543210", "0.1.0-beta.6")
        self.assertEqual(version, THROWAWAY)
        self.assertEqual(REHEARSAL.pep440(version), "0.1.0b9876543210")

    def test_rejects_a_run_id_that_could_collide_with_a_real_beta(self) -> None:
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.derive("6", "0.1.0-beta.6")
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.derive("not-a-number", "0.1.0-beta.6")

    def test_rejects_a_branch_version_outside_the_grammar(self) -> None:
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.derive("9876543210", "1.0.0")


class ApplyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        copy_lockstep_tree(self.root)
        self.old = REHEARSAL.workspace_version(self.root)

    def test_moves_the_whole_lockstep_set_and_leaves_no_stale_pin(self) -> None:
        REHEARSAL.apply(self.root, THROWAWAY)
        self.assertEqual(REHEARSAL.workspace_version(self.root), THROWAWAY)
        for relative in REHEARSAL.manifests(self.root):
            manifest = json.loads((self.root / relative).read_text(encoding="utf-8"))
            self.assertEqual(manifest["version"], THROWAWAY, relative)
            for field in ("dependencies", "optionalDependencies"):
                for name, pinned in (manifest.get(field) or {}).items():
                    if name.startswith("@redact-secret/"):
                        self.assertEqual(pinned, THROWAWAY, f"{relative} {name}")
        for relative in (
            REHEARSAL.CARGO_TOML,
            REHEARSAL.CARGO_LOCK,
            REHEARSAL.TYPESCRIPT_VERSION,
            *REHEARSAL.LOCKFILES,
            *REHEARSAL.DOC_PINS,
        ):
            text = (self.root / relative).read_text(encoding="utf-8")
            self.assertNotIn(self.old, text, relative)
        quickstart = (self.root / "docs/quickstart.md").read_text(encoding="utf-8")
        self.assertIn(f"redact-secret=={REHEARSAL.pep440(THROWAWAY)}", quickstart)

    def test_only_workspace_members_move_in_cargo_lock(self) -> None:
        REHEARSAL.apply(self.root, THROWAWAY)
        lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        moved = re.findall(r'name = "([^"]+)"\nversion = "' + re.escape(THROWAWAY) + '"', lock)
        self.assertEqual(
            sorted(moved),
            sorted(["redact-secret", "redact-secret-cli", "redact-secret-node", "redact-secret-python", "redact-secret-wasm"]),
        )

    def test_the_repository_lockstep_check_accepts_the_bumped_manifests(self) -> None:
        REHEARSAL.apply(self.root, THROWAWAY)
        # The per-manifest comparison `scripts/check-rust-workspace.py` runs,
        # over the bumped copy, using that script's own manifest discovery.
        self.assertEqual(self._manifest_errors(), [])

    def _manifest_errors(self) -> list[str]:
        errors = []
        for relative in WORKSPACE.LOCKSTEP_MANIFESTS + (WORKSPACE.WASM_MANIFEST,) + tuple(
            WORKSPACE.native_platform_manifests(self.root)
        ):
            manifest = json.loads((self.root / relative).read_text(encoding="utf-8"))
            if manifest["version"] != THROWAWAY:
                errors.append(relative)
            for field in ("dependencies", "optionalDependencies"):
                for name, pinned in (manifest.get(field) or {}).items():
                    if name.startswith("@redact-secret/") and pinned != THROWAWAY:
                        errors.append(f"{relative}:{name}")
        return errors

    def test_refuses_the_version_the_branch_already_carries(self) -> None:
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.apply(self.root, self.old)

    def test_fails_when_a_file_it_must_move_no_longer_carries_the_version(self) -> None:
        (self.root / "packages/javascript/src/version.ts").write_text("export const VERSION = \"9.9.9\";\n")
        with self.assertRaises(REHEARSAL.RehearsalError):
            REHEARSAL.apply(self.root, THROWAWAY)


class UnpublishedProbeTests(unittest.TestCase):
    def test_probes_every_npm_package_both_crates_and_pypi(self) -> None:
        labels = [label for label, _ in REHEARSAL.registry_probes(ROOT, THROWAWAY)]
        scoped = [
            relative
            for relative in REHEARSAL.manifests(ROOT)
            if json.loads((ROOT / relative).read_text(encoding="utf-8"))["name"].startswith("@")
        ]
        self.assertEqual(sum(label.startswith("npm ") for label in labels), len(scoped))
        self.assertGreaterEqual(len(scoped), 10)
        self.assertIn(f"crates.io redact-secret@{THROWAWAY}", labels)
        self.assertIn(f"crates.io redact-secret-cli@{THROWAWAY}", labels)
        self.assertIn(f"PyPI redact-secret==0.1.0b9876543210", labels)

    def test_only_a_404_proves_absence(self) -> None:
        self.assertEqual(REHEARSAL.check_unpublished(ROOT, THROWAWAY, status=lambda url: 404), [])
        for code in (200, 429, 500):
            errors = REHEARSAL.check_unpublished(ROOT, THROWAWAY, status=lambda url, code=code: code)
            self.assertTrue(errors, code)

    def test_a_published_version_is_named(self) -> None:
        errors = REHEARSAL.check_unpublished(
            ROOT, THROWAWAY, status=lambda url: 200 if "crates/redact-secret-cli/" in url else 404
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("redact-secret-cli", errors[0])


class WorkflowWiringTests(unittest.TestCase):
    """The rehearsal must actually qualify the bumped version, in every job."""

    def read(self, name: str) -> str:
        return (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")

    def test_the_rehearsal_qualifies_the_throwaway_version(self) -> None:
        text = self.read("package-release-rehearsal.yml")
        self.assertIn("rehearsal-version: ${{ needs.version.outputs.version }}", text)
        self.assertIn("check-unpublished", text)
        self.assertIn("uses: ./.github/actions/apply-rehearsal-version", text)

    def test_every_building_job_applies_the_version_right_after_checkout(self) -> None:
        for name in ("artifact-qualification.yml", "python-wheels.yml"):
            text = self.read(name)
            checkouts = text.count("actions/checkout@")
            applied = text.count("uses: ./.github/actions/apply-rehearsal-version")
            self.assertGreaterEqual(applied, 3, name)
            self.assertLess(applied, checkouts, name)
        qualification = self.read("artifact-qualification.yml")
        for job in (
            "node-addon", "browser", "cli", "package-consumer-node", "package-consumer-browser",
            "package-consumer-wasm-runtimes", "clean-install", "inventory",
        ):
            match = re.search(r"\n  " + re.escape(job) + r":\n(.*?)(?=\n  [a-z0-9-]+:\n|\Z)", qualification, re.S)
            self.assertIsNotNone(match, job)
            self.assertIn("apply-rehearsal-version", match.group(1), job)

    def test_release_workflow_never_passes_a_rehearsal_version(self) -> None:
        self.assertNotIn("rehearsal-version", self.read("release.yml"))

    def test_inventory_packages_both_crates_together_and_tolerates_the_uncommitted_bump(self) -> None:
        text = self.read("artifact-qualification.yml")
        self.assertIn("-p redact-secret -p redact-secret-cli", text)
        self.assertIn("--allow-dirty", text)
        self.assertNotIn("cargo package --no-verify --locked -p redact-secret-cli", text)


if __name__ == "__main__":
    unittest.main()
