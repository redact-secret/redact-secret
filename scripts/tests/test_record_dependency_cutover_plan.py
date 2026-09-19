from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "record-dependency-cutover-plan.py"
SPEC = importlib.util.spec_from_file_location("record_dependency_cutover_plan", SCRIPT)
assert SPEC and SPEC.loader
RECORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECORD
SPEC.loader.exec_module(RECORD)

TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
PLATFORMS = {"aarch64-apple-darwin": "darwin-arm64", "x86_64-unknown-linux-gnu": "linux-x64-gnu"}


class Repository:
    """A minimal repository this script's own reads are satisfied by: a
    declared `node-publish-targets` policy, the platform-name mapping
    `qualify-node-addon.mjs` carries, a manifest for each native dependency
    package, the wasm package, and the wrapper -- so each test can remove or
    change exactly one thing."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.targets = list(TARGETS)
        self.platforms = dict(PLATFORMS)
        self.include_native_manifests = True
        self.include_wasm_manifest = True
        self.include_wrapper_manifest = True
        self.wrapper_version = "0.1.0-beta.1"

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def build(self) -> Path:
        targets_toml = "[" + ", ".join(json.dumps(t) for t in self.targets) + "]"
        self.write(
            "Cargo.toml",
            "[workspace]\n[workspace.metadata.redact-secret]\n"
            f"node-publish-targets = {targets_toml}\n",
        )
        mapping = "\n".join(
            f'  "{target}": "{platform}",' for target, platform in self.platforms.items()
        )
        self.write(
            "scripts/qualify-node-addon.mjs",
            "const TARGET_PLATFORM_NAMES = {\n" + mapping + "\n};\n",
        )
        if self.include_native_manifests:
            for target in self.targets:
                platform = self.platforms[target]
                self.write(
                    f"bindings/node/npm/{platform}/package.json",
                    json.dumps(
                        {
                            "name": f"@redact-secret/node-{platform}",
                            "version": "0.1.0-beta.1",
                        },
                        indent=2,
                    )
                    + "\n",
                )
        if self.include_wasm_manifest:
            self.write(
                "bindings/wasm/npm/package.json",
                json.dumps(
                    {"name": "@redact-secret/wasm", "version": "0.1.0-beta.1"}, indent=2
                )
                + "\n",
            )
        if self.include_wrapper_manifest:
            self.write(
                "packages/javascript/package.json",
                json.dumps(
                    {"name": "@redact-secret/core", "version": self.wrapper_version}, indent=2
                )
                + "\n",
            )
        return self.root

    def artifacts(self, directory: Path, present: set[str] | None = None) -> Path:
        """A downloaded-artifact tree naming one directory per expected
        artifact; `present` restricts which ones actually exist, defaulting
        to every declared target plus `wasm-web` and its `wasm-web-common`
        companion."""
        names = present
        if names is None:
            names = {f"node-addon-{target}" for target in self.targets} | {
                "wasm-web",
                "wasm-web-common",
            }
        for name in names:
            (directory / name).mkdir(parents=True, exist_ok=True)
        return directory


class PlanTests(unittest.TestCase):
    def build_plan(self, configure=None, artifact_names=None) -> dict:
        with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as artifacts_dir:
            repository = Repository(Path(repo_dir))
            if configure is not None:
                configure(repository)
            root = repository.build()
            artifacts = repository.artifacts(Path(artifacts_dir), artifact_names)
            with unittest.mock.patch.dict(
                os.environ, {"SOURCE_COMMIT": "abc123", "GITHUB_SHA": ""}, clear=False
            ):
                return RECORD.build_plan(root, artifacts), artifacts

    def test_a_complete_repository_resolves_every_dependency(self) -> None:
        plan, artifacts = self.build_plan()
        self.assertEqual(len(plan["dependencies"]), 3)  # two native + wasm
        self.assertEqual(RECORD.plan_errors(plan, artifacts), [])

    def test_dependencies_are_ordered_native_then_wasm(self) -> None:
        plan, _ = self.build_plan()
        kinds = [entry["kind"] for entry in plan["dependencies"]]
        self.assertEqual(kinds, ["native", "native", "wasm"])

    def test_each_native_entry_carries_its_declared_package_and_version(self) -> None:
        plan, _ = self.build_plan()
        entry = next(
            e for e in plan["dependencies"] if e["target"] == "aarch64-apple-darwin"
        )
        self.assertEqual(entry["package"], "@redact-secret/node-darwin-arm64")
        self.assertEqual(entry["version"], "0.1.0-beta.1")
        self.assertEqual(entry["expectedArtifact"], "node-addon-aarch64-apple-darwin")
        self.assertTrue(entry["artifactPresent"])

    def test_the_wrapper_is_gated_on_every_dependency_package(self) -> None:
        plan, _ = self.build_plan()
        self.assertEqual(plan["wrapper"]["package"], "@redact-secret/core")
        self.assertEqual(
            sorted(plan["wrapper"]["gatedOn"]),
            sorted(
                [
                    "@redact-secret/node-darwin-arm64",
                    "@redact-secret/node-linux-x64-gnu",
                    "@redact-secret/wasm",
                ]
            ),
        )

    def test_a_missing_native_artifact_is_reported_as_an_error(self) -> None:
        plan, artifacts = self.build_plan(
            artifact_names={"node-addon-x86_64-unknown-linux-gnu", "wasm-web", "wasm-web-common"}
        )
        errors = RECORD.plan_errors(plan, artifacts)
        self.assertEqual(
            errors,
            [f"node-addon-aarch64-apple-darwin: no qualified artifact in {artifacts}"],
        )

    def test_a_missing_wasm_artifact_is_reported_as_an_error(self) -> None:
        plan, artifacts = self.build_plan(
            artifact_names={f"node-addon-{target}" for target in TARGETS} | {"wasm-web-common"}
        )
        errors = RECORD.plan_errors(plan, artifacts)
        self.assertEqual(errors, [f"wasm-web: no qualified artifact in {artifacts}"])

    def test_a_missing_wasm_common_companion_artifact_is_reported_as_an_error(self) -> None:
        plan, artifacts = self.build_plan(
            artifact_names={f"node-addon-{target}" for target in TARGETS} | {"wasm-web"}
        )
        entry = next(e for e in plan["dependencies"] if e["kind"] == "wasm")
        self.assertEqual(entry["companionArtifact"], "wasm-web-common")
        self.assertFalse(entry["companionArtifactPresent"])
        errors = RECORD.plan_errors(plan, artifacts)
        self.assertEqual(
            errors, [f"wasm-web-common: no qualified companion artifact in {artifacts}"]
        )

    def test_the_wasm_entry_carries_its_companion_artifact_name(self) -> None:
        plan, _ = self.build_plan()
        entry = next(e for e in plan["dependencies"] if e["kind"] == "wasm")
        self.assertEqual(entry["companionArtifact"], "wasm-web-common")
        self.assertTrue(entry["companionArtifactPresent"])

    def test_a_native_package_with_no_manifest_is_unresolved(self) -> None:
        def configure(repository: Repository) -> None:
            repository.include_native_manifests = False

        plan, artifacts = self.build_plan(configure)
        errors = RECORD.plan_errors(plan, artifacts)
        self.assertEqual(
            errors,
            [
                "node-addon-aarch64-apple-darwin: no dependency package manifest resolved for it",
                "node-addon-x86_64-unknown-linux-gnu: no dependency package manifest resolved for it",
            ],
        )

    def test_no_declared_targets_yields_only_the_wasm_dependency(self) -> None:
        def configure(repository: Repository) -> None:
            repository.targets = []

        plan, artifacts = self.build_plan(
            configure, artifact_names={"wasm-web", "wasm-web-common"}
        )
        self.assertEqual(len(plan["dependencies"]), 1)
        self.assertEqual(plan["dependencies"][0]["kind"], "wasm")
        self.assertEqual(RECORD.plan_errors(plan, artifacts), [])


if __name__ == "__main__":
    unittest.main()
