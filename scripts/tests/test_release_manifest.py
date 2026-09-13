from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import textwrap
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "release-manifest.py"
SPEC = importlib.util.spec_from_file_location("release_manifest", SCRIPT)
assert SPEC and SPEC.loader
RELEASE_MANIFEST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RELEASE_MANIFEST
SPEC.loader.exec_module(RELEASE_MANIFEST)


VALID_FIELDS = dict(
    source_revision="a" * 40,
    conformance_identity="b" * 40,
    version="0.1.0-beta.1",
    artifact_set=["npm:@redact-secret/core"],
    registry_state={"npm": "published"},
)


class BuildManifestTests(unittest.TestCase):
    def test_carries_all_five_fields(self) -> None:
        manifest = RELEASE_MANIFEST.build_manifest(**VALID_FIELDS)
        self.assertEqual(
            set(manifest),
            {
                "source_revision",
                "conformance_identity",
                "version",
                "artifact_set",
                "registry_state",
            },
        )
        self.assertEqual(manifest["source_revision"], VALID_FIELDS["source_revision"])
        self.assertEqual(manifest["artifact_set"], ["npm:@redact-secret/core"])
        self.assertEqual(manifest["registry_state"], {"npm": "published"})

    def test_rejects_each_missing_field(self) -> None:
        for field, empty in (
            ("source_revision", ""),
            ("conformance_identity", ""),
            ("version", ""),
            ("artifact_set", []),
            ("registry_state", {}),
        ):
            with self.subTest(field=field):
                fields = dict(VALID_FIELDS, **{field: empty})
                with self.assertRaises(ValueError):
                    RELEASE_MANIFEST.build_manifest(**fields)

    def test_artifact_set_and_registry_state_are_sorted(self) -> None:
        manifest = RELEASE_MANIFEST.build_manifest(
            **dict(
                VALID_FIELDS,
                artifact_set=["npm:b", "npm:a"],
                registry_state={"pypi": "unpublished", "npm": "published"},
            )
        )
        self.assertEqual(manifest["artifact_set"], ["npm:a", "npm:b"])
        self.assertEqual(list(manifest["registry_state"]), ["npm", "pypi"])


class CliTests(unittest.TestCase):
    def test_writes_the_manifest_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "manifest.json"
            status = RELEASE_MANIFEST.main(
                [
                    "--source-revision",
                    VALID_FIELDS["source_revision"],
                    "--conformance-identity",
                    VALID_FIELDS["conformance_identity"],
                    "--version",
                    VALID_FIELDS["version"],
                    "--artifact",
                    "npm:@redact-secret/core",
                    "--registry-state",
                    "npm=published",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 0)
            recorded = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(recorded["version"], VALID_FIELDS["version"])
            self.assertEqual(recorded["registry_state"], {"npm": "published"})

    def test_fails_without_writing_when_a_field_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "manifest.json"
            status = RELEASE_MANIFEST.main(
                [
                    "--source-revision",
                    "",
                    "--conformance-identity",
                    VALID_FIELDS["conformance_identity"],
                    "--version",
                    VALID_FIELDS["version"],
                    "--artifact",
                    "npm:@redact-secret/core",
                    "--registry-state",
                    "npm=published",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertFalse(out.exists())

    def test_registry_state_requires_name_equals_state(self) -> None:
        with self.assertRaises(ValueError):
            RELEASE_MANIFEST._parse_registry_state(["npm"])


class WorkflowOutputTests(unittest.TestCase):
    """Execute the real workflow shell with only registry commands stubbed."""

    def _report_steps(self) -> list[tuple[str, str]]:
        root = SCRIPT.parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text()
        steps = re.split(r"^      - name: ", workflow, flags=re.M)
        report_steps = []
        for step in steps:
            if not step.startswith("Report "):
                continue
            shell = step.split("        run: |\n", 1)[1]
            shell = re.split(r"^  [^ ]", shell, maxsplit=1, flags=re.M)[0]
            shell = textwrap.dedent(shell)
            shell = re.sub(r"\$\{\{.*?\}\}", "0.1.0-beta.1", shell)
            report_steps.append((step.splitlines()[0], shell))
        self.assertEqual(len(report_steps), 5)
        return report_steps

    def _workflow_workspace(self, directory: Path) -> None:
        root = SCRIPT.parents[1]
        (directory / "scripts").symlink_to(root / "scripts", target_is_directory=True)
        (directory / "packages").symlink_to(root / "packages", target_is_directory=True)
        node_platform = directory / "bindings/node/npm/0.1.0-beta.1"
        node_platform.mkdir(parents=True)
        node_platform.joinpath("package.json").write_text(
            json.dumps({"name": "@redact-secret/node-synthetic", "version": "0.1.0-beta.1"}),
            encoding="utf-8",
        )
        wasm = directory / "bindings/wasm"
        wasm.mkdir(parents=True)
        wasm.joinpath("npm").symlink_to(root / "bindings/wasm/npm", target_is_directory=True)

    def _write_registry_stubs(self, directory: Path) -> None:
        real_node = shutil.which("node")
        self.assertIsNotNone(real_node)
        directory.joinpath("curl").write_text(
            "#!/bin/sh\n"
            "if [ \"${CURL_STATUS:-404}\" = transport ]; then exit 7; fi\n"
            "printf '%s' \"${CURL_STATUS:-404}\"\n",
            encoding="utf-8",
        )
        directory.joinpath("node").write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  scripts/npm-registry-metadata.mjs|*/scripts/npm-registry-metadata.mjs)\n"
            "    case \"${NPM_METADATA_STATE:-unpublished}\" in\n"
            "      published) printf '%040d\\n' 0 ;;\n"
            "      unpublished) printf 'unpublished\\n' ;;\n"
            "      malformed|failure) exit 1 ;;\n"
            "    esac\n"
            "    exit 0\n"
            "    ;;\n"
            "esac\n"
            f"exec {real_node!s} \"$@\"\n",
            encoding="utf-8",
        )
        for name in ("curl", "node"):
            directory.joinpath(name).chmod(0o755)

    def _run_report_step(self, name: str, shell: str, directory: Path, *, npm_state: str, curl_status: str) -> dict[str, str]:
        output = directory / "output"
        output.write_text("")
        registry_state = directory / "registry-state.json"
        registry_state.unlink(missing_ok=True)
        subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", shell],
            cwd=directory,
            env={
                **os.environ,
                "PATH": f"{directory}:{os.environ['PATH']}",
                "GITHUB_OUTPUT": str(output),
                "NPM_METADATA_STATE": npm_state,
                "CURL_STATUS": curl_status,
            },
            check=True,
            capture_output=True,
        )
        if registry_state.exists():
            return json.loads(registry_state.read_text())
        lines = output.read_text().splitlines()
        self.assertEqual(len(lines), 1, name)
        key, value = lines[0].split("=", 1)
        self.assertEqual(key, "registry_state_json")
        return json.loads(value)

    def test_registry_outputs_are_single_line_json(self) -> None:
        checked = 0
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self._workflow_workspace(directory)
            self._write_registry_stubs(directory)
            for name, shell in self._report_steps():
                with self.subTest(step=name):
                    state = self._run_report_step(name, shell, directory, npm_state="unpublished", curl_status="404")
                    self.assertTrue(state)
                    self.assertEqual(set(state.values()), {"unpublished"})
                    checked += 1
        self.assertEqual(checked, 5)

    def test_registry_reporters_only_treat_exact_absence_as_unpublished(self) -> None:
        cases = [
            ("published", "200", "published"),
            ("unpublished", "404", "unpublished"),
            ("failure", "401", "unknown"),
            ("failure", "403", "unknown"),
            ("failure", "429", "unknown"),
            ("failure", "500", "unknown"),
            ("failure", "transport", "unknown"),
            ("malformed", "200", "unknown"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self._workflow_workspace(directory)
            self._write_registry_stubs(directory)
            for npm_state, curl_status, expected in cases:
                for name, shell in self._report_steps():
                    with self.subTest(step=name, npm_state=npm_state, curl_status=curl_status):
                        state = self._run_report_step(name, shell, directory, npm_state=npm_state, curl_status=curl_status)
                        self.assertTrue(state)
                        uses_npm_helper = name in {"Report registry state", "Report npm registry state"}
                        step_expected = expected
                        if npm_state == "malformed" and not uses_npm_helper:
                            step_expected = "published"
                        self.assertEqual(set(state.values()), {step_expected})

    def test_manifest_records_whole_product_when_publishers_are_skipped(self) -> None:
        root = SCRIPT.parents[1]
        workflow = (root / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Build and record the manifest\n", 1)[1]
        shell = step.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        shell = textwrap.dedent(shell)
        shell = re.sub(r"\$\{\{.*?\}\}", "", shell)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "packages").symlink_to(root / "packages", target_is_directory=True)
            (directory / "scripts").symlink_to(root / "scripts", target_is_directory=True)
            subprocess.run(["bash", "-e", "-o", "pipefail", "-c", shell], cwd=directory,
                           env={**os.environ, "GITHUB_SHA": "a" * 40,
                                "GITHUB_OUTPUT": str(directory / "output")},
                           check=True, capture_output=True)
            manifest = json.loads((directory / "manifest.json").read_text())
            self.assertEqual(len(manifest["artifact_set"]), 11)
            self.assertEqual(set(manifest["artifact_set"]), set(manifest["registry_state"]))
            self.assertEqual(set(manifest["registry_state"].values()), {"unknown"})
            self.assertIn("pypi:redact-secret", manifest["artifact_set"])
            self.assertIn("crate:redact-secret-cli", manifest["artifact_set"])


if __name__ == "__main__":
    unittest.main()
