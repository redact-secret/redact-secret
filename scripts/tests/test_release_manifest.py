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


class NormalizeArtifactDigestsTests(unittest.TestCase):
    def test_matching_stages_produce_no_errors(self) -> None:
        digest = "a" * 64
        normalized, errors = RELEASE_MANIFEST.normalize_artifact_digests(
            {
                "pypi:redact-secret": [
                    {
                        "file": "redact_secret-0.1.0.tar.gz",
                        "built": digest,
                        "qualified": digest,
                        "published": digest,
                        "comparable": True,
                    }
                ]
            }
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["pypi:redact-secret"],
            [
                {
                    "file": "redact_secret-0.1.0.tar.gz",
                    "built": digest,
                    "qualified": digest,
                    "published": digest,
                    "comparable": True,
                    "note": None,
                }
            ],
        )

    def test_disagreeing_comparable_stages_are_an_error_naming_both_digests(self) -> None:
        qualified = "a" * 64
        published = "b" * 64
        _, errors = RELEASE_MANIFEST.normalize_artifact_digests(
            {
                "crate:redact-secret": [
                    {
                        "file": "redact-secret-0.1.0.crate",
                        "qualified": qualified,
                        "published": published,
                        "comparable": True,
                    }
                ]
            }
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("crate:redact-secret", errors[0])
        self.assertIn("redact-secret-0.1.0.crate", errors[0])
        self.assertIn(qualified, errors[0])
        self.assertIn(published, errors[0])

    def test_non_comparable_record_without_note_is_an_error(self) -> None:
        _, errors = RELEASE_MANIFEST.normalize_artifact_digests(
            {
                "npm:@redact-secret/wasm": [
                    {"file": "redact_secret_wasm_bg.wasm", "qualified": "a" * 64, "comparable": False}
                ]
            }
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("requires a note", errors[0])

    def test_non_comparable_record_with_note_is_accepted(self) -> None:
        normalized, errors = RELEASE_MANIFEST.normalize_artifact_digests(
            {
                "npm:@redact-secret/wasm": [
                    {
                        "file": "redact_secret_wasm_bg.wasm",
                        "built": "a" * 64,
                        "qualified": "a" * 64,
                        "published": "c" * 40,
                        "comparable": False,
                        "note": "npm repacks the artifact into a new tarball before publishing.",
                    }
                ]
            }
        )
        self.assertEqual(errors, [])
        self.assertEqual(normalized["npm:@redact-secret/wasm"][0]["published"], "c" * 40)

    def test_missing_stage_values_are_not_a_mismatch(self) -> None:
        _, errors = RELEASE_MANIFEST.normalize_artifact_digests(
            {
                "pypi:redact-secret": [
                    {"file": "redact_secret-0.1.0.tar.gz", "qualified": "a" * 64, "comparable": True}
                ]
            }
        )
        self.assertEqual(errors, [])

    def test_entry_must_be_a_list(self) -> None:
        _, errors = RELEASE_MANIFEST.normalize_artifact_digests({"pypi:redact-secret": {"file": "x"}})
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a list", errors[0])


VALID_DRIFT_SUMMARY = {"regressions": 0, "improvements": 1, "newAndUnclassified": 0, "staleProviderProvenance": 2}


class NormalizeSupportMatrixDriftTests(unittest.TestCase):
    def test_empty_value_is_recorded_as_empty_with_no_errors(self) -> None:
        normalized, errors = RELEASE_MANIFEST.normalize_support_matrix_drift({})
        self.assertEqual(normalized, {})
        self.assertEqual(errors, [])

    def test_well_formed_drift_record_passes_through_unchanged(self) -> None:
        drift = {"summary": VALID_DRIFT_SUMMARY, "regressions": []}
        normalized, errors = RELEASE_MANIFEST.normalize_support_matrix_drift(drift)
        self.assertEqual(normalized, drift)
        self.assertEqual(errors, [])

    def test_missing_summary_is_an_error(self) -> None:
        _, errors = RELEASE_MANIFEST.normalize_support_matrix_drift({"regressions": []})
        self.assertTrue(any("summary" in e for e in errors))

    def test_negative_summary_count_is_an_error(self) -> None:
        drift = {"summary": dict(VALID_DRIFT_SUMMARY, regressions=-1)}
        _, errors = RELEASE_MANIFEST.normalize_support_matrix_drift(drift)
        self.assertTrue(any("regressions" in e for e in errors))

    def test_non_integer_summary_count_is_an_error(self) -> None:
        drift = {"summary": dict(VALID_DRIFT_SUMMARY, improvements="1")}
        _, errors = RELEASE_MANIFEST.normalize_support_matrix_drift(drift)
        self.assertTrue(any("improvements" in e for e in errors))


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

    def test_defaults_artifact_digests_to_empty_object(self) -> None:
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
            self.assertEqual(recorded["artifact_digests"], {})

    def test_digest_mismatch_still_writes_the_manifest_but_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "manifest.json"
            digests = json.dumps(
                {
                    "crate:redact-secret": [
                        {
                            "file": "redact-secret-0.1.0.crate",
                            "qualified": "a" * 64,
                            "published": "b" * 64,
                            "comparable": True,
                        }
                    ]
                }
            )
            status = RELEASE_MANIFEST.main(
                [
                    "--source-revision",
                    VALID_FIELDS["source_revision"],
                    "--conformance-identity",
                    VALID_FIELDS["conformance_identity"],
                    "--version",
                    VALID_FIELDS["version"],
                    "--artifact",
                    "crate:redact-secret",
                    "--registry-state",
                    "crate=published",
                    "--artifact-digests",
                    digests,
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertTrue(out.exists())
            recorded = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(recorded["artifact_digests"]["crate:redact-secret"][0]["qualified"], "a" * 64)
            self.assertEqual(recorded["artifact_digests"]["crate:redact-secret"][0]["published"], "b" * 64)

    def test_invalid_artifact_digests_json_fails_without_writing(self) -> None:
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
                    "--artifact-digests",
                    "not json",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertFalse(out.exists())

    def test_defaults_support_matrix_drift_to_empty_object(self) -> None:
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
            self.assertEqual(recorded["support_matrix_drift"], {})

    def test_support_matrix_drift_is_recorded_alongside_the_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "manifest.json"
            drift = json.dumps({"summary": {"regressions": 1, "improvements": 0, "newAndUnclassified": 0, "staleProviderProvenance": 0}})
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
                    "--support-matrix-drift",
                    drift,
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 0)
            recorded = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(recorded["support_matrix_drift"]["summary"]["regressions"], 1)

    def test_malformed_support_matrix_drift_still_writes_the_manifest_but_fails(self) -> None:
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
                    "--support-matrix-drift",
                    '{"summary": {}}',
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertTrue(out.exists())

    def test_invalid_support_matrix_drift_json_fails_without_writing(self) -> None:
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
                    "--support-matrix-drift",
                    "not json",
                    "--out",
                    str(out),
                ]
            )
            self.assertEqual(status, 1)
            self.assertFalse(out.exists())


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
            self.assertEqual(len(manifest["artifact_set"]), 13)
            self.assertEqual(set(manifest["artifact_set"]), set(manifest["registry_state"]))
            self.assertEqual(set(manifest["registry_state"].values()), {"unknown"})
            self.assertIn("pypi:redact-secret", manifest["artifact_set"])
            self.assertIn("crate:redact-secret-cli", manifest["artifact_set"])


if __name__ == "__main__":
    unittest.main()
