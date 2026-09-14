from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-release-gate.py"
SPEC = importlib.util.spec_from_file_location("check_release_gate", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

RELEASE_YML = """\
name: Release

on:
  workflow_dispatch:

permissions: {}

jobs:
  ci:
    name: CI
    uses: ./.github/workflows/ci.yml
    permissions:
      contents: read

  python-wheels:
    name: Python wheels
    uses: ./.github/workflows/python-wheels.yml
    permissions:
      contents: read

  artifact-qualification:
    name: Artifact qualification
    uses: ./.github/workflows/artifact-qualification.yml
    permissions:
      contents: read

  publish-native-dependencies:
    name: Publish npm dependency
    runs-on: ubuntu-latest
    needs: [ci, python-wheels, artifact-qualification]
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

  publish-wasm-dependency:
    name: Publish npm dependency (wasm)
    runs-on: ubuntu-latest
    needs: [ci, python-wheels, artifact-qualification]
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

  publish:
    name: Publish to npm
    runs-on: ubuntu-latest
    needs:
      - ci
      - python-wheels
      - artifact-qualification
      - publish-native-dependencies
      - publish-wasm-dependency
    environment:
      name: release
    permissions:
      contents: write

    steps:
      - name: Check out repository
        run: echo noop

  publish-crates:
    name: Publish crates.io
    needs: [ci, python-wheels, artifact-qualification]
    runs-on: ubuntu-latest
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

  publish-pypi:
    name: Publish PyPI
    needs: [ci, python-wheels, artifact-qualification]
    runs-on: ubuntu-latest
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop
"""

CI_YML = """\
name: CI

on:
  pull_request:
  push:
    branches:
      - main
  workflow_call:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo noop
"""

WHEELS_YML = """\
name: Python wheels

on:
  workflow_call:

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - run: echo noop
"""

ARTIFACT_QUALIFICATION_YML = """\
name: Artifact qualification

on:
  workflow_call:

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - run: echo noop
"""


class ReleaseGateTests(unittest.TestCase):
    """A fully-wired repository has no errors; each way of un-wiring it does."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self._write("release.yml", RELEASE_YML)
        self._write("ci.yml", CI_YML)
        self._write("python-wheels.yml", WHEELS_YML)
        self._write("artifact-qualification.yml", ARTIFACT_QUALIFICATION_YML)

    def _write(self, name: str, content: str) -> Path:
        path = self.root / ".github" / "workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_fully_wired_repository_has_no_errors(self) -> None:
        self.assertEqual(CHECK.validate(self.root), [])

    def test_missing_release_workflow_is_an_error(self) -> None:
        (self.root / ".github" / "workflows" / "release.yml").unlink()
        errors = CHECK.validate(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("missing release workflow", errors[0])

    def test_publish_not_needing_ci_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "    needs:\n      - ci\n      - python-wheels\n",
            "    needs:\n      - python-wheels\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("does not need ci" in error for error in errors))

    def test_publish_not_needing_python_wheels_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "    needs:\n      - ci\n      - python-wheels\n",
            "    needs:\n      - ci\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("does not need python-wheels" in error for error in errors))

    def test_publish_not_needing_artifact_qualification_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "    needs:\n      - ci\n      - python-wheels\n      - artifact-qualification\n",
            "    needs:\n      - ci\n      - python-wheels\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("does not need artifact-qualification" in error for error in errors))

    def test_removing_the_ci_gate_job_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "  ci:\n    name: CI\n    uses: ./.github/workflows/ci.yml\n    permissions:\n      contents: read\n\n",
            "",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("missing required gate job 'ci'" in error for error in errors))

    def test_repointing_a_gate_jobs_uses_target_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "uses: ./.github/workflows/ci.yml",
            "uses: ./.github/workflows/some-other-workflow.yml",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("must call ./.github/workflows/ci.yml" in error for error in errors))

    def test_dropping_workflow_call_from_a_called_workflow_is_an_error(self) -> None:
        broken = CI_YML.replace("  workflow_call:\n", "")
        self._write("ci.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("does not expose workflow_call" in error for error in errors))

    def test_missing_publish_job_is_an_error(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish:")]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("missing publish job" in error for error in errors))

    def test_publish_crates_not_needing_a_gate_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "  publish-crates:\n    name: Publish crates.io\n    needs: [ci, python-wheels, artifact-qualification]\n",
            "  publish-crates:\n    name: Publish crates.io\n    needs: [ci, python-wheels]\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("publish-crates job does not need artifact-qualification" in error for error in errors)
        )

    def test_publish_pypi_not_needing_a_gate_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "  publish-pypi:\n    name: Publish PyPI\n    needs: [ci, python-wheels, artifact-qualification]\n",
            "  publish-pypi:\n    name: Publish PyPI\n    needs: [ci]\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "publish-pypi job does not need artifact-qualification, python-wheels" in error
                for error in errors
            )
        )

    def test_missing_publish_crates_job_is_an_error(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish-crates:")] + RELEASE_YML[RELEASE_YML.index("  publish-pypi:") :]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("missing publish-crates job" in error for error in errors))

    def test_missing_publish_pypi_job_is_an_error(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish-pypi:")]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("missing publish-pypi job" in error for error in errors))

    def test_publish_not_needing_native_dependencies_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - publish-native-dependencies\n      - publish-wasm-dependency\n",
            "      - publish-wasm-dependency\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "publish job does not need publish-native-dependencies" in error
                for error in errors
            )
        )

    def test_publish_not_needing_wasm_dependency_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - publish-native-dependencies\n      - publish-wasm-dependency\n",
            "      - publish-native-dependencies\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("publish job does not need publish-wasm-dependency" in error for error in errors)
        )

    def test_missing_publish_native_dependencies_job_is_an_error(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish-native-dependencies:")] + RELEASE_YML[
            RELEASE_YML.index("  publish-wasm-dependency:") :
        ]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("missing required job 'publish-native-dependencies'" in error for error in errors)
        )

    def test_missing_publish_wasm_dependency_job_is_an_error(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish-wasm-dependency:")] + RELEASE_YML[
            RELEASE_YML.index("  publish:") :
        ]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("missing required job 'publish-wasm-dependency'" in error for error in errors)
        )

    def test_recovery_assets_must_be_normalized_before_npm_pack(self) -> None:
        self._write(
            "reconcile-release.yml",
            "name: Reconcile Release\n"
            "jobs:\n"
            "  reconcile:\n"
            "    steps:\n"
            "      - run: cp recovered/* package/\n",
        )

        errors = CHECK.validate(self.root)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("normalized to mode 0644", errors[0])

    def test_recovery_asset_mode_normalization_is_accepted(self) -> None:
        self._write(
            "reconcile-release.yml",
            "name: Reconcile Release\n"
            "jobs:\n"
            "  reconcile:\n"
            "    steps:\n"
            "      - run: |\n"
            '          chmod 0644 "$package_dir"/$asset_glob\n',
        )

        self.assertEqual(CHECK.validate(self.root), [])


if __name__ == "__main__":
    unittest.main()
