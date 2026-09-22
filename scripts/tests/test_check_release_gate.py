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

  artifact-qualification:
    name: Artifact qualification
    uses: ./.github/workflows/artifact-qualification.yml
    permissions:
      contents: read

  publish-native-dependencies:
    name: Publish npm dependency
    runs-on: ubuntu-latest
    needs: [ci, artifact-qualification]
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
    needs: [ci, artifact-qualification]
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

      - name: Verify the root artifact reports the full profile
        shell: bash
        run: |
          node --input-type=module <<'NODE_VERIFY'
          import { readFileSync } from "node:fs";
          import init, { profile } from "./bindings/wasm/npm/redact_secret_wasm.js";
          import initCommon, { profile as profileCommon } from "./bindings/wasm/npm/redact_secret_wasm_common.js";
          await init(readFileSync("./bindings/wasm/npm/redact_secret_wasm_bg.wasm"));
          if (profile() !== "full") { throw new Error("not full"); }
          await initCommon(readFileSync("./bindings/wasm/npm/redact_secret_wasm_common_bg.wasm"));
          if (profileCommon() !== "common") { throw new Error("not common"); }
          NODE_VERIFY

      - name: Pack, content-check, publish, and verify
        run: echo noop

  publish:
    name: Publish to npm
    runs-on: ubuntu-latest
    needs:
      - ci
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
    needs: [ci, artifact-qualification]
    runs-on: ubuntu-latest
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

      - name: Publish redact-secret
        run: echo noop

      - name: Verify redact-secret publication matches the qualified crate
        run: python3 -B scripts/verify-crate-digest.py --inventory qualification-inventory/artifact-inventory.json --crate redact-secret --published-checksum deadbeef

      - name: Publish redact-secret-cli
        run: echo noop

      - name: Verify redact-secret-cli publication matches the qualified crate
        run: python3 -B scripts/verify-crate-digest.py --inventory qualification-inventory/artifact-inventory.json --crate redact-secret-cli --published-checksum deadbeef

  publish-pypi:
    name: Publish PyPI
    needs: [ci, artifact-qualification]
    runs-on: ubuntu-latest
    environment:
      name: release
    permissions:
      contents: read

    steps:
      - name: Check out repository
        run: echo noop

      - name: Verify published wheels match the qualified inventory
        run: python3 -B scripts/verify-python-digest.py --inventory qualification-inventory/artifact-inventory.json dist/*

      - name: Publish to PyPI
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
            "    needs:\n      - ci\n      - artifact-qualification\n",
            "    needs:\n      - artifact-qualification\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(any("does not need ci" in error for error in errors))

    def test_publish_not_needing_artifact_qualification_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "    needs:\n      - ci\n      - artifact-qualification\n",
            "    needs:\n      - ci\n",
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
            "  publish-crates:\n    name: Publish crates.io\n    needs: [ci, artifact-qualification]\n",
            "  publish-crates:\n    name: Publish crates.io\n    needs: [ci]\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any("publish-crates job does not need artifact-qualification" in error for error in errors)
        )

    def test_publish_pypi_not_needing_a_gate_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "  publish-pypi:\n    name: Publish PyPI\n    needs: [ci, artifact-qualification]\n",
            "  publish-pypi:\n    name: Publish PyPI\n    needs: [ci]\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "publish-pypi job does not need artifact-qualification" in error
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

    def test_missing_profile_verification_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Verify the root artifact reports the full profile\n"
            "        shell: bash\n"
            "        run: |\n"
            "          node --input-type=module <<'NODE_VERIFY'\n"
            "          import { readFileSync } from \"node:fs\";\n"
            "          import init, { profile } from \"./bindings/wasm/npm/redact_secret_wasm.js\";\n"
            "          import initCommon, { profile as profileCommon } from \"./bindings/wasm/npm/redact_secret_wasm_common.js\";\n"
            "          await init(readFileSync(\"./bindings/wasm/npm/redact_secret_wasm_bg.wasm\"));\n"
            "          if (profile() !== \"full\") { throw new Error(\"not full\"); }\n"
            "          await initCommon(readFileSync(\"./bindings/wasm/npm/redact_secret_wasm_common_bg.wasm\"));\n"
            "          if (profileCommon() !== \"common\") { throw new Error(\"not common\"); }\n"
            "          NODE_VERIFY\n\n",
            "",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Verify the root artifact reports the full profile' step" in error
                for error in errors
            )
        )

    def test_missing_wasm_publish_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Pack, content-check, publish, and verify\n        run: echo noop\n\n",
            "",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Pack, content-check, publish, and verify' step" in error
                for error in errors
            )
        )

    def test_profile_verification_step_after_publish_step_is_an_error(self) -> None:
        verify_step = (
            "      - name: Verify the root artifact reports the full profile\n"
            "        shell: bash\n"
            "        run: |\n"
            "          node --input-type=module <<'NODE_VERIFY'\n"
            "          import { readFileSync } from \"node:fs\";\n"
            "          import init, { profile } from \"./bindings/wasm/npm/redact_secret_wasm.js\";\n"
            "          import initCommon, { profile as profileCommon } from \"./bindings/wasm/npm/redact_secret_wasm_common.js\";\n"
            "          await init(readFileSync(\"./bindings/wasm/npm/redact_secret_wasm_bg.wasm\"));\n"
            "          if (profile() !== \"full\") { throw new Error(\"not full\"); }\n"
            "          await initCommon(readFileSync(\"./bindings/wasm/npm/redact_secret_wasm_common_bg.wasm\"));\n"
            "          if (profileCommon() !== \"common\") { throw new Error(\"not common\"); }\n"
            "          NODE_VERIFY\n\n"
        )
        publish_step = "      - name: Pack, content-check, publish, and verify\n        run: echo noop\n\n"
        broken = RELEASE_YML.replace(verify_step + publish_step, publish_step + verify_step)
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "must precede 'Pack, content-check, publish, and verify'" in error
                for error in errors
            )
        )

    def test_profile_verification_step_not_asserting_full_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            'if (profile() !== "full") { throw new Error("not full"); }\n',
            "\n",
        )
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any('does not assert the root artifact reports "full"' in error for error in errors)
        )

    def test_profile_verification_step_not_asserting_common_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "          await initCommon(readFileSync(\"./bindings/wasm/npm/redact_secret_wasm_common_bg.wasm\"));\n"
            '          if (profileCommon() !== "common") { throw new Error("not common"); }\n',
            "",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                'does not assert the common artifact reports "common"' in error
                for error in errors
            )
        )

    def test_missing_publish_pypi_job_is_missing_error_for_digest_step(self) -> None:
        broken = RELEASE_YML[: RELEASE_YML.index("  publish-pypi:")]
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        # Already covered by test_missing_publish_pypi_job_is_an_error, but the
        # digest-step checks must not also fire a confusing second error for a
        # job that does not exist.
        self.assertFalse(any("is missing the 'Verify published wheels" in error for error in errors))

    def test_missing_pypi_digest_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Verify published wheels match the qualified inventory\n"
            "        run: python3 -B scripts/verify-python-digest.py --inventory qualification-inventory/artifact-inventory.json dist/*\n\n",
            "",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Verify published wheels match the qualified inventory' step" in error
                for error in errors
            )
        )

    def test_missing_pypi_publish_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Publish to PyPI\n        run: echo noop\n",
            "",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Publish to PyPI' step" in error
                for error in errors
            )
        )

    def test_pypi_digest_step_after_publish_step_is_an_error(self) -> None:
        digest_step = (
            "      - name: Verify published wheels match the qualified inventory\n"
            "        run: python3 -B scripts/verify-python-digest.py --inventory qualification-inventory/artifact-inventory.json dist/*\n\n"
        )
        publish_step = "      - name: Publish to PyPI\n        run: echo noop\n"
        broken = RELEASE_YML.replace(digest_step + publish_step, publish_step + "\n" + digest_step)
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "'Verify published wheels match the qualified inventory' must precede "
                "'Publish to PyPI'" in error
                for error in errors
            )
        )

    def test_pypi_digest_step_not_running_the_script_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "python3 -B scripts/verify-python-digest.py --inventory qualification-inventory/artifact-inventory.json dist/*",
            "echo noop",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "does not run scripts/verify-python-digest.py" in error
                for error in errors
            )
        )

    def test_missing_crate_digest_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Verify redact-secret publication matches the qualified crate\n"
            "        run: python3 -B scripts/verify-crate-digest.py --inventory qualification-inventory/artifact-inventory.json --crate redact-secret --published-checksum deadbeef\n\n",
            "",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Verify redact-secret publication matches the qualified crate' step" in error
                for error in errors
            )
        )

    def test_missing_crate_publish_step_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "      - name: Publish redact-secret-cli\n        run: echo noop\n\n",
            "",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "is missing the 'Publish redact-secret-cli' step" in error
                for error in errors
            )
        )

    def test_crate_digest_step_before_publish_step_is_an_error(self) -> None:
        digest_step = (
            "      - name: Verify redact-secret publication matches the qualified crate\n"
            "        run: python3 -B scripts/verify-crate-digest.py --inventory qualification-inventory/artifact-inventory.json --crate redact-secret --published-checksum deadbeef\n\n"
        )
        publish_step = "      - name: Publish redact-secret\n        run: echo noop\n\n"
        broken = RELEASE_YML.replace(publish_step + digest_step, digest_step + publish_step)
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "'Verify redact-secret publication matches the qualified crate' must follow "
                "'Publish redact-secret'" in error
                for error in errors
            )
        )

    def test_crate_digest_step_not_running_the_script_is_an_error(self) -> None:
        broken = RELEASE_YML.replace(
            "python3 -B scripts/verify-crate-digest.py --inventory qualification-inventory/artifact-inventory.json --crate redact-secret --published-checksum deadbeef",
            "echo noop",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertTrue(
            any(
                "does not run scripts/verify-crate-digest.py" in error
                for error in errors
            )
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

    def test_inline_needs_output_in_run_block_is_an_error(self) -> None:
        # Issue #614: an apostrophe in a job output ended this quoted string.
        broken = RELEASE_YML.replace(
            "      - name: Publish to PyPI\n        run: echo noop\n",
            "      - name: Publish to PyPI\n"
            "        run: |\n"
            "          echo start\n"
            "\n"
            "          wasm_json='${{ needs.publish-wasm-dependency.outputs.registry_state_json }}'\n",
        )
        self.assertNotEqual(broken, RELEASE_YML)
        self._write("release.yml", broken)
        errors = CHECK.validate(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("substitutes a `${{ needs.* }}` job output inline", errors[0])

    def test_inline_needs_output_in_one_line_run_is_an_error(self) -> None:
        self._write(
            "reconcile-release.yml",
            "name: Reconcile Release\n"
            "jobs:\n"
            "  reconcile:\n"
            "    steps:\n"
            "      - run: |\n"
            '          chmod 0644 "$package_dir"/$asset_glob\n'
            "      - run: echo \"${{ needs.reconcile.outputs.source_revision }}\"\n",
        )
        errors = CHECK.validate(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("reconcile-release.yml:7:", errors[0])

    def test_needs_output_through_env_is_accepted(self) -> None:
        passing = RELEASE_YML.replace(
            "      - name: Publish to PyPI\n        run: echo noop\n",
            "      - name: Publish to PyPI\n"
            "        if: ${{ needs.publish-wasm-dependency.result == 'success' }}\n"
            "        env:\n"
            "          WASM_JSON: ${{ needs.publish-wasm-dependency.outputs.registry_state_json }}\n"
            "        run: |\n"
            '          wasm_json="$WASM_JSON"\n',
        )
        self.assertNotEqual(passing, RELEASE_YML)
        self._write("release.yml", passing)
        self.assertEqual(CHECK.validate(self.root), [])

    def test_repository_release_workflows_have_no_inline_needs_outputs(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        for workflow in CHECK.INLINE_NEEDS_WORKFLOWS:
            self.assertEqual(
                CHECK.inline_needs_in_run((repo / workflow).read_text(encoding="utf-8")),
                [],
                workflow,
            )


if __name__ == "__main__":
    unittest.main()
