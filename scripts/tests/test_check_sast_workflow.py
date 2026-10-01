from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-sast-workflow.py"
SPEC = importlib.util.spec_from_file_location("check_sast_workflow", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

REPO_ROOT = Path(__file__).resolve().parents[2]

GOOD_WORKFLOW = """\
name: SAST

on:
  pull_request:
  push:
    branches:
      - main

permissions: {}

jobs:
  opengrep:
    name: OpenGrep (pinned baseline)
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Check out repository
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0

      - name: Run the pinned, provenance-verified OpenGrep scan
        id: scan
        continue-on-error: true
        run: python3 -B scripts/run-sast.py --out out.json --sarif-out sast/reports/ci-latest.sarif

      - name: Upload SARIF to code scanning
        id: upload
        if: always()
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0
        with:
          sarif_file: sast/reports/ci-latest.sarif
          wait-for-processing: true

      - name: Synchronize reviewed SARIF suppressions
        if: github.ref == 'refs/heads/main' && steps.upload.outcome == 'success'
        continue-on-error: true
        uses: advanced-security/dismiss-alerts@a18f986bdb40edba0dd7a74382c15d4a3d50a1c8 # v2.0.3
        with:
          sarif-id: ${{ steps.upload.outputs.sarif-id }}
          sarif-file: sast/reports/ci-latest.sarif
        env:
          GITHUB_TOKEN: ${{ github.token }}

      - name: Enforce scan result
        if: always()
        run: |
          if [ "${{ steps.scan.outcome }}" != "success" ]; then
            exit 1
          fi
"""


def write(tmp: Path, text: str) -> Path:
    workflows = tmp / ".github" / "workflows"
    workflows.mkdir(parents=True)
    path = workflows / "sast.yml"
    path.write_text(text, encoding="utf-8")
    return tmp


class SastWorkflowCheckTest(unittest.TestCase):
    def test_this_repository_satisfies_every_check(self) -> None:
        self.assertEqual(CHECK.validate(REPO_ROOT), [])

    def test_missing_workflow_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            errors = CHECK.validate(Path(root))
            self.assertTrue(any("missing workflow" in error for error in errors))

    def test_well_formed_workflow_passes(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            root = write(Path(root_dir), GOOD_WORKFLOW)
            self.assertEqual(CHECK.validate(root), [])

    def test_missing_pull_request_trigger_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("  pull_request:\n", "")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("pull_request" in error for error in errors))

    def test_missing_timeout_minutes_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("    timeout-minutes: 20\n", "")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("timeout-minutes" in error for error in errors))

    def test_scan_step_without_continue_on_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "        continue-on-error: true\n        run: python3", "        run: python3"
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("id: scan) must declare continue-on-error" in error for error in errors))

    def test_scan_step_with_wrong_sarif_output_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "--sarif-out sast/reports/ci-latest.sarif",
                "--sarif-out other.sarif",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must generate SARIF at" in error for error in errors))

    def test_enforce_step_checking_conclusion_instead_of_outcome_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("steps.scan.outcome", "steps.scan.conclusion")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("checks steps.scan.conclusion" in error for error in errors))
            self.assertTrue(any("no step checks steps.scan.outcome" in error for error in errors))

    def test_sarif_upload_without_continue_on_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "        if: always()\n        continue-on-error: true\n        uses: github/codeql-action",
                "        if: always()\n        uses: github/codeql-action",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("uploads SARIF but lacks continue-on-error" in error for error in errors))

    def test_sarif_upload_without_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("        id: upload\n", "")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("lacks id: upload" in error for error in errors))

    def test_sarif_upload_without_processing_wait_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("          wait-for-processing: true\n", "")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("wait-for-processing: true" in error for error in errors))

    def test_sarif_upload_with_wrong_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "          sarif_file: sast/reports/ci-latest.sarif\n",
                "          sarif_file: other.sarif\n",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must upload the generated SARIF path" in error for error in errors))

    def test_sarif_upload_without_always_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "        id: upload\n        if: always()\n",
                "        id: upload\n",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("lacks if: always()" in error for error in errors))

    def test_missing_sarif_upload_step_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.split("      - name: Upload SARIF to code scanning")[0] + (
                "      - name: Enforce scan result\n"
                "        if: always()\n"
                '        run: echo "${{ steps.scan.outcome }}"\n'
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("no step uploads SARIF" in error for error in errors))

    def test_missing_dismissal_step_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            before, remainder = GOOD_WORKFLOW.split("      - name: Synchronize reviewed SARIF suppressions\n", 1)
            _, after = remainder.split("      - name: Enforce scan result\n", 1)
            root = write(Path(root_dir), before + "      - name: Enforce scan result\n" + after)
            errors = CHECK.validate(root)
            self.assertTrue(any("no step synchronizes SARIF suppressions" in error for error in errors))

    def test_unpinned_dismissal_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "advanced-security/dismiss-alerts@a18f986bdb40edba0dd7a74382c15d4a3d50a1c8",
                "advanced-security/dismiss-alerts@v2",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must pin dismiss-alerts" in error for error in errors))

    def test_dismissal_without_continue_on_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "        if: github.ref == 'refs/heads/main' && steps.upload.outcome == 'success'\n"
                "        continue-on-error: true\n",
                "        if: github.ref == 'refs/heads/main' && steps.upload.outcome == 'success'\n",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("synchronizes suppressions but lacks" in error for error in errors))

    def test_dismissal_outside_main_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "github.ref == 'refs/heads/main' && ",
                "",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must run only on refs/heads/main" in error for error in errors))

    def test_dismissal_without_successful_upload_guard_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                " && steps.upload.outcome == 'success'",
                "",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must require a successful processed SARIF upload" in error for error in errors))

    def test_dismissal_with_wrong_sarif_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "${{ steps.upload.outputs.sarif-id }}",
                "${{ steps.other.outputs.sarif-id }}",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must consume steps.upload.outputs.sarif-id" in error for error in errors))

    def test_dismissal_with_wrong_sarif_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace(
                "          sarif-file: sast/reports/ci-latest.sarif\n",
                "          sarif-file: other.sarif\n",
            )
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must read the generated SARIF path" in error for error in errors))

    def test_dismissal_without_github_token_fails(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            broken = GOOD_WORKFLOW.replace("          GITHUB_TOKEN: ${{ github.token }}\n", "")
            root = write(Path(root_dir), broken)
            errors = CHECK.validate(root)
            self.assertTrue(any("must receive GITHUB_TOKEN" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
