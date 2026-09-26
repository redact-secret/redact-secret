from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "record-artifact-inventory.py"
SPEC = importlib.util.spec_from_file_location("record_artifact_inventory", SCRIPT)
assert SPEC and SPEC.loader
RECORD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RECORD
SPEC.loader.exec_module(RECORD)

MATRIX = {
    "node-addon-targets": ["aarch64-apple-darwin", "x86_64-unknown-linux-musl"],
    "cli-release-targets": ["aarch64-apple-darwin", "x86_64-pc-windows-msvc"],
    "python-wheel-targets": ["aarch64-apple-darwin"],
    "node-support-majors": [20, 22],
    "browser-engines": ["chromium", "webkit"],
}

SOURCE_COMMIT = "a" * 40
PRODUCT_VERSION = "0.1.0-beta.1"


def installed_report(lane: str, target: str) -> dict:
    return {
        "schemaVersion": 1,
        "sourceCommit": SOURCE_COMMIT,
        "published": False,
        "lane": lane,
        "runtime": {
            "name": "node" if lane == "node" else target,
            "version": f"v{target}.0.0" if lane == "node" else "1.0",
        },
        "productVersion": PRODUCT_VERSION,
        "commands": ["npm install --no-audit --no-fund", "public API qualification"],
        "results": {
            "initialize": "passed",
            "scan": "passed",
            "incremental": "passed",
            "incrementalCorpus": "passed",
            "stream": "passed",
            "aiContextBoundary": "passed",
            "mcpBoundary": "passed",
            "mcpResourcesRead": "passed",
        },
        "incrementalCorpus": {
            "path": "conformance/fixtures/incremental-corpus.json",
            "sha256": RECORD.corpus_identity()["incremental-corpus.json"],
            "offsetUnit": "utf8-byte",
            "fixtureCount": RECORD.incremental_corpus_fixture_count(),
        },
        "packageArtifacts": [
            {
                "name": "@redact-secret/core",
                "version": PRODUCT_VERSION,
                "file": "core.tgz",
                "sha256": "1" * 64,
            },
            {
                "name": "@redact-secret/node-test",
                "version": PRODUCT_VERSION,
                "file": "node.tgz",
                "sha256": "2" * 64,
            },
            {
                "name": "@redact-secret/wasm",
                "version": PRODUCT_VERSION,
                "file": "wasm.tgz",
                "sha256": "3" * 64,
            },
        ],
    }


QUICKSTART_SHA256 = "q" * 64


def _built(name: str) -> dict:
    # `Artifacts.build` writes each artifact file's own name as its bytes.
    return {"file": name, "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest()}


def clean_install_report(lane: str) -> dict:
    checks = {check: "passed" for check in RECORD.CLEAN_INSTALL_CHECKS[lane]}
    binaries = (
        [_built("package-cp310-abi3-macosx.whl")]
        if lane == "python"
        else [
            _built("redact-secret.darwin-arm64.node"),
            _built("redact_secret_wasm_bg.wasm"),
            _built("redact_secret_wasm_common_bg.wasm"),
        ]
    )
    return {
        "schemaVersion": 1,
        "lane": lane,
        "sourceCommit": SOURCE_COMMIT,
        "published": False,
        "productVersion": PRODUCT_VERSION,
        "document": {"path": "docs/quickstart.md", "sha256": QUICKSTART_SHA256},
        "commands": ["npm install @redact-secret/core@0.1.0-beta.1"],
        "runtime": {"name": lane, "version": "1.0"},
        "loadedArtifact": RECORD.CLEAN_INSTALL_ARTIFACT[lane],
        "budgetSeconds": 300,
        "elapsedSeconds": 42.0,
        "binaries": binaries,
        "results": checks,
    }


ROOT = SCRIPT.parents[1]


def _example_file(path: str) -> dict:
    return {"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}


def golden_path_report(lane: str) -> dict:
    lock = json.loads((ROOT / "examples" / "mcp-redact" / "package-lock.json").read_text(encoding="utf-8"))
    entry = "examples/mcp-redact/agent-context.mjs"
    files = [
        _example_file(entry),
        _example_file("examples/mcp-redact/redact-tool-call.mjs"),
        _example_file("examples/mcp-redact/streaming-tool-result.real-core.test.mjs"),
    ]
    report = clean_install_report(lane)
    return {
        "schemaVersion": 2,
        "lane": lane,
        "sourceCommit": SOURCE_COMMIT,
        "published": False,
        "productVersion": PRODUCT_VERSION,
        "example": {"path": "examples/mcp-redact", "entry": entry, "files": files},
        "adapters": {
            "source": "https://registry.npmjs.org/",
            "lockfile": "examples/mcp-redact/package-lock.json",
            "packages": sorted(
                (
                    {"name": key.removeprefix("node_modules/"), "version": e["version"], "integrity": e["integrity"]}
                    for key, e in lock["packages"].items()
                    if key.startswith("node_modules/@redact-secret/")
                ),
                key=lambda p: p["name"],
            ),
        },
        "realCoreTests": ["examples/mcp-redact/streaming-tool-result.real-core.test.mjs"],
        "runtime": {"name": lane, "version": "1.0"},
        "loadedArtifact": RECORD.GOLDEN_PATH_ARTIFACT[lane],
        "binaries": report["binaries"],
        "results": {check: "passed" for check in RECORD.GOLDEN_PATH_CHECKS[lane]},
    }


class Artifacts:
    """Builds a downloaded-artifact tree that satisfies `require_matrix`, so
    each test can remove or add exactly one thing."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: dict[str, list[str]] = {
            "node-addon-aarch64-apple-darwin": [
                "redact-secret.darwin-arm64.node",
                "index.js",
            ],
            "node-addon-x86_64-unknown-linux-musl": [
                "redact-secret.linux-x64-musl.node",
                "index.js",
            ],
            "cli-aarch64-apple-darwin": ["redact-secret"],
            "cli-x86_64-pc-windows-msvc": ["redact-secret.exe"],
            "python-wheel-aarch64-apple-darwin": ["package-cp310-abi3-macosx.whl"],
            "python-sdist": ["package-0.1.0.tar.gz"],
            "wasm-web": ["redact_secret_wasm.js", "redact_secret_wasm_bg.wasm"],
            "wasm-web-common": [
                "redact_secret_wasm_common.js",
                "redact_secret_wasm_common_bg.wasm",
            ],
            "installed-javascript-node-20": ["installed-javascript-node-20.json"],
            "installed-javascript-node-22": ["installed-javascript-node-22.json"],
            "installed-javascript-browser-chromium": [
                "installed-javascript-browser-chromium.json"
            ],
            "installed-javascript-browser-webkit": [
                "installed-javascript-browser-webkit.json"
            ],
            "clean-install-node": ["clean-install-node.json"],
            "clean-install-python": ["clean-install-python.json"],
            "clean-install-browser": ["clean-install-browser.json"],
            "golden-path-node": ["golden-path-node.json"],
        }
        self.clean_install = {
            lane: clean_install_report(lane) for lane in RECORD.CLEAN_INSTALL_CHECKS
        }
        self.golden_path = {lane: golden_path_report(lane) for lane in RECORD.GOLDEN_PATH_CHECKS}

    def build(self) -> Path:
        for artifact, names in self.files.items():
            directory = self.root / artifact
            directory.mkdir(parents=True, exist_ok=True)
            for name in names:
                path = directory / name
                if artifact.startswith("installed-javascript-"):
                    if artifact.startswith("installed-javascript-node-"):
                        lane = "node"
                        target = artifact.removeprefix("installed-javascript-node-")
                    else:
                        lane = "browser"
                        target = artifact.removeprefix("installed-javascript-browser-")
                    path.write_text(json.dumps(installed_report(lane, target)), encoding="utf-8")
                elif artifact.startswith("clean-install-"):
                    lane = artifact.removeprefix("clean-install-")
                    path.write_text(json.dumps(self.clean_install[lane]), encoding="utf-8")
                elif artifact.startswith("golden-path-"):
                    lane = artifact.removeprefix("golden-path-")
                    path.write_text(json.dumps(self.golden_path[lane]), encoding="utf-8")
                else:
                    path.write_bytes(name.encode("utf-8"))
        return self.root


class InventoryTests(unittest.TestCase):
    def collect(self, configure=None) -> list[dict]:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Artifacts(Path(directory))
            if configure is not None:
                configure(artifacts)
            return RECORD.collect(artifacts.build())

    def errors(self, configure=None) -> list[str]:
        return RECORD.require_matrix(MATRIX, self.collect(configure))

    def qualification_errors(self, configure=None) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Artifacts(Path(directory))
            if configure is not None:
                configure(artifacts)
            root = artifacts.build()
            results, errors = RECORD.collect_installed_javascript_qualification(root)
            return errors + RECORD.require_installed_javascript_qualification(
                MATRIX, results, SOURCE_COMMIT, PRODUCT_VERSION
            )

    def test_a_complete_matrix_passes(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_every_file_is_recorded_with_a_family_size_and_digest(self) -> None:
        collected = self.collect()
        entry = next(
            item for item in collected if item["file"] == "redact-secret.darwin-arm64.node"
        )
        self.assertEqual(entry["family"], "node-addon")
        self.assertEqual(entry["target"], "aarch64-apple-darwin")
        self.assertEqual(entry["bytes"], len(b"redact-secret.darwin-arm64.node"))
        self.assertEqual(len(entry["sha256"]), 64)

    def test_a_missing_addon_target_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["node-addon-x86_64-unknown-linux-musl"]

        self.assertEqual(
            self.errors(configure),
            ["node-addon: no artifact for x86_64-unknown-linux-musl"],
        )

    def test_a_missing_cli_target_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["cli-x86_64-pc-windows-msvc"]

        self.assertEqual(
            self.errors(configure), ["cli: no artifact for x86_64-pc-windows-msvc"]
        )

    def test_a_missing_wheel_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["python-wheel-aarch64-apple-darwin"]

        self.assertEqual(
            self.errors(configure), ["python-wheel: no artifact for aarch64-apple-darwin"]
        )

    def test_a_missing_sdist_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["python-sdist"]

        self.assertEqual(self.errors(configure), ["python-sdist: no artifact was produced"])

    def test_a_missing_browser_artifact_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["wasm-web"]

        self.assertEqual(self.errors(configure), ["browser: no artifact was produced"])

    def test_an_undeclared_target_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            artifacts.files["cli-aarch64-unknown-linux-gnu"] = ["redact-secret"]

        self.assertEqual(
            self.errors(configure),
            ["cli: built aarch64-unknown-linux-gnu, which Cargo.toml does not declare"],
        )

    def test_a_common_browser_artifact_is_recorded_with_its_own_family(self) -> None:
        entry = next(
            item
            for item in self.collect()
            if item["file"] == "redact_secret_wasm_common_bg.wasm"
        )
        self.assertEqual(entry["family"], "browser-common")
        self.assertIsNone(entry["target"])

    def test_a_missing_common_browser_artifact_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["wasm-web-common"]

        self.assertEqual(
            self.errors(configure), ["browser-common: no artifact was produced"]
        )

    def test_an_unrecognized_artifact_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            artifacts.files["something-else"] = ["file"]

        self.assertEqual(
            self.errors(configure), ["unrecognized artifact(s): something-else"]
        )

    def test_shadow_determinism_records_are_not_unrecognized_artifacts(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            for host in ("ubuntu-latest", "macos-latest", "windows-latest", "wasm32-wasip1"):
                artifacts.files[f"shadow-determinism-{host}"] = [f"{host}-full.jsonl", f"{host}-common.jsonl"]
            artifacts.files["shadow-determinism-report"] = ["report-full.json", "report-common.json"]

        self.assertEqual(self.errors(configure), [])
        self.assertFalse(
            any(entry["artifact"].startswith("shadow-determinism-") for entry in self.collect(configure))
        )

    def test_the_support_matrix_drift_record_is_not_an_unrecognized_artifact(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            artifacts.files["support-matrix-drift"] = ["support-matrix-drift.json"]

        self.assertEqual(self.errors(configure), [])
        self.assertNotIn(
            "support-matrix-drift",
            {entry["artifact"] for entry in self.collect(configure)},
        )

    def test_installed_javascript_qualification_covers_declared_runtimes(self) -> None:
        self.assertEqual(self.qualification_errors(), [])

    def test_missing_installed_node_major_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            del artifacts.files["installed-javascript-node-22"]

        self.assertEqual(
            self.qualification_errors(configure),
            ["installed JavaScript node: no qualification for 22"],
        )

    def test_failed_installed_stream_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Artifacts(Path(directory)).build()
            path = (
                root
                / "installed-javascript-browser-webkit"
                / "installed-javascript-browser-webkit.json"
            )
            report = json.loads(path.read_text(encoding="utf-8"))
            report["results"]["stream"] = "failed"
            path.write_text(json.dumps(report), encoding="utf-8")
            results, errors = RECORD.collect_installed_javascript_qualification(root)
            errors += RECORD.require_installed_javascript_qualification(
                MATRIX, results, SOURCE_COMMIT, PRODUCT_VERSION
            )
        self.assertEqual(
            errors, ["installed JavaScript browser webkit: stream did not pass"]
        )

    def test_missing_installed_mcp_boundary_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Artifacts(Path(directory)).build()
            path = root / "installed-javascript-node-22" / "installed-javascript-node-22.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            del report["results"]["mcpBoundary"]
            path.write_text(json.dumps(report), encoding="utf-8")
            results, errors = RECORD.collect_installed_javascript_qualification(root)
            errors += RECORD.require_installed_javascript_qualification(
                MATRIX, results, SOURCE_COMMIT, PRODUCT_VERSION
            )
        self.assertEqual(errors, ["installed JavaScript node 22: mcpBoundary did not pass"])

    def test_missing_installed_mcp_resources_read_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Artifacts(Path(directory)).build()
            path = root / "installed-javascript-node-22" / "installed-javascript-node-22.json"
            report = json.loads(path.read_text(encoding="utf-8"))
            del report["results"]["mcpResourcesRead"]
            path.write_text(json.dumps(report), encoding="utf-8")
            results, errors = RECORD.collect_installed_javascript_qualification(root)
            errors += RECORD.require_installed_javascript_qualification(
                MATRIX, results, SOURCE_COMMIT, PRODUCT_VERSION
            )
        self.assertEqual(errors, ["installed JavaScript node 22: mcpResourcesRead did not pass"])

    def test_missing_installed_incremental_corpus_result_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Artifacts(Path(directory)).build()
            path = (
                root
                / "installed-javascript-node-20"
                / "installed-javascript-node-20.json"
            )
            report = json.loads(path.read_text(encoding="utf-8"))
            del report["results"]["incrementalCorpus"]
            del report["incrementalCorpus"]
            path.write_text(json.dumps(report), encoding="utf-8")
            results, errors = RECORD.collect_installed_javascript_qualification(root)
            errors += RECORD.require_installed_javascript_qualification(
                MATRIX, results, SOURCE_COMMIT, PRODUCT_VERSION
            )
        self.assertEqual(
            errors,
            [
                "installed JavaScript node 20: incrementalCorpus did not pass",
                "installed JavaScript node 20: incremental corpus path is incomplete",
                "installed JavaScript node 20: incremental corpus hash does not match the inventory",
                "installed JavaScript node 20: incremental corpus offset unit is invalid",
                "installed JavaScript node 20: incremental corpus fixture count does not match the inventory",
            ],
        )

    def clean_install_errors(self, configure=None) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Artifacts(Path(directory))
            if configure is not None:
                configure(artifacts)
            root = artifacts.build()
            results, errors = RECORD.collect_clean_install_qualification(root)
            return errors + RECORD.require_clean_install_qualification(
                results, RECORD.collect(root), SOURCE_COMMIT, PRODUCT_VERSION, QUICKSTART_SHA256
            )

    def test_clean_install_evidence_is_not_an_unrecognized_artifact(self) -> None:
        self.assertFalse(any(entry["artifact"].startswith("clean-install-") for entry in self.collect()))

    def test_clean_install_qualification_covers_every_lane(self) -> None:
        self.assertEqual(self.clean_install_errors(), [])

    def test_a_missing_clean_install_lane_fails(self) -> None:
        def drop(artifacts: Artifacts) -> None:
            del artifacts.files["clean-install-python"]

        self.assertIn("clean install python: no qualification", self.clean_install_errors(drop))

    def test_a_clean_install_binary_this_run_did_not_build_fails(self) -> None:
        def swap(artifacts: Artifacts) -> None:
            artifacts.clean_install["node"]["binaries"][0]["sha256"] = "0" * 64

        self.assertIn(
            "clean install node: redact-secret.darwin-arm64.node is not an artifact this run qualified",
            self.clean_install_errors(swap),
        )

    def test_a_clean_install_from_another_quickstart_revision_fails(self) -> None:
        def stale(artifacts: Artifacts) -> None:
            artifacts.clean_install["browser"]["document"]["sha256"] = "0" * 64

        self.assertIn(
            "clean install browser: did not run this revision's docs/quickstart.md",
            self.clean_install_errors(stale),
        )

    def test_a_clean_install_over_budget_or_failed_check_fails(self) -> None:
        def slow(artifacts: Artifacts) -> None:
            artifacts.clean_install["node"]["elapsedSeconds"] = 301
            artifacts.clean_install["python"]["results"]["failure"] = "failed"

        errors = self.clean_install_errors(slow)
        self.assertIn("clean install node: documented path did not finish within 300s", errors)
        self.assertIn("clean install python: failure did not pass", errors)

    def test_a_published_or_wrong_artifact_clean_install_fails(self) -> None:
        def registry(artifacts: Artifacts) -> None:
            artifacts.clean_install["browser"]["published"] = True
            artifacts.clean_install["node"]["loadedArtifact"] = "wasm"

        errors = self.clean_install_errors(registry)
        self.assertIn(
            "clean install browser: must qualify candidate artifacts (published=false)", errors
        )
        self.assertIn("clean install node: did not load the addon artifact", errors)

    def golden_path_errors(self, configure=None) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Artifacts(Path(directory))
            if configure is not None:
                configure(artifacts)
            root = artifacts.build()
            results, errors = RECORD.collect_golden_path_qualification(root)
            return errors + RECORD.require_golden_path_qualification(
                results, RECORD.collect(root), SOURCE_COMMIT, PRODUCT_VERSION
            )

    def test_golden_path_evidence_is_not_an_unrecognized_artifact(self) -> None:
        self.assertFalse(any(entry["artifact"].startswith("golden-path-") for entry in self.collect()))

    def test_golden_path_qualification_covers_the_node_lane(self) -> None:
        self.assertEqual(self.golden_path_errors(), [])

    def test_a_missing_golden_path_lane_fails(self) -> None:
        def drop(artifacts: Artifacts) -> None:
            del artifacts.files["golden-path-node"]

        self.assertIn("golden path node: no qualification", self.golden_path_errors(drop))

    def test_a_python_golden_path_lane_is_retired(self) -> None:
        """#810 retired the Python MCP twins and their lane; a report for it
        is not evidence of anything."""

        def revive(artifacts: Artifacts) -> None:
            artifacts.files["golden-path-python"] = ["golden-path-python.json"]
            artifacts.golden_path["python"] = {**golden_path_report("node"), "lane": "python"}

        self.assertIn("golden-path-python: invalid lane", self.golden_path_errors(revive))

    def test_a_golden_path_binary_this_run_did_not_build_fails(self) -> None:
        def swap(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["binaries"][0]["sha256"] = "0" * 64

        self.assertIn(
            "golden path node: redact-secret.darwin-arm64.node is not an artifact this run qualified",
            self.golden_path_errors(swap),
        )

    def test_a_golden_path_on_another_revision_of_the_example_fails(self) -> None:
        def stale(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["example"]["files"][0]["sha256"] = "0" * 64

        self.assertIn(
            "golden path node: did not run this revision's examples/mcp-redact", self.golden_path_errors(stale)
        )

    def test_a_node_golden_path_without_the_real_core_tests_fails(self) -> None:
        def skipped(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["realCoreTests"] = []

        self.assertIn(
            "golden path node: did not run this revision's real-core example tests",
            self.golden_path_errors(skipped),
        )

    def test_a_golden_path_on_adapters_other_than_the_locked_ones_fails(self) -> None:
        expected = "golden path node: did not install the registry adapters examples/mcp-redact/package-lock.json locks"

        def other_version(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["adapters"]["packages"][0]["version"] = "0.0.0"

        def other_bytes(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["adapters"]["packages"][0]["integrity"] = "sha512-" + "A" * 86 + "=="

        def old_pin(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["adapters"] = {"repository": "redact-secret/redact-secret-adapters", "commit": "b" * 40}

        for configure in (other_version, other_bytes, old_pin):
            self.assertIn(expected, self.golden_path_errors(configure))

    def test_a_published_unsanitized_or_wrong_artifact_golden_path_fails(self) -> None:
        def broken(artifacts: Artifacts) -> None:
            artifacts.golden_path["node"]["published"] = True
            artifacts.golden_path["node"]["loadedArtifact"] = "wasm"
            artifacts.golden_path["node"]["results"]["sanitized"] = "failed"

        errors = self.golden_path_errors(broken)
        self.assertIn("golden path node: must qualify candidate artifacts (published=false)", errors)
        self.assertIn("golden path node: did not load the addon artifact", errors)
        self.assertIn("golden path node: sanitized did not pass", errors)

    def test_an_addon_without_a_compiled_library_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            artifacts.files["node-addon-aarch64-apple-darwin"] = ["index.js"]

        self.assertEqual(
            self.errors(configure),
            ["node-addon aarch64-apple-darwin: carries no compiled .node library"],
        )

    def test_a_cli_artifact_without_an_executable_fails(self) -> None:
        def configure(artifacts: Artifacts) -> None:
            artifacts.files["cli-aarch64-apple-darwin"] = ["README.md"]

        self.assertEqual(
            self.errors(configure),
            ["cli aarch64-apple-darwin: carries no executable"],
        )

    def test_the_source_commit_prefers_the_real_head_over_a_merge_ref(self) -> None:
        """On a pull request `GITHUB_SHA` is the synthesized merge commit,
        which no clone can resolve; `SOURCE_COMMIT` carries the head."""
        head, merge = "a" * 40, "b" * 40
        with unittest.mock.patch.dict(
            os.environ, {"SOURCE_COMMIT": head, "GITHUB_SHA": merge}, clear=False
        ):
            self.assertEqual(RECORD.source_commit(), head)
        with unittest.mock.patch.dict(
            os.environ, {"SOURCE_COMMIT": "", "GITHUB_SHA": merge}, clear=False
        ):
            self.assertEqual(RECORD.source_commit(), merge)

    def test_the_source_commit_falls_back_to_the_checked_out_head(self) -> None:
        with unittest.mock.patch.dict(
            os.environ, {"SOURCE_COMMIT": "", "GITHUB_SHA": ""}, clear=False
        ):
            commit = RECORD.source_commit()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")

    def test_the_summary_records_the_commit_and_never_claims_publication(self) -> None:
        inventory = {
            "sourceCommit": "0" * 40,
            "productVersion": "0.1.0-beta.1",
            "artifacts": self.collect(),
            "packageContents": {"@redact-secret/core": ["dist/index.js"]},
            "releaseReadiness": RECORD.release_readiness_record(),
        }
        summary = RECORD.render_summary(inventory)
        self.assertIn("0" * 40, summary)
        self.assertIn("Published: no", summary)
        self.assertIn("separate approval required", summary)
        self.assertIn("post-publication-release-workflow", summary)
        self.assertIn("dist/index.js", summary)

    def test_release_readiness_record_pins_review_and_registry_boundaries(self) -> None:
        record = RECORD.release_readiness_record()
        self.assertEqual(record["issue"], 606)
        review = record["publicApiAndChangelogReview"]
        self.assertEqual(review["status"], "required-before-release-approval")
        self.assertEqual(
            review["currentPublicApiReview"]["path"],
            "docs/audits/beta6-candidate-public-contract-review.md",
        )
        self.assertRegex(
            review["currentPublicApiReview"]["sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            review["publicApiReview"]["path"],
            "docs/audits/candidate-public-contract-review.md",
        )
        self.assertEqual(
            review["publicApiReview"]["scope"],
            "historical-beta.1-candidate-review",
        )
        self.assertRegex(review["publicApiReview"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(review["changelog"]["path"], "CHANGELOG.md")
        self.assertRegex(review["changelog"]["sha256"], r"^[0-9a-f]{64}$")
        registry = record["registryInstallVerification"]
        self.assertEqual(registry["status"], "post-publication-release-workflow")
        self.assertEqual(registry["verifier"], "scripts/verify-registry-install.mjs")
        self.assertEqual(
            registry["authorization"], "separate release approval required"
        )


class CratePackageDigestTests(unittest.TestCase):
    def test_no_directory_yields_no_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "target" / "package"
            self.assertEqual(RECORD.crate_package_digests(missing), [])

    def test_each_crate_file_is_recorded_with_its_matching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package_dir = Path(directory)
            core = package_dir / "redact-secret-0.1.0.crate"
            cli = package_dir / "redact-secret-cli-0.1.0.crate"
            core.write_bytes(b"core bytes")
            cli.write_bytes(b"cli bytes")

            entries = {entry["target"]: entry for entry in RECORD.crate_package_digests(package_dir)}

            self.assertEqual(set(entries), {"redact-secret", "redact-secret-cli"})
            self.assertEqual(entries["redact-secret"]["family"], "crate")
            self.assertEqual(entries["redact-secret"]["file"], "redact-secret-0.1.0.crate")
            self.assertEqual(entries["redact-secret"]["bytes"], len(b"core bytes"))
            self.assertEqual(len(entries["redact-secret"]["sha256"]), 64)
            # `redact-secret-cli-0.1.0.crate` must not be misattributed to
            # `redact-secret` by a naive substring match.
            self.assertEqual(entries["redact-secret-cli"]["file"], "redact-secret-cli-0.1.0.crate")

    def test_an_unrecognized_crate_file_is_still_recorded_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package_dir = Path(directory)
            (package_dir / "some-other-crate-0.1.0.crate").write_bytes(b"x")

            entries = RECORD.crate_package_digests(package_dir)

            self.assertEqual(entries[0]["target"], "unknown")


class RequireCratesTests(unittest.TestCase):
    def test_both_crates_present_passes(self) -> None:
        entries = [{"target": name} for name in RECORD.CRATES]
        self.assertEqual(RECORD.require_crates(entries), [])

    def test_a_missing_crate_fails(self) -> None:
        entries = [{"target": RECORD.CRATE}]
        self.assertEqual(
            RECORD.require_crates(entries),
            ["crate: no packaged .crate artifact for redact-secret-cli"],
        )

    def test_an_undeclared_crate_fails(self) -> None:
        entries = [{"target": name} for name in RECORD.CRATES] + [{"target": "unknown"}]
        self.assertEqual(
            RECORD.require_crates(entries),
            ["crate: packaged unknown, which is not a declared crate"],
        )


if __name__ == "__main__":
    unittest.main()
