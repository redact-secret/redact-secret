from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "validate-release-records.py"
SPEC = importlib.util.spec_from_file_location("validate_release_records", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ValidateReleaseRecordsTests(unittest.TestCase):
    def fixture(self, reconstructed: bool = False, version: str = "1.2.3-beta.4") -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        record = root / f"docs/releases/{version}"
        record.mkdir(parents=True)
        (record / "README.md").write_text("record\n")
        inventory = {
            "sourceCommit": "a" * 40, "productVersion": version,
            "conformanceFixtures": {"corpus.json": "b" * 64},
            "artifacts": [{"family": "python-wheel", "file": f"file-{i}.whl", "sha256": f"{i:064x}"}
                          for i in range(9)],
        }
        inventory_path = record / "artifact-inventory.json"
        inventory_path.write_text(json.dumps(inventory))
        registries = {}
        artifacts = MODULE.expected_artifacts(version)
        for artifact in artifacts:
            if artifact.startswith("npm:"):
                registries[artifact] = {"shasum": "abc", "integrity": "sha512-abc"}
            elif artifact.startswith("crate:"):
                registries[artifact] = {"checksum": "c" * 64}
            else:
                registries[artifact] = {"files": [{"filename": f"file-{i}.whl", "sha256": f"{i:064x}"}
                                                   for i in range(9)]}
        evidence = {
            "reason": "reconstructed from immutable public metadata",
            "original_manifest": {"registry_state": {"npm:@redact-secret/core": "unknown"}},
            "registries": registries, "runs": [{"id": 123, "result": "verified"}],
            "verification": {"node": [str(i) for i in range(MODULE.expected_node_lanes(version))],
                             "browser": "chromium"},
            "tag": {"name": f"v{version}", "object": "d" * 40, "target": "a" * 40},
        }
        manifest = {
            "source_revision": "a" * 40, "conformance_identity": "e" * 40,
            "version": version, "artifact_set": sorted(artifacts),
            "registry_state": {name: "published" for name in artifacts},
            "release_evidence": evidence,
            "artifact_inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        }
        if reconstructed:
            manifest["record_kind"] = "reconstructed"
        (record / "manifest.json").write_text(json.dumps(manifest))
        (root / "CHANGELOG.md").write_text(
            f"[Publication evidence](docs/releases/{version}/README.md).\n")
        return root

    def validate(self, root: Path, changelog: str | None = None, version: str = "1.2.3-beta.4") -> None:
        with mock.patch.object(MODULE, "conformance_identity", return_value="e" * 40):
            MODULE.validate_record(root, root / f"docs/releases/{version}",
                                   changelog if changelog is not None else (root / "CHANGELOG.md").read_text())

    def test_accepts_complete_workflow_and_reconstructed_records(self) -> None:
        self.validate(self.fixture())
        self.validate(self.fixture(reconstructed=True))

    def test_rejects_missing_required_files(self) -> None:
        root = self.fixture()
        (root / "docs/releases/1.2.3-beta.4/README.md").unlink()
        with self.assertRaisesRegex(MODULE.InvalidRecord, "missing README"):
            self.validate(root)

    def test_rejects_version_source_conformance_artifact_and_tag_mismatches(self) -> None:
        fields = ("version", "source_revision", "conformance_identity", "artifact_set")
        for field in fields:
            with self.subTest(field=field):
                root = self.fixture()
                path = root / "docs/releases/1.2.3-beta.4/manifest.json"
                value = json.loads(path.read_text())
                value[field] = [] if field == "artifact_set" else "wrong"
                path.write_text(json.dumps(value))
                with self.assertRaises(MODULE.InvalidRecord):
                    self.validate(root)
        root = self.fixture()
        path = root / "docs/releases/1.2.3-beta.4/manifest.json"
        value = json.loads(path.read_text())
        value["release_evidence"]["tag"]["target"] = "f" * 40
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(MODULE.InvalidRecord, "tag target"):
            self.validate(root)

    def test_rejects_partial_unknown_and_unproven_reconstruction(self) -> None:
        for state in ("unpublished", "unknown"):
            root = self.fixture()
            path = root / "docs/releases/1.2.3-beta.4/manifest.json"
            value = json.loads(path.read_text())
            value["registry_state"]["npm:@redact-secret/core"] = state
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(MODULE.InvalidRecord, "complete and published"):
                self.validate(root)
        root = self.fixture(reconstructed=True)
        path = root / "docs/releases/1.2.3-beta.4/manifest.json"
        value = json.loads(path.read_text())
        del value["release_evidence"]["original_manifest"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(MODULE.InvalidRecord, "provenance"):
            self.validate(root)

    def test_pre_musl_releases_keep_their_eleven_artifact_six_lane_shape(self) -> None:
        self.assertEqual(len(MODULE.expected_artifacts("0.1.0-beta.4")), 11)
        self.assertEqual(len(MODULE.expected_artifacts("0.1.0-beta.5")), 13)
        self.validate(self.fixture(version="0.1.0-beta.4"), version="0.1.0-beta.4")
        root = self.fixture(version="0.1.0-beta.4")
        path = root / "docs/releases/0.1.0-beta.4/manifest.json"
        value = json.loads(path.read_text())
        value["artifact_set"] = sorted(MODULE.EXPECTED_ARTIFACTS)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(MODULE.InvalidRecord, "artifact set mismatch"):
            self.validate(root, version="0.1.0-beta.4")

    def test_later_releases_require_musl_artifacts_and_eight_node_lanes(self) -> None:
        root = self.fixture(version="0.1.0-beta.5")
        path = root / "docs/releases/0.1.0-beta.5/manifest.json"
        value = json.loads(path.read_text())
        value["artifact_set"] = sorted(MODULE.EXPECTED_ARTIFACTS - MODULE.MUSL_ARTIFACTS)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(MODULE.InvalidRecord, "artifact set mismatch"):
            self.validate(root, version="0.1.0-beta.5")
        root = self.fixture(version="0.1.0-beta.5")
        path = root / "docs/releases/0.1.0-beta.5/manifest.json"
        value = json.loads(path.read_text())
        value["release_evidence"]["verification"]["node"] = [str(i) for i in range(6)]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(MODULE.InvalidRecord, "8 Node install lanes"):
            self.validate(root, version="0.1.0-beta.5")

    def test_rejects_missing_changelog_link(self) -> None:
        with self.assertRaisesRegex(MODULE.InvalidRecord, "CHANGELOG"):
            self.validate(self.fixture(), changelog="")

    def test_manifest_without_artifact_digests_is_accepted(self) -> None:
        # Frozen historical records (beta.1 through beta.5) predate this
        # field entirely (issue #528).
        self.validate(self.fixture())

    def test_comparable_stages_that_agree_are_accepted(self) -> None:
        digest = "a" * 64
        MODULE.validate_artifact_digests(
            {"pypi:redact-secret": [{"file": "x.whl", "built": digest, "qualified": digest,
                                      "published": digest, "comparable": True}]},
            "label",
        )

    def test_comparable_stages_that_disagree_are_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.InvalidRecord, "digest mismatch across stages"):
            MODULE.validate_artifact_digests(
                {"crate:redact-secret": [{"file": "x.crate", "qualified": "a" * 64,
                                           "published": "b" * 64, "comparable": True}]},
                "label",
            )

    def test_non_comparable_without_note_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.InvalidRecord, "requires a note"):
            MODULE.validate_artifact_digests(
                {"npm:@redact-secret/wasm": [{"file": "x.wasm", "comparable": False}]}, "label",
            )

    def test_non_comparable_with_note_is_accepted(self) -> None:
        MODULE.validate_artifact_digests(
            {"npm:@redact-secret/wasm": [{"file": "x.wasm", "comparable": False, "note": "repacked"}]},
            "label",
        )


if __name__ == "__main__":
    unittest.main()
