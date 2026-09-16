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
    def fixture(self, reconstructed: bool = False) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        record = root / "docs/releases/1.2.3-beta.4"
        record.mkdir(parents=True)
        (record / "README.md").write_text("record\n")
        inventory = {
            "sourceCommit": "a" * 40, "productVersion": "1.2.3-beta.4",
            "conformanceFixtures": {"corpus.json": "b" * 64},
            "artifacts": [{"family": "python-wheel", "file": f"file-{i}.whl", "sha256": f"{i:064x}"}
                          for i in range(9)],
        }
        inventory_path = record / "artifact-inventory.json"
        inventory_path.write_text(json.dumps(inventory))
        registries = {}
        for artifact in MODULE.EXPECTED_ARTIFACTS:
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
            "verification": {"node": [str(i) for i in range(6)], "browser": "chromium"},
            "tag": {"name": "v1.2.3-beta.4", "object": "d" * 40, "target": "a" * 40},
        }
        manifest = {
            "source_revision": "a" * 40, "conformance_identity": "e" * 40,
            "version": "1.2.3-beta.4", "artifact_set": sorted(MODULE.EXPECTED_ARTIFACTS),
            "registry_state": {name: "published" for name in MODULE.EXPECTED_ARTIFACTS},
            "release_evidence": evidence,
            "artifact_inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        }
        if reconstructed:
            manifest["record_kind"] = "reconstructed"
        (record / "manifest.json").write_text(json.dumps(manifest))
        (root / "CHANGELOG.md").write_text(
            "[Publication evidence](docs/releases/1.2.3-beta.4/README.md).\n")
        return root

    def validate(self, root: Path, changelog: str | None = None) -> None:
        with mock.patch.object(MODULE, "conformance_identity", return_value="e" * 40):
            MODULE.validate_record(root, root / "docs/releases/1.2.3-beta.4",
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

    def test_rejects_missing_changelog_link(self) -> None:
        with self.assertRaisesRegex(MODULE.InvalidRecord, "CHANGELOG"):
            self.validate(self.fixture(), changelog="")


if __name__ == "__main__":
    unittest.main()
