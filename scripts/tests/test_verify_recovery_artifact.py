from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "verify-recovery-artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_recovery_artifact", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class RecoveryArtifactTests(unittest.TestCase):
    def test_missing_extra_and_changed_bytes_are_rejected(self):
        payload = b"synthetic qualified artifact"
        inventory = {"artifacts": [{"artifact": "addon", "file": "addon.node", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                CHECK.verify_files(inventory, "addon", root)
            (root / "addon.node").write_bytes(payload)
            CHECK.verify_files(inventory, "addon", root)
            (root / "extra.txt").write_text("extra")
            with self.assertRaises(ValueError):
                CHECK.verify_files(inventory, "addon", root)
            (root / "extra.txt").unlink()
            (root / "addon.node").write_bytes(payload.upper())
            with self.assertRaises(ValueError):
                CHECK.verify_files(inventory, "addon", root)

    def test_pypi_distinguishes_complete_partial_absent_and_conflict(self):
        inventory = {"artifacts": [{"file": "synthetic.whl", "sha256": "a" * 64}, {"file": "synthetic.tar.gz", "sha256": "b" * 64}]}
        files = [{"filename": item["file"], "digests": {"sha256": item["sha256"]}} for item in inventory["artifacts"]]

        complete = CHECK.verify_pypi(inventory, {"urls": files})
        self.assertEqual(complete.status, "complete")
        self.assertEqual(complete.missing_files, [])

        partial = CHECK.verify_pypi(inventory, {"urls": files[:1]})
        self.assertEqual(partial.status, "partial")
        self.assertEqual(partial.existing_files, ["synthetic.whl"])
        self.assertEqual(partial.missing_files, ["synthetic.tar.gz"])

        absent = CHECK.pypi_absent(inventory)
        self.assertEqual(absent.status, "absent")
        self.assertEqual(absent.missing_files, ["synthetic.tar.gz", "synthetic.whl"])

        conflicts = (
            files + [{"filename": "extra.whl", "digests": {"sha256": "c" * 64}}],
            [{"filename": "synthetic.whl", "digests": {"sha256": "d" * 64}}, files[1]],
        )
        for bad in conflicts:
            with self.subTest(files=bad):
                state = CHECK.verify_pypi(inventory, {"urls": bad})
                self.assertEqual(state.status, "conflict")

    def test_pypi_unobservable_state_is_not_publishable(self):
        state = CHECK.pypi_unobservable("synthetic registry failure")
        self.assertEqual(state.status, "unobservable")
        self.assertEqual(state.reason, "synthetic registry failure")

    def test_pypi_http_errors_other_than_404_are_unobservable(self):
        inventory = {"artifacts": [{"file": "synthetic.whl", "sha256": "a" * 64}]}
        original_urlopen = CHECK.urlopen

        def fail_with_server_error(*_args, **_kwargs):
            raise CHECK.HTTPError("https://pypi.example.invalid", 503, "unavailable", {}, io.BytesIO())

        try:
            CHECK.urlopen = fail_with_server_error
            state = CHECK.fetch_pypi_state(inventory, "synthetic-project", "synthetic-version")
        finally:
            CHECK.urlopen = original_urlopen

        self.assertEqual(state.status, "unobservable")
        self.assertEqual(state.reason, "PyPI returned HTTP 503")

    def test_fetch_pypi_state_classifies_registry_observations(self):
        inventory = {"artifacts": [{"file": "synthetic.whl", "sha256": "a" * 64}]}
        original_urlopen = CHECK.urlopen

        class Response:
            def __init__(self, payload: bytes):
                self.payload = io.BytesIO(payload)

            def __enter__(self):
                return self.payload

            def __exit__(self, *_args):
                return False

        def with_urlopen(stub):
            try:
                CHECK.urlopen = stub
                return CHECK.fetch_pypi_state(inventory, "synthetic-project", "synthetic-version")
            finally:
                CHECK.urlopen = original_urlopen

        complete_payload = json.dumps(
            {"urls": [{"filename": "synthetic.whl", "digests": {"sha256": "a" * 64}}]}
        ).encode()
        self.assertEqual(
            with_urlopen(lambda *_args, **_kwargs: Response(complete_payload)).status,
            "complete",
        )
        self.assertEqual(
            with_urlopen(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    CHECK.HTTPError("https://pypi.example.invalid", 404, "missing", {}, io.BytesIO())
                )
            ).status,
            "absent",
        )
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                state = with_urlopen(
                    lambda *_args, status=status, **_kwargs: (_ for _ in ()).throw(
                        CHECK.HTTPError("https://pypi.example.invalid", status, "error", {}, io.BytesIO())
                    )
                )
                self.assertEqual(state.status, "unobservable")
                self.assertEqual(state.reason, f"PyPI returned HTTP {status}")
        self.assertEqual(
            with_urlopen(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    CHECK.URLError("synthetic transport failure")
                )
            ).status,
            "unobservable",
        )
        self.assertEqual(
            with_urlopen(lambda *_args, **_kwargs: Response(b"{not-json")).status,
            "unobservable",
        )

    def test_partial_pypi_recovery_stages_only_missing_verified_files(self):
        wheel = b"synthetic wheel bytes"
        sdist = b"synthetic sdist bytes"
        inventory = {
            "artifacts": [
                {"file": "synthetic.whl", "bytes": len(wheel), "sha256": hashlib.sha256(wheel).hexdigest()},
                {"file": "synthetic.tar.gz", "bytes": len(sdist), "sha256": hashlib.sha256(sdist).hexdigest()},
            ]
        }
        state = CHECK.verify_pypi(
            inventory,
            {"urls": [{"filename": "synthetic.whl", "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}}]},
        )
        self.assertEqual(state.status, "partial")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "synthetic.whl").write_bytes(wheel)
            (root / "synthetic.tar.gz").write_bytes(sdist)

            CHECK.stage_missing_pypi_files(inventory, state, root)

            self.assertFalse((root / "synthetic.whl").exists())
            self.assertEqual((root / "synthetic.tar.gz").read_bytes(), sdist)

    def test_partial_pypi_recovery_rejects_unavailable_original_files(self):
        wheel = b"synthetic wheel bytes"
        sdist = b"synthetic sdist bytes"
        inventory = {
            "artifacts": [
                {"file": "synthetic.whl", "bytes": len(wheel), "sha256": hashlib.sha256(wheel).hexdigest()},
                {"file": "synthetic.tar.gz", "bytes": len(sdist), "sha256": hashlib.sha256(sdist).hexdigest()},
            ]
        }
        state = CHECK.verify_pypi(
            inventory,
            {"urls": [{"filename": "synthetic.whl", "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}}]},
        )

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                CHECK.stage_missing_pypi_files(inventory, state, Path(tmp))
