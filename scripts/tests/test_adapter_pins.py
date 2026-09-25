from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "adapter-pins.py"
SPEC = importlib.util.spec_from_file_location("adapter_pins", SCRIPT)
assert SPEC and SPEC.loader
PINS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PINS
SPEC.loader.exec_module(PINS)

COMMIT = "a" * 40


def pin(**overrides) -> dict:
    record = {
        "schemaVersion": 1,
        "repository": "redact-secret/redact-secret-adapters",
        "commit": COMMIT,
        "packages": [
            {"name": "@redact-secret/adapter", "version": "0.1.0", "contentDigest": "sha256:" + "1" * 64},
            {"name": "@redact-secret/adapter-ai-context", "version": "0.1.0", "contentDigest": "sha256:" + "2" * 64},
        ],
        "consumers": ["examples/mcp-redact"],
    }
    record.update(overrides)
    return record


def write_tarball(path: Path, files: dict[str, bytes]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ValidatePinTest(unittest.TestCase):
    def test_a_well_formed_pin_has_no_problems(self) -> None:
        self.assertEqual(PINS.validate_pin(pin()), [])

    def test_a_branch_or_short_sha_is_never_a_pin(self) -> None:
        for commit in ["develop", "a7fbcc3", "A" * 40, None]:
            self.assertTrue(PINS.validate_pin(pin(commit=commit)), commit)

    def test_repository_schema_and_consumers_are_required(self) -> None:
        self.assertTrue(PINS.validate_pin(pin(schemaVersion=2)))
        self.assertTrue(PINS.validate_pin(pin(repository="someone/else")))
        self.assertTrue(PINS.validate_pin(pin(consumers=[])))
        self.assertTrue(PINS.validate_pin(pin(consumers=["../outside"])))
        self.assertTrue(PINS.validate_pin(pin(consumers=["/abs"])))

    def test_every_package_needs_a_name_version_and_digest(self) -> None:
        bad = [
            {"name": "left-pad", "version": "0.1.0", "contentDigest": "sha256:" + "1" * 64},
            {"name": "@redact-secret/adapter", "version": "latest", "contentDigest": "sha256:" + "1" * 64},
            {"name": "@redact-secret/adapter", "version": "0.1.0", "contentDigest": "md5:abc"},
        ]
        for package in bad:
            self.assertTrue(PINS.validate_pin(pin(packages=[package])), package)
        twice = pin()["packages"][0]
        self.assertTrue(PINS.validate_pin(pin(packages=[twice, twice])))
        self.assertTrue(PINS.validate_pin(pin(packages=[])))


class ConsumerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "examples" / "mcp-redact").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_consumer(self, dependencies: dict) -> None:
        manifest = {"name": "consumer", "private": True, "dependencies": dependencies}
        (self.root / "examples" / "mcp-redact" / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    def test_specifiers_point_at_the_pinned_cache_relative_to_the_consumer(self) -> None:
        spec = PINS.expected_specifier(self.root, "examples/mcp-redact", COMMIT, pin()["packages"][1])
        self.assertEqual(spec, f"file:../../.cache/adapters/{COMMIT}/redact-secret-adapter-ai-context-0.1.0.tgz")

    def test_a_consumer_naming_exactly_the_pinned_tarballs_agrees(self) -> None:
        record = pin()
        self.write_consumer({})
        PINS.rewrite_consumers(record, self.root)
        self.assertEqual(PINS.check_consumers(record, self.root), [])

    def test_a_stale_commit_a_registry_version_or_an_unpinned_adapter_is_reported(self) -> None:
        record = pin()
        self.write_consumer({})
        PINS.rewrite_consumers(record, self.root)
        stale = pin(commit="b" * 40)
        self.assertEqual(len(PINS.check_consumers(stale, self.root)), 2)

        self.write_consumer(
            {
                "@redact-secret/adapter": "^0.1.0",
                "@redact-secret/adapter-ai-context": PINS.expected_specifier(
                    self.root, "examples/mcp-redact", COMMIT, record["packages"][1]
                ),
                "@redact-secret/adapter-pino": "file:../../somewhere/adapter-pino.tgz",
                "@redact-secret/adapter-otel": "^0.1.0",
            }
        )
        problems = PINS.check_consumers(record, self.root)
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("adapter-pino" in p for p in problems))
        self.assertFalse(any("adapter-otel" in p for p in problems))

    def test_a_missing_consumer_manifest_is_reported(self) -> None:
        self.assertEqual(len(PINS.check_consumers(pin(), self.root)), 1)


class DigestTest(unittest.TestCase):
    def test_the_digest_is_over_contents_not_archive_bytes_and_matches_the_installed_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {"package/package.json": b'{"name":"x"}', "package/dist/index.js": b"export {};\n"}
            write_tarball(root / "a.tgz", files)
            write_tarball(root / "b.tgz", dict(reversed(list(files.items()))))
            self.assertEqual(PINS.tarball_digest(root / "a.tgz"), PINS.tarball_digest(root / "b.tgz"))

            installed = root / "node_modules" / "x"
            (installed / "dist").mkdir(parents=True)
            (installed / "package.json").write_bytes(files["package/package.json"])
            (installed / "dist" / "index.js").write_bytes(files["package/dist/index.js"])
            self.assertEqual(PINS.installed_digest(installed), PINS.tarball_digest(root / "a.tgz"))

            (installed / "dist" / "index.js").write_bytes(b"export const tampered = 1;\n")
            self.assertNotEqual(PINS.installed_digest(installed), PINS.tarball_digest(root / "a.tgz"))

    def test_a_cached_tarball_that_does_not_match_its_pin_is_removed_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = pin()
            cache = PINS.cache_dir(root, COMMIT)
            cache.mkdir(parents=True)
            for package in record["packages"]:
                write_tarball(cache / PINS.tarball_name(package["name"], package["version"]), {"package/x": b"x"})
            with self.assertRaises(PINS.PinError):
                PINS.verified_tarballs(record, root)
            self.assertFalse((cache / "redact-secret-adapter-0.1.0.tgz").exists())

    def test_verify_installed_reports_a_missing_or_foreign_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = pin()
            self.assertEqual(len(PINS.verify_installed(record, root)), 2)


class AncestryTest(unittest.TestCase):
    def test_only_identical_or_ahead_means_the_pin_is_on_the_branch(self) -> None:
        for status, expected in [("identical", True), ("ahead", True), ("behind", False), ("diverged", False)]:
            completed = mock.Mock(stdout=f"{status}\n")
            with mock.patch.object(PINS.subprocess, "run", return_value=completed):
                self.assertEqual(PINS.gh_compare_is_ancestor(COMMIT, "develop"), expected, status)


class CommittedPinTest(unittest.TestCase):
    def test_the_committed_pin_is_valid_and_every_consumer_agrees(self) -> None:
        record = PINS.load_pin()
        self.assertEqual(PINS.validate_pin(record), [])
        self.assertEqual(PINS.check_consumers(record), [])


if __name__ == "__main__":
    unittest.main()
