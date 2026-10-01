from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "install-opengrep.py"
SPEC = importlib.util.spec_from_file_location("install_opengrep", SCRIPT)
assert SPEC and SPEC.loader
INSTALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALL
SPEC.loader.exec_module(INSTALL)

GOOD_BINARY = b"pretend-opengrep-binary-bytes"
GOOD_SHA256 = INSTALL.sha256_hex(GOOD_BINARY)

LOCK = {
    "opengrep_version": "1.30.0",
    "signing": {
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "certificate_identity_regexp": r"^https://github\.com/opengrep/opengrep/",
    },
    "binaries": {
        "fake-platform": {"asset": "opengrep_fake", "sha256": GOOD_SHA256},
    },
}


def fake_downloader(assets: dict[str, bytes]):
    def download(url: str) -> bytes:
        for suffix, content in assets.items():
            if url.endswith(suffix):
                return content
        raise AssertionError(f"unexpected download url {url}")

    return download


def cosign_result(returncode: int, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


class DetectPlatformKeyTest(unittest.TestCase):
    def test_macos_arm64_maps_to_macos_arm64(self) -> None:
        with (
            mock.patch.object(INSTALL.platform, "system", return_value="Darwin"),
            mock.patch.object(INSTALL.platform, "machine", return_value="arm64"),
        ):
            self.assertEqual(INSTALL.detect_platform_key(), "macos-arm64")

    def test_linux_glibc_maps_to_gnu_variant(self) -> None:
        with (
            mock.patch.object(INSTALL.platform, "system", return_value="Linux"),
            mock.patch.object(INSTALL.platform, "machine", return_value="x86_64"),
            mock.patch.object(INSTALL.os, "confstr", return_value="glibc 2.35"),
        ):
            self.assertEqual(INSTALL.detect_platform_key(), "linux-x86_64-gnu")

    def test_linux_without_glibc_confstr_maps_to_musl_variant(self) -> None:
        def raise_value_error(name: str) -> str:
            raise ValueError(name)

        with (
            mock.patch.object(INSTALL.platform, "system", return_value="Linux"),
            mock.patch.object(INSTALL.platform, "machine", return_value="x86_64"),
            mock.patch.object(INSTALL.os, "confstr", side_effect=raise_value_error),
        ):
            self.assertEqual(INSTALL.detect_platform_key(), "linux-x86_64-musl")

    def test_unsupported_platform_fails_closed(self) -> None:
        with (
            mock.patch.object(INSTALL.platform, "system", return_value="Windows"),
            mock.patch.object(INSTALL.platform, "machine", return_value="AMD64"),
        ):
            with self.assertRaises(INSTALL.VerificationFailed):
                INSTALL.detect_platform_key()


class InstallTamperTest(unittest.TestCase):
    def test_installs_when_checksum_and_signature_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            path = INSTALL.install(
                lock=LOCK,
                platform_key="fake-platform",
                cache_dir=Path(cache_dir),
                downloader=fake_downloader(
                    {
                        "opengrep_fake": GOOD_BINARY,
                        "opengrep_fake.cert": b"cert",
                        "opengrep_fake.sig": b"sig",
                    }
                ),
                cosign_runner=lambda args: cosign_result(0),
            )
            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), GOOD_BINARY)

    def test_tampered_binary_fails_closed_on_checksum_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            with self.assertRaises(INSTALL.VerificationFailed) as ctx:
                INSTALL.install(
                    lock=LOCK,
                    platform_key="fake-platform",
                    cache_dir=Path(cache_dir),
                    downloader=fake_downloader(
                        {
                            "opengrep_fake": b"a-different-binary-someone-swapped-in",
                            "opengrep_fake.cert": b"cert",
                            "opengrep_fake.sig": b"sig",
                        }
                    ),
                    cosign_runner=lambda args: self.fail("cosign must not run after a checksum mismatch"),
                )
            self.assertIn("sha256 mismatch", str(ctx.exception))
            self.assertFalse((Path(cache_dir) / "1.30.0" / "fake-platform" / "opengrep").exists())

    def test_forged_signature_fails_closed_and_leaves_no_binary(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            with self.assertRaises(INSTALL.VerificationFailed) as ctx:
                INSTALL.install(
                    lock=LOCK,
                    platform_key="fake-platform",
                    cache_dir=Path(cache_dir),
                    downloader=fake_downloader(
                        {
                            "opengrep_fake": GOOD_BINARY,
                            "opengrep_fake.cert": b"forged-cert",
                            "opengrep_fake.sig": b"forged-sig",
                        }
                    ),
                    cosign_runner=lambda args: cosign_result(1, stderr="no matching signatures"),
                )
            self.assertIn("cosign rejected", str(ctx.exception))
            final_path = Path(cache_dir) / "1.30.0" / "fake-platform" / "opengrep"
            self.assertFalse(final_path.exists())
            tmp_path = Path(cache_dir) / "1.30.0" / "fake-platform" / ".opengrep_fake.tmp"
            self.assertFalse(tmp_path.exists(), "a forged-signature binary must not survive verification")

    def test_missing_cosign_fails_closed_rather_than_skipping_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:

            def missing_cosign(args: list[str]) -> subprocess.CompletedProcess[str]:
                raise FileNotFoundError("cosign")

            with self.assertRaises(INSTALL.VerificationFailed) as ctx:
                INSTALL.install(
                    lock=LOCK,
                    platform_key="fake-platform",
                    cache_dir=Path(cache_dir),
                    downloader=fake_downloader(
                        {
                            "opengrep_fake": GOOD_BINARY,
                            "opengrep_fake.cert": b"cert",
                            "opengrep_fake.sig": b"sig",
                        }
                    ),
                    cosign_runner=missing_cosign,
                )
            self.assertIn("not installed", str(ctx.exception))

    def test_unpinned_platform_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            with self.assertRaises(INSTALL.VerificationFailed) as ctx:
                INSTALL.install(
                    lock=LOCK,
                    platform_key="platform-nobody-pinned",
                    cache_dir=Path(cache_dir),
                    downloader=fake_downloader({}),
                    cosign_runner=lambda args: self.fail("must not download for an unpinned platform"),
                )
            self.assertIn("no pinned binary for platform", str(ctx.exception))

    def test_tampered_cache_entry_is_rejected_and_refetched(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            dest_dir = Path(cache_dir) / "1.30.0" / "fake-platform"
            dest_dir.mkdir(parents=True)
            (dest_dir / "opengrep").write_bytes(b"a binary someone dropped in the cache by hand")

            path = INSTALL.install(
                lock=LOCK,
                platform_key="fake-platform",
                cache_dir=Path(cache_dir),
                downloader=fake_downloader(
                    {
                        "opengrep_fake": GOOD_BINARY,
                        "opengrep_fake.cert": b"cert",
                        "opengrep_fake.sig": b"sig",
                    }
                ),
                cosign_runner=lambda args: cosign_result(0),
            )
            self.assertEqual(path.read_bytes(), GOOD_BINARY)

    def test_valid_cache_entry_is_reused_without_downloading(self) -> None:
        with tempfile.TemporaryDirectory() as cache_dir:
            dest_dir = Path(cache_dir) / "1.30.0" / "fake-platform"
            dest_dir.mkdir(parents=True)
            (dest_dir / "opengrep").write_bytes(GOOD_BINARY)

            def fail_download(url: str) -> bytes:
                raise AssertionError("a verified cache hit must not re-download")

            path = INSTALL.install(
                lock=LOCK,
                platform_key="fake-platform",
                cache_dir=Path(cache_dir),
                downloader=fail_download,
                cosign_runner=lambda args: self.fail("a verified cache hit must not re-verify"),
            )
            self.assertEqual(path.read_bytes(), GOOD_BINARY)


if __name__ == "__main__":
    unittest.main()
