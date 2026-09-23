#!/usr/bin/env python3
"""Wheel selection for the clean-install qualification probe (issue #687)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from installed_wheel_probe import (  # noqa: E402
    installed_tags,
    select_wheel,
    wheel_file_tags,
)

# The published Linux artifact: one filename, two expanded tags. Matching a
# tag against the end of this filename is what failed before #687.
MANYLINUX = "redact_secret-0.1.0b6-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
MANYLINUX_METADATA = """Wheel-Version: 1.0
Generator: maturin (1.15.0)
Root-Is-Purelib: false
Tag: cp310-abi3-manylinux_2_17_x86_64
Tag: cp310-abi3-manylinux2014_x86_64
"""
MACOS = "redact_secret-0.1.0b6-cp310-abi3-macosx_11_0_arm64.whl"
MUSL = "redact_secret-0.1.0b6-cp310-abi3-musllinux_1_2_x86_64.whl"
WINDOWS = "redact_secret-0.1.0b6-cp310-abi3-win_amd64.whl"


class WheelFileTags(unittest.TestCase):
    def test_expands_a_compressed_platform_tag_set(self) -> None:
        self.assertEqual(
            wheel_file_tags(MANYLINUX),
            {
                "cp310-abi3-manylinux_2_17_x86_64",
                "cp310-abi3-manylinux2014_x86_64",
            },
        )

    def test_single_tag_filename_declares_exactly_that_tag(self) -> None:
        self.assertEqual(wheel_file_tags(MACOS), {"cp310-abi3-macosx_11_0_arm64"})

    def test_expands_every_component(self) -> None:
        self.assertEqual(
            wheel_file_tags("pkg-1.0-py2.py3-none-any.whl"),
            {"py2-none-any", "py3-none-any"},
        )

    def test_a_build_tag_does_not_shift_the_components(self) -> None:
        self.assertEqual(
            wheel_file_tags("pkg-1.0-1-cp310-abi3-win_amd64.whl"),
            {"cp310-abi3-win_amd64"},
        )

    def test_a_non_wheel_name_declares_nothing(self) -> None:
        self.assertEqual(wheel_file_tags("redact_secret-0.1.0b6.tar.gz"), set())
        self.assertEqual(wheel_file_tags("notawheel.whl"), set())


class SelectWheel(unittest.TestCase):
    def test_matches_the_manylinux_candidate_its_metadata_expands_to(self) -> None:
        self.assertEqual(
            select_wheel(installed_tags(MANYLINUX_METADATA), [MACOS, MANYLINUX, WINDOWS]),
            MANYLINUX,
        )

    def test_matches_a_single_tag_candidate(self) -> None:
        metadata = "Tag: cp310-abi3-macosx_11_0_arm64\n"
        self.assertEqual(select_wheel(installed_tags(metadata), [MACOS, MANYLINUX]), MACOS)

    def test_rejects_a_platform_no_candidate_provides(self) -> None:
        metadata = "Tag: cp310-abi3-macosx_10_12_x86_64\n"
        self.assertIsNone(select_wheel(installed_tags(metadata), [MANYLINUX, MUSL, WINDOWS]))

    def test_musllinux_does_not_satisfy_a_manylinux_install(self) -> None:
        metadata = "Tag: cp310-abi3-musllinux_1_2_x86_64\n"
        self.assertEqual(select_wheel(installed_tags(metadata), [MANYLINUX, MUSL]), MUSL)

    def test_no_candidates_means_no_selection(self) -> None:
        self.assertIsNone(select_wheel(installed_tags(MANYLINUX_METADATA), []))

    def test_metadata_without_tag_lines_selects_nothing(self) -> None:
        self.assertEqual(installed_tags("Wheel-Version: 1.0\n"), [])
        self.assertIsNone(select_wheel([], [MANYLINUX]))


if __name__ == "__main__":
    unittest.main()
