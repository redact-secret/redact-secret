from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-json-path-citations.py"
SPEC = importlib.util.spec_from_file_location("check_json_path_citations", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class Repository:
    """A minimal tracked-file set for `validate`, without a real `git` repo."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: list[str] = []

    def write(self, relative: str, content: str) -> str:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.files.append(relative)
        return relative


class CheckJsonPathCitationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Repository(Path(self.directory.name))

    def validate(self) -> list[str]:
        return CHECK.validate(self.repo.root, self.repo.files)

    def assertOneError(self, fragment: str) -> None:
        errors = self.validate()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(fragment, errors[0])

    def test_a_citation_to_a_real_path_passes(self) -> None:
        self.repo.write("docs/contracts/precision/precision-contracts.json", "{}\n")
        self.repo.write(
            "conformance/fixtures/synchronous-corpus.json",
            '{"fixtures": [{"note": "See docs/contracts/precision/precision-contracts.json."}]}\n',
        )
        self.assertEqual(self.validate(), [])

    def test_a_dangling_citation_is_rejected(self) -> None:
        self.repo.write(
            "conformance/fixtures/synchronous-corpus.json",
            '{"fixtures": [{"note": "Moved to docs/audits/evidence/367/precision-contracts.json."}]}\n',
        )
        self.assertOneError(
            "dangling path citation 'docs/audits/evidence/367/precision-contracts.json'"
        )

    def test_a_dangling_citation_under_reference_is_rejected(self) -> None:
        self.repo.write(
            "docs/coverage/precision-context-matrix.json",
            '{"reference": "docs/contracts/precision/does-not-exist.json"}\n',
        )
        self.assertOneError(
            "dangling path citation 'docs/contracts/precision/does-not-exist.json'"
        )

    def test_a_citation_outside_note_or_reference_is_ignored(self) -> None:
        self.repo.write(
            "conformance/fixtures/synchronous-corpus.json",
            '{"fixtures": [{"input": "docs/audits/evidence/367/precision-contracts.json"}]}\n',
        )
        self.assertEqual(self.validate(), [])

    def test_frozen_evidence_archive_is_excluded(self) -> None:
        self.repo.write(
            "docs/audits/evidence/475/shape-inventory.json",
            '{"note": "comparable to docs/audits/evidence/367/precision-contracts.json"}\n',
        )
        self.assertEqual(self.validate(), [])

    def test_frozen_release_records_are_excluded(self) -> None:
        self.repo.write(
            "docs/releases/0.1.0-beta.6/manifest.json",
            '{"note": "built from docs/audits/evidence/367/precision-contracts.json"}\n',
        )
        self.assertEqual(self.validate(), [])

    def test_a_prose_mention_without_a_path_shape_is_ignored(self) -> None:
        self.repo.write(
            "conformance/fixtures/synchronous-corpus.json",
            '{"fixtures": [{"note": "docker-pat-oat-exact-length-partitions carries the shape."}]}\n',
        )
        self.assertEqual(self.validate(), [])

    def test_a_malformed_json_file_is_skipped_without_crashing(self) -> None:
        self.repo.write("conformance/fixtures/broken.json", "{not json")
        self.assertEqual(self.validate(), [])


if __name__ == "__main__":
    unittest.main()
