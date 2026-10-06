from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-historical-permalinks.py"
SPEC = importlib.util.spec_from_file_location("check_historical_permalinks", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

BASE = "https://github.com/redact-secret/redact-secret"
REVIEW = "# Review\n\n## Findings\n\nText.\n\n## Findings\n\nAgain.\n\n<a id=\"custom-anchor\"></a>\n"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Repo:
    """A throwaway git repository whose `main` stands in for origin/main."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "T")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True).stdout.strip()

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.git("add", "--", relative)

    def commit(self, message: str = "c") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")


def link(sha: str, path: str, fragment: str = "", kind: str = "blob") -> str:
    return f"{BASE}/{kind}/{sha}/{path}" + (f"#{fragment}" if fragment else "")


class HistoricalPermalinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Repo(Path(self.directory.name))
        self.repo.write("docs/audits/review.md", REVIEW)
        self.repo.write("docs/audits/evidence/9/a.txt", "alpha\nbeta\n")
        self.pin = self.repo.commit("pin")

    def check(self, text: str, **kwargs) -> tuple[list[str], dict[str, int]]:
        self.repo.write("docs/doc.md", text)
        repo = CHECK.Repo(self.repo.root, **kwargs)
        return CHECK.validate(repo, ["docs/doc.md"])

    def test_valid_permalinks_pass(self) -> None:
        text = "\n".join(
            [
                link(self.pin, "docs/audits/review.md"),
                link(self.pin, "docs/audits/review.md", "findings"),
                link(self.pin, "docs/audits/review.md", "findings-1"),
                link(self.pin, "docs/audits/review.md", "custom-anchor"),
                link(self.pin, "docs/audits/evidence/9/a.txt", "L2"),
                link(self.pin, "docs/audits/evidence/9", kind="tree"),
            ]
        )
        errors, stats = self.check(text)
        self.assertEqual(errors, [])
        self.assertEqual(stats["links"], 6)

    def test_missing_path_is_detected(self) -> None:
        errors, _ = self.check(link(self.pin, "docs/audits/gone.md"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("docs/audits/gone.md does not exist at", errors[0])
        self.assertTrue(errors[0].startswith("docs/doc.md:"))

    def test_unreachable_commit_is_detected(self) -> None:
        self.repo.git("checkout", "-q", "-b", "side")
        self.repo.write("docs/audits/side.md", "# Side\n")
        side = self.repo.commit("side")
        self.repo.git("checkout", "-q", "main")
        errors, _ = self.check(link(side, "docs/audits/side.md"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(f"{side} is not an ancestor of main", errors[0])

    def test_commit_missing_from_history_is_reported_not_passed(self) -> None:
        absent = "f" * 40
        errors, stats = self.check(link(absent, "docs/audits/review.md"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("is not in the local history", errors[0])
        self.assertEqual(stats["missing_commits"], 1)

    def test_wrong_anchor_is_detected(self) -> None:
        errors, _ = self.check(link(self.pin, "docs/audits/review.md", "no-such-heading"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("anchor #no-such-heading is not a heading", errors[0])

    def test_line_anchor_past_end_is_detected(self) -> None:
        errors, _ = self.check(link(self.pin, "docs/audits/evidence/9/a.txt", "L9"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("past the end", errors[0])

    def test_anchor_on_a_non_markdown_file_is_not_silently_accepted(self) -> None:
        errors, _ = self.check(link(self.pin, "docs/audits/evidence/9/a.txt", "section"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("cannot be checked", errors[0])

    def test_blob_link_to_a_directory_is_detected(self) -> None:
        errors, _ = self.check(link(self.pin, "docs/audits/evidence/9"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("use `tree`", errors[0])

    def test_invalid_digest_in_a_checksum_bundle_is_detected(self) -> None:
        good = sha256("alpha\nbeta\n")
        self.repo.write("docs/audits/evidence/8/a.txt", "alpha\nbeta\n")
        self.repo.write("docs/audits/evidence/8/b.txt", "gamma\n")
        self.repo.write("docs/audits/evidence/8/SHA256SUMS.txt", f"{good}  a.txt\n{'0' * 64}  b.txt\n")
        pin = self.repo.commit("bundle")
        errors, _ = self.check(link(pin, "docs/audits/evidence/8/SHA256SUMS.txt"))
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("invalid digest for docs/audits/evidence/8/b.txt", errors[0])

    def test_valid_checksum_bundle_and_missing_listed_file(self) -> None:
        self.repo.write("docs/audits/evidence/8/a.txt", "alpha\n")
        self.repo.write("docs/audits/evidence/8/SHA256SUMS.txt", f"{sha256('alpha' + chr(10))}  a.txt\n")
        pin = self.repo.commit("bundle")
        self.assertEqual(self.check(link(pin, "docs/audits/evidence/8/SHA256SUMS.txt"))[0], [])
        self.repo.write("docs/audits/evidence/7/SHA256SUMS.txt", f"{'1' * 64}  absent.txt\n")
        pin = self.repo.commit("bundle2")
        errors, _ = self.check(link(pin, "docs/audits/evidence/7/SHA256SUMS.txt"))
        self.assertIn("does not exist at", errors[0])

    def digest_record(self, digest: str) -> None:
        record = {"readiness": {"review": {"path": "docs/audits/review.md", "sha256": digest}}}
        self.repo.write("docs/releases/1/artifact-inventory.json", json.dumps(record))

    def test_digest_record_of_a_retired_file_is_verified_against_its_permalink(self) -> None:
        review = link(self.pin, "docs/audits/review.md")
        self.digest_record(sha256(REVIEW))
        (self.repo.root / "docs/audits/review.md").unlink()
        self.repo.write("docs/releases/1/README.md", review)
        repo = CHECK.Repo(self.repo.root)
        errors, stats = CHECK.validate(repo, ["docs/releases/1/README.md", "docs/releases/1/artifact-inventory.json"])
        self.assertEqual(errors, [])
        self.digest_record("0" * 64)
        errors, _ = CHECK.validate(repo, ["docs/releases/1/README.md", "docs/releases/1/artifact-inventory.json"])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("invalid digest for docs/audits/review.md", errors[0])

    def test_digest_record_without_a_permalink_is_counted_not_hidden(self) -> None:
        self.digest_record(sha256(REVIEW))
        (self.repo.root / "docs/audits/review.md").unlink()
        repo = CHECK.Repo(self.repo.root)
        errors, stats = CHECK.validate(repo, ["docs/releases/1/artifact-inventory.json"])
        self.assertEqual(errors, [])
        self.assertEqual(stats["digest_unresolved"], 1)

    def test_no_main_ref_is_unavailable_not_a_pass(self) -> None:
        self.repo.git("branch", "-m", "trunk")
        with self.assertRaises(CHECK.Unavailable) as raised:
            CHECK.Repo(self.repo.root)
        self.assertIn("--no-ancestry", str(raised.exception))
        errors, _ = self.check(link(self.pin, "docs/audits/review.md"), check_ancestry=False)
        self.assertEqual(errors, [])

    def test_main_exit_codes(self) -> None:
        def run(*args: str) -> tuple[int, str]:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = CHECK.main([str(self.repo.root), *args])
            return code, out.getvalue()

        self.repo.write("docs/doc.md", link(self.pin, "docs/audits/review.md"))
        self.assertEqual(run()[0], 0)
        self.repo.write("docs/doc.md", link(self.pin, "docs/audits/nope.md"))
        code, output = run()
        self.assertEqual(code, 1)
        self.assertIn("ERROR docs/doc.md", output)
        self.repo.write("docs/doc.md", link("e" * 40, "docs/audits/review.md"))
        code, output = run()
        self.assertEqual(code, 2)
        self.assertIn("UNAVAILABLE", output)

    def test_main_ancestry_skip_is_stated(self) -> None:
        self.repo.git("branch", "-m", "trunk")
        self.repo.write("docs/doc.md", link(self.pin, "docs/audits/review.md"))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECK.main([str(self.repo.root), "--no-ancestry"]), 0)
        self.assertIn("ancestry NOT checked", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(CHECK.main([str(self.repo.root)]), 2)
        self.assertIn("UNAVAILABLE no main ref", out.getvalue())


class RetirementPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Repo(Path(self.directory.name))
        self.repo.write("docs/audits/a.md", "# A\n")
        self.repo.write("docs/audits/evidence/1/data.txt", "data\n")
        self.repo.write("docs/audits/evidence/1/SHA256SUMS.txt", f"{sha256('data' + chr(10))}  data.txt\n")
        self.repo.write(
            "docs/releases/1/artifact-inventory.json",
            json.dumps({"review": {"path": "docs/audits/a.md", "sha256": sha256("# A\n")}}),
        )
        self.pin = self.repo.commit("pin")

    def run_pin(self, pin: str | None = None) -> list[str]:
        repo = CHECK.Repo(self.repo.root)
        return CHECK.retirement_errors(repo, pin or self.pin, ["docs/audits/"])[0]

    def test_a_faithful_pin_passes(self) -> None:
        self.assertEqual(self.run_pin(), [])

    def test_a_file_changed_since_the_pin_is_detected(self) -> None:
        self.repo.write("docs/audits/a.md", "# A, edited\n")
        self.repo.commit("edit")
        errors = self.run_pin()
        self.assertTrue(any("docs/audits/a.md: differs from the tree being removed" in e for e in errors), errors)

    def test_a_file_added_after_the_pin_is_detected(self) -> None:
        self.repo.write("docs/audits/b.md", "# B\n")
        self.repo.commit("add")
        errors = self.run_pin()
        self.assertEqual(errors, ["docs/audits/b.md: does not exist at pin " + self.pin[:12]])

    def test_a_pin_off_main_is_rejected(self) -> None:
        self.repo.git("checkout", "-q", "-b", "side")
        self.repo.write("docs/audits/c.md", "# C\n")
        side = self.repo.commit("side")
        self.repo.git("checkout", "-q", "main")
        self.assertIn("is not an ancestor of main", self.run_pin(side)[0])

    def test_an_invalid_digest_record_is_detected(self) -> None:
        self.repo.write(
            "docs/releases/1/artifact-inventory.json",
            json.dumps({"review": {"path": "docs/audits/a.md", "sha256": "0" * 64}}),
        )
        pin = self.repo.commit("bad digest")
        errors = self.run_pin(pin)
        self.assertTrue(any("invalid digest for docs/audits/a.md" in e for e in errors), errors)

    def test_an_invalid_checksum_bundle_is_detected(self) -> None:
        self.repo.write("docs/audits/evidence/1/SHA256SUMS.txt", f"{'0' * 64}  data.txt\n")
        pin = self.repo.commit("bad sums")
        errors = self.run_pin(pin)
        self.assertTrue(any("invalid digest for docs/audits/evidence/1/data.txt" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
