from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-cross-repository-links.py"
SPEC = importlib.util.spec_from_file_location("check_cross_repository_links", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

CORE = "https://github.com/redact-secret/redact-secret"
BENCH = "https://github.com/redact-secret/redact-secret-benchmarks"
SHA = "a" * 40


def fake_resolver(existing: set[tuple[str, str, str]]):
    return lambda repo, ref, path: (repo, ref, path) in existing


def run(text: str, existing: set[tuple[str, str, str]]) -> list[str]:
    with tempfile.TemporaryDirectory() as temp:
        doc = Path(temp) / "doc.md"
        doc.write_text(text, encoding="utf-8")
        return CHECK.validate(CHECK.collect([doc]), fake_resolver(existing), Path(temp))


class ExtractTests(unittest.TestCase):
    def test_non_repository_url_is_ignored(self) -> None:
        text = "[a](https://example.com/redact-secret/x/blob/main/a.md) [b](https://github.com/other/x/blob/main/a.md)"
        self.assertEqual(CHECK.extract_links(text), set())

    def test_placeholders_are_ignored(self) -> None:
        text = f"{CORE}/blob/{{revision}}/a.md {CORE}/blob/<sha>/a.md {CORE}/blob/main/{{path}}"
        self.assertEqual(CHECK.extract_links(text), set())

    def test_anchor_query_and_trailing_punctuation_are_stripped(self) -> None:
        text = f"see ({BENCH}/blob/main/docs/a.md#L3). Also {CORE}/blob/main/b.md."
        self.assertEqual(
            CHECK.extract_links(text),
            {("redact-secret-benchmarks", "main", "docs/a.md"), ("redact-secret", "main", "b.md")},
        )


class ValidateTests(unittest.TestCase):
    def test_live_main_path_passes(self) -> None:
        self.assertEqual(run(f"{BENCH}/blob/main/docs/a.md", {("redact-secret-benchmarks", "main", "docs/a.md")}), [])

    def test_moved_main_path_fails(self) -> None:
        errors = run(f"{BENCH}/blob/main/docs/old.md", {("redact-secret-benchmarks", "main", "docs/new.md")})
        self.assertEqual(len(errors), 1)
        self.assertIn("docs/old.md does not exist on redact-secret-benchmarks main", errors[0])

    def test_valid_pinned_permalink_passes(self) -> None:
        self.assertEqual(run(f"{CORE}/blob/{SHA}/a.md", {("redact-secret", SHA, "a.md")}), [])

    def test_permalink_whose_path_did_not_exist_at_commit_fails(self) -> None:
        errors = run(f"{CORE}/blob/{SHA}/a.md", {("redact-secret", SHA, "b.md")})
        self.assertEqual(len(errors), 1)
        self.assertIn(f"does not exist at {SHA}", errors[0])

    def test_branch_ref_fails(self) -> None:
        errors = run(f"{CORE}/blob/workbench/1-x/a.md", set())
        self.assertEqual(len(errors), 1)
        self.assertIn("40-hex permalink", errors[0])

    def test_release_tag_is_resolved(self) -> None:
        self.assertEqual(run(f"{CORE}/blob/v0.1.0-beta.2/a.md", {("redact-secret", "v0.1.0-beta.2", "a.md")}), [])
        self.assertEqual(len(run(f"{CORE}/blob/v0.1.0-beta.2/a.md", set())), 1)

    def test_error_names_each_citing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            files = []
            for name in ("one.md", "two.md"):
                path = Path(temp) / name
                path.write_text(f"{CORE}/blob/main/gone.md", encoding="utf-8")
                files.append(path)
            errors = CHECK.validate(CHECK.collect(files), fake_resolver(set()), Path(temp))
        self.assertEqual([e.split(":")[0] for e in errors], ["one.md", "two.md"])


class UnavailableSourceTests(unittest.TestCase):
    """A remote source that cannot be reached is reported, never passed silently (issue #1264)."""

    def unreachable(self, repo: str, ref: str, path: str) -> bool:
        raise CHECK.Unverifiable(f"cannot reach {repo}@{ref}")

    def collect_one(self, text: str, temp: str) -> dict:
        doc = Path(temp) / "doc.md"
        doc.write_text(text, encoding="utf-8")
        return CHECK.collect([doc])

    def test_unverifiable_link_is_listed_and_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            links = self.collect_one(f"{BENCH}/blob/main/docs/a.md", temp)
            unverified: list[str] = []
            errors = CHECK.validate(links, self.unreachable, Path(temp), unverified)
        self.assertEqual(errors, [])
        self.assertEqual(len(unverified), 1)
        self.assertIn("doc.md: redact-secret-benchmarks/main/docs/a.md: cannot reach", unverified[0])

    def test_unverifiable_link_propagates_when_the_caller_does_not_collect_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            links = self.collect_one(f"{BENCH}/blob/main/docs/a.md", temp)
            with self.assertRaises(CHECK.Unverifiable):
                CHECK.validate(links, self.unreachable, Path(temp))

    def test_offline_resolver_uses_local_git_and_never_calls_gh(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = lambda *a: subprocess.run(
                ["git", "-C", temp, *a], check=True, capture_output=True, text=True
            ).stdout.strip()  # noqa: E731
            run("init", "-q", "-b", "main")
            run("config", "user.email", "t@example.invalid")
            run("config", "user.name", "T")
            (root / "a.md").write_text("x\n", encoding="utf-8")
            run("add", "a.md")
            run("commit", "-q", "-m", "c")
            sha = run("rev-parse", "HEAD")
            run("tag", "v0.1.0-beta.1")
            resolve = CHECK.make_resolver(root, "redact-secret/redact-secret", offline=True)
            self.assertTrue(resolve("redact-secret", sha, "a.md"))
            self.assertFalse(resolve("redact-secret", sha, "b.md"))
            self.assertTrue(resolve("redact-secret", "v0.1.0-beta.1", "a.md"))
            self.assertFalse(resolve("redact-secret", "v0.1.0-beta.1", "b.md"))
            with self.assertRaises(CHECK.Unverifiable):
                resolve("redact-secret", "b" * 40, "a.md")
            with self.assertRaises(CHECK.Unverifiable):
                resolve("redact-secret-benchmarks", "main", "a.md")

    def test_gh_failures_are_unverifiable_not_runtime_errors(self) -> None:
        original = CHECK.subprocess.run

        def broken(*args, **kwargs):
            raise FileNotFoundError("gh")

        CHECK.subprocess.run = broken
        try:
            with self.assertRaises(CHECK.Unverifiable):
                CHECK.gh_path_exists("redact-secret/x", "main", "a.md")
        finally:
            CHECK.subprocess.run = original

    def test_main_exit_status_separates_broken_from_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run = lambda *a: subprocess.run(["git", "-C", temp, *a], check=True, capture_output=True, text=True)  # noqa: E731
            run("init", "-q", "-b", "main")
            run("config", "user.email", "t@example.invalid")
            run("config", "user.name", "T")
            (Path(temp) / "doc.md").write_text(f"{BENCH}/blob/main/docs/a.md\n", encoding="utf-8")
            run("add", "doc.md")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(CHECK.main([temp, "--offline"]), 0)
            self.assertIn("UNVERIFIED", out.getvalue())
            self.assertIn("1 unverified", out.getvalue())
            original = CHECK.gh_path_exists
            CHECK.gh_path_exists = self.unreachable
            try:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(CHECK.main([temp]), 2)
            finally:
                CHECK.gh_path_exists = original
            self.assertIn("UNAVAILABLE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
