from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-release-refs.py"
SPEC = importlib.util.spec_from_file_location("check_release_refs", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)

GUARD_STEP = (
    "      - name: Require main as the release source\n"
    "        if: ${{ github.ref != 'refs/heads/main' }}\n"
    "        run: exit 1\n"
    '      - run: python3 -B scripts/check-release-refs.py --candidate-ref "$GITHUB_REF"\n'
)


UNGUARDED_STEP = "      - run: publish\n"


def release_workflow(jobs: dict[str, bool]) -> str:
    """`jobs` maps job id -> whether it includes the ref guard."""
    body = "name: Release\njobs:\n"
    for job_name, guarded in jobs.items():
        body += (
            f"  {job_name}:\n"
            "    runs-on: ubuntu-latest\n"
            + ("    needs:\n" + "".join(f"      - {dep}\n" for dep in CHECK.TAG_NEEDS) if job_name == "tag-release" else "")
            + "    steps:\n"
            + (GUARD_STEP if guarded else UNGUARDED_STEP)
        )
    return body


def reconcile_workflow(*, guarded: bool = True, present: bool = True) -> str:
    if not present:
        return "name: Reconcile Release\njobs:\n  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: noop\n"
    return (
        "name: Reconcile Release\njobs:\n"
        "  reconcile:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        + (GUARD_STEP if guarded else "      - run: reconcile\n")
        + "  tag-reconciled-release:\n    runs-on: ubuntu-latest\n    steps:\n"
        + GUARD_STEP
    )


class Repository:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.release_jobs = {job: True for job in CHECK.RELEASE_JOBS}
        self.reconcile_guarded = True
        self.release_present = True
        self.reconcile_present = True

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def build(self) -> Path:
        if self.release_present:
            self.write(".github/workflows/release.yml", release_workflow(self.release_jobs))
        self.write(
            ".github/workflows/reconcile-release.yml",
            reconcile_workflow(guarded=self.reconcile_guarded, present=self.reconcile_present),
        )
        return self.root


class ValidateTests(unittest.TestCase):
    def run_validate(self, mutate=lambda repo: None) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(Path(tmp))
            mutate(repo)
            repo.build()
            return CHECK.validate(repo.root)

    def test_fully_guarded_workflows_pass(self) -> None:
        self.assertEqual(self.run_validate(), [])

    def test_publish_without_guard_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.release_jobs["publish"] = False

        errors = self.run_validate(mutate)
        self.assertTrue(
            any("publish" in error and "does not require main" in error for error in errors)
        )

    def test_publish_crates_without_guard_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.release_jobs["publish-crates"] = False

        errors = self.run_validate(mutate)
        self.assertTrue(
            any("publish-crates" in error and "does not require main" in error for error in errors)
        )

    def test_reconcile_without_guard_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_guarded = False

        errors = self.run_validate(mutate)
        self.assertTrue(
            any("reconcile" in error and "does not require main" in error for error in errors)
        )

    def test_missing_reconcile_job_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_present = False

        errors = self.run_validate(mutate)
        self.assertTrue(any("missing job 'reconcile'" in error for error in errors))

    def test_missing_release_workflow_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.release_present = False

        errors = self.run_validate(mutate)
        self.assertTrue(any("release.yml" in error and "missing workflow" in error for error in errors))

    def test_each_publisher_and_tagger_requires_a_guard(self) -> None:
        for job in CHECK.RELEASE_JOBS:
            with self.subTest(job=job):
                errors = self.run_validate(lambda repo: repo.release_jobs.update({job: False}))
                self.assertTrue(any(job in error and "require main" in error for error in errors))

    def test_tag_must_wait_for_each_registry_and_install_check(self) -> None:
        for dependency in CHECK.TAG_NEEDS:
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as tmp:
                repo = Repository(Path(tmp))
                repo.build()
                path = repo.root / ".github/workflows/release.yml"
                path.write_text(path.read_text().replace(f"      - {dependency}\n", ""))
                self.assertIn(f"tag-release must depend on {dependency}", CHECK.validate(repo.root))

    def test_missing_version_check_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(Path(tmp))
            repo.build()
            path = repo.root / ".github/workflows/release.yml"
            path.write_text(path.read_text().replace(CHECK.CANDIDATE_CHECK, "echo skipped", 1))
            self.assertTrue(any("candidate version validation" in error for error in CHECK.validate(repo.root)))

    def test_rc_only_guard_is_rejected(self) -> None:
        self.assertFalse(CHECK.requires_main("if: ${{ !startsWith(github.ref, 'refs/heads/rc/') }}"))

    def test_tag_creation_in_publish_job_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(Path(tmp))
            repo.build()
            path = repo.root / ".github/workflows/release.yml"
            path.write_text(path.read_text().replace("    steps:\n", '    steps:\n      - run: gh api /git/tags\n', 1))
            self.assertTrue(any("only be created by tag-release" in error for error in CHECK.validate(repo.root)))


class ReleaseSourceIdentityTests(unittest.TestCase):
    def test_main_accepts_stable_and_beta_versions(self) -> None:
        for version in ("0.1.0-beta.1", "1.0.0"):
            self.assertEqual(CHECK.validate_candidate_ref("refs/heads/main", version), [])

    def test_wrong_refs_versions_and_channels_fail(self) -> None:
        for ref, version in (
            ("refs/heads/rc/0.1.0-beta.1", "0.1.0-beta.1"),
            ("refs/tags/rc/0.1.0-beta.1", "0.1.0-beta.1"),
            ("refs/heads/feature/release", "1.0.0"),
            ("refs/heads/main", "1.0.0-alpha.1"),
            ("refs/heads/main", "01.0.0"),
        ):
            with self.subTest(ref=ref, version=version):
                self.assertTrue(CHECK.validate_candidate_ref(ref, version))


if __name__ == "__main__":
    unittest.main()
