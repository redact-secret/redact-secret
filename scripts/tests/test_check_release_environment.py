from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-release-environment.py"
SPEC = importlib.util.spec_from_file_location("check_release_environment", SCRIPT)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def release_workflow(environment: str | None) -> str:
    environment_block = f"    environment:\n      name: {environment}\n" if environment else ""
    return (
        "name: Release\njobs:\n"
        "  publish:\n"
        "    runs-on: ubuntu-latest\n"
        f"{environment_block}"
        "    steps:\n"
        "      - run: publish\n"
    )


def reconcile_workflow(environment: str | None, *, shorthand: bool = False) -> str:
    if not environment:
        environment_block = ""
    elif shorthand:
        environment_block = f"    environment: {environment}\n"
    else:
        environment_block = f"    environment:\n      name: {environment}\n"
    return (
        "name: Reconcile Release\njobs:\n"
        "  reconcile:\n"
        "    runs-on: ubuntu-latest\n"
        f"{environment_block}"
        "    steps:\n"
        "      - run: reconcile\n"
    )


class Repository:
    """Builds a minimal repository that satisfies the check."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.release_environment: str | None = "release"
        self.reconcile_environment: str | None = "release"
        self.reconcile_shorthand = False
        self.release_present = True
        self.reconcile_present = True

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def build(self) -> Path:
        if self.release_present:
            self.write(".github/workflows/release.yml", release_workflow(self.release_environment))
        if self.reconcile_present:
            self.write(
                ".github/workflows/reconcile-release.yml",
                reconcile_workflow(self.reconcile_environment, shorthand=self.reconcile_shorthand),
            )
        return self.root


class ValidateTests(unittest.TestCase):
    def run_validate(self, mutate=lambda repo: None) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(Path(tmp))
            mutate(repo)
            repo.build()
            return CHECK.validate(repo.root)

    def test_matching_environments_pass(self) -> None:
        self.assertEqual(self.run_validate(), [])

    def test_shorthand_environment_syntax_passes(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_shorthand = True

        self.assertEqual(self.run_validate(mutate), [])

    def test_reconcile_without_an_environment_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_environment = None

        errors = self.run_validate(mutate)
        self.assertTrue(any("reconcile" in error and "declares no environment" in error for error in errors))

    def test_release_without_an_environment_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.release_environment = None

        errors = self.run_validate(mutate)
        self.assertTrue(any("publish" in error and "declares no environment" in error for error in errors))

    def test_mismatched_environments_fail(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_environment = "staging"

        errors = self.run_validate(mutate)
        self.assertTrue(any("staging" in error and "release" in error for error in errors))

    def test_missing_release_workflow_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.release_present = False

        errors = self.run_validate(mutate)
        self.assertTrue(any("release.yml" in error and "missing workflow" in error for error in errors))

    def test_missing_reconcile_workflow_fails(self) -> None:
        def mutate(repo: Repository) -> None:
            repo.reconcile_present = False

        errors = self.run_validate(mutate)
        self.assertTrue(any("reconcile-release.yml" in error and "missing workflow" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
