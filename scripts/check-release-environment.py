#!/usr/bin/env python3
"""Enforce that `Reconcile Release` is bound to the `Release` GitHub environment.

Both workflows hold `contents: write` and can create the `v{version}` tag.
`AGENTS.md`'s release authority section and issue #78's disposition (`RB-8`)
require every release-capable workflow to run under the same environment
protection, not just `Release`. Binding both jobs to the identical GitHub
environment name is what guarantees "at least the same protection": the
protection rules live on the environment itself, in repository settings, not
in this file, so two jobs that name the same environment always share them.

Checks, in order:

1. `.github/workflows/release.yml`'s `publish` job declares an `environment`.
2. `.github/workflows/reconcile-release.yml`'s `reconcile` job declares an
   `environment` naming the exact same environment.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RELEASE_WORKFLOW = Path(".github") / "workflows" / "release.yml"
RELEASE_JOB = "publish"

RECONCILE_WORKFLOW = Path(".github") / "workflows" / "reconcile-release.yml"
RECONCILE_JOB = "reconcile"

# A named top-level job block: `  <job-name>:` through the line before the
# next top-level job (or end of file). Workflow jobs are two-space indented
# directly under `jobs:`; everything inside a job is indented at least three
# spaces (or blank), so the body stops exactly at the next two-space job
# header instead of swallowing it.
JOB_BLOCK = re.compile(r"^  (?P<name>[A-Za-z][\w-]*):\n(?P<body>(?:[ \t]{3,}.*\n|[ \t]*\n)*)", re.M)

# `environment: <name>` (shorthand) or `environment:` followed by `name: <name>`.
ENVIRONMENT_SHORTHAND = re.compile(r"^\s*environment:\s*(\S+)\s*$", re.M)
ENVIRONMENT_BLOCK_NAME = re.compile(r"^\s*environment:\s*\n\s*name:\s*(\S+)\s*$", re.M)


def job_body(workflow_text: str, job_name: str) -> str | None:
    for match in JOB_BLOCK.finditer(workflow_text):
        if match.group("name") == job_name:
            return match.group("body")
    return None


def job_environment_name(workflow_text: str, job_name: str) -> str | None:
    """The environment `job_name` declares, or `None` if it declares none."""
    body = job_body(workflow_text, job_name)
    if body is None:
        return None
    block_match = ENVIRONMENT_BLOCK_NAME.search(body)
    if block_match:
        return block_match.group(1)
    shorthand_match = ENVIRONMENT_SHORTHAND.search(body)
    if shorthand_match:
        return shorthand_match.group(1)
    return None


def validate(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []

    release_path = root / RELEASE_WORKFLOW
    if not release_path.is_file():
        return [f"{RELEASE_WORKFLOW.as_posix()}: missing workflow"]
    release_text = release_path.read_text(encoding="utf-8")
    if job_body(release_text, RELEASE_JOB) is None:
        return [f"{RELEASE_WORKFLOW.as_posix()}: missing job {RELEASE_JOB!r}"]
    release_environment = job_environment_name(release_text, RELEASE_JOB)
    if not release_environment:
        errors.append(f"{RELEASE_WORKFLOW.as_posix()}: job {RELEASE_JOB!r} declares no environment")

    reconcile_path = root / RECONCILE_WORKFLOW
    if not reconcile_path.is_file():
        return errors + [f"{RECONCILE_WORKFLOW.as_posix()}: missing workflow"]
    reconcile_text = reconcile_path.read_text(encoding="utf-8")
    if job_body(reconcile_text, RECONCILE_JOB) is None:
        return errors + [f"{RECONCILE_WORKFLOW.as_posix()}: missing job {RECONCILE_JOB!r}"]
    reconcile_environment = job_environment_name(reconcile_text, RECONCILE_JOB)
    if not reconcile_environment:
        errors.append(f"{RECONCILE_WORKFLOW.as_posix()}: job {RECONCILE_JOB!r} declares no environment")
    elif release_environment and reconcile_environment != release_environment:
        errors.append(
            f"{RECONCILE_WORKFLOW.as_posix()}: job {RECONCILE_JOB!r} declares environment "
            f"{reconcile_environment!r}, which does not match {RELEASE_WORKFLOW.as_posix()}'s "
            f"{release_environment!r}"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    args = parser.parse_args()

    errors = validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Release environment check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
