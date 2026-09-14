#!/usr/bin/env python3
"""Enforce that `release.yml` cannot publish without the qualification set.

Issue #77 (`RB-7`) requires that the `publish` job in
`.github/workflows/release.yml` is unreachable unless every job in the
required qualification set has succeeded for the exact commit being
released. Issue #34's acceptance criterion "build and test all artifacts
before any registry publication step is eligible" extends that requirement to
every registry publish job -- npm, crates.io, and PyPI alike -- so this script
also fails when `publish-crates` or `publish-pypi` stop declaring the same
qualification set in `needs:`, not just `publish`. This script fails when
that graph drifts: a required reusable workflow call job is removed, its
`uses:` target is repointed, or a publish job stops declaring it in `needs:`.

`REQUIRED_GATES` is the qualification set this repository enforces before any
job in `PUBLISH_JOBS` may run.

Issue #141 adds a second, npm-specific ordering requirement: the `publish`
job (the `@redact-secret/core` wrapper) must also declare
`NPM_DEPENDENCY_GATES` in `needs:`, so the wrapper cannot become eligible
before every runtime dependency package (`@redact-secret/node-<platform>`
x6 and `@redact-secret/wasm`) has been packed, content-checked,
published, and verified at its declared version. This is what makes the
first cutover and every routine release after it the same graph rather than
two: there is no separate "cutover mode" that could be skipped by mistake,
because the wrapper's own `needs:` makes the dependency gate unconditional.

This intentionally parses the workflow YAML with plain text and regular
expressions rather than a YAML library, matching
`check-python-package.py`'s wheel-matrix check: no third-party dependency is
declared for the scripts in this directory.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RELEASE_WORKFLOW = Path(".github") / "workflows" / "release.yml"

# job id -> the reusable workflow it must call.
REQUIRED_GATES = {
    "ci": "./.github/workflows/ci.yml",
    "python-wheels": "./.github/workflows/python-wheels.yml",
    "artifact-qualification": "./.github/workflows/artifact-qualification.yml",
}

# Every job that publishes to a registry. Each one must declare the full
# REQUIRED_GATES set in `needs:` -- a partial gate on one registry's publish
# job while another one publishes unqualified would defeat the point of the
# qualification set.
PUBLISH_JOBS = ("publish", "publish-crates", "publish-pypi")

# The npm dependency packages the wrapper (`publish`) must not be publishable
# ahead of. crates.io and PyPI have no equivalent dependency-package gate, so
# this applies to `publish` alone, not every job in PUBLISH_JOBS.
NPM_DEPENDENCY_GATES = ("publish-native-dependencies", "publish-wasm-dependency")

JOB_HEADER_PREFIX = "  "
ATTRIBUTE_PREFIX = "    "
LIST_ITEM_PREFIX = "      - "


def jobs_section(text: str) -> str:
    """Return the text of the `jobs:` mapping, excluding everything above it.

    Restricting to this slice keeps job-id detection from matching unrelated
    two-space-indented keys, such as `on:`'s `workflow_dispatch:`.
    """
    for line_start, line in _line_starts(text):
        if line == "jobs:":
            return text[line_start + len(line) + 1 :]
    raise ValueError(f"{RELEASE_WORKFLOW.as_posix()}: no jobs: section found")


def _line_starts(text: str) -> list[tuple[int, str]]:
    starts = []
    offset = 0
    for line in text.splitlines():
        starts.append((offset, line))
        offset += len(line) + 1
    return starts


def job_blocks(text: str) -> dict[str, str]:
    """Map each top-level job id in a `jobs:` slice to its body text."""
    lines = _line_starts(text)
    headers = [
        (offset, line[len(JOB_HEADER_PREFIX) : -1])
        for offset, line in lines
        if line.startswith(JOB_HEADER_PREFIX)
        and not line.startswith(ATTRIBUTE_PREFIX)
        and line.endswith(":")
    ]
    blocks: dict[str, str] = {}
    for index, (offset, job_id) in enumerate(headers):
        start = offset + len(JOB_HEADER_PREFIX) + len(job_id) + 1
        end = headers[index + 1][0] if index + 1 < len(headers) else len(text)
        blocks[job_id] = text[start:end]
    return blocks


def extract_uses(job_body: str) -> str | None:
    for line in job_body.splitlines():
        if line.startswith(ATTRIBUTE_PREFIX + "uses:"):
            return line[len(ATTRIBUTE_PREFIX + "uses:") :].strip()
    return None


def extract_needs(job_body: str) -> list[str]:
    lines = job_body.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(ATTRIBUTE_PREFIX + "needs:"):
            continue
        inline = line[len(ATTRIBUTE_PREFIX + "needs:") :].strip()
        if inline:
            return [item.strip() for item in inline.strip("[]").split(",") if item.strip()]
        items = []
        for later in lines[index + 1 :]:
            if not later.startswith(LIST_ITEM_PREFIX):
                break
            items.append(later[len(LIST_ITEM_PREFIX) :].strip())
        return items
    return []


def has_workflow_call_trigger(text: str) -> bool:
    return any(line.strip() == "workflow_call:" for line in text.splitlines())


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    release_path = root / RELEASE_WORKFLOW
    if not release_path.is_file():
        return [f"{RELEASE_WORKFLOW.as_posix()}: missing release workflow"]

    jobs = job_blocks(jobs_section(release_path.read_text(encoding="utf-8")))

    for gate, expected_uses in REQUIRED_GATES.items():
        body = jobs.get(gate)
        if body is None:
            errors.append(f"{RELEASE_WORKFLOW.as_posix()}: missing required gate job '{gate}'")
            continue
        actual_uses = extract_uses(body)
        if actual_uses != expected_uses:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: job '{gate}' must call {expected_uses}, found {actual_uses!r}"
            )
        called_workflow = root / Path(expected_uses.removeprefix("./"))
        if called_workflow.is_file() and not has_workflow_call_trigger(
            called_workflow.read_text(encoding="utf-8")
        ):
            errors.append(f"{called_workflow.as_posix()}: does not expose workflow_call")

    for publish_job in PUBLISH_JOBS:
        publish = jobs.get(publish_job)
        if publish is None:
            errors.append(f"{RELEASE_WORKFLOW.as_posix()}: missing {publish_job} job")
            continue
        needs = set(extract_needs(publish))
        missing = sorted(set(REQUIRED_GATES) - needs)
        if missing:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: {publish_job} job does not need {', '.join(missing)}"
            )

    for dependency_job in NPM_DEPENDENCY_GATES:
        if dependency_job not in jobs:
            errors.append(f"{RELEASE_WORKFLOW.as_posix()}: missing required job '{dependency_job}'")

    publish = jobs.get("publish")
    if publish is not None:
        needs = set(extract_needs(publish))
        missing = sorted(set(NPM_DEPENDENCY_GATES) - needs)
        if missing:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: publish job does not need {', '.join(missing)} "
                "-- the wrapper must not be publishable ahead of its runtime dependency packages"
            )

    reconcile_path = root / ".github/workflows/reconcile-release.yml"
    if reconcile_path.is_file():
        reconcile = reconcile_path.read_text(encoding="utf-8")
        if not re.search(
            r'^\s+chmod 0644 "\$package_dir"/\$asset_glob\s*$', reconcile, re.M
        ):
            errors.append(
                f"{reconcile_path.relative_to(root).as_posix()}: recovered npm package assets "
                "must be normalized to mode 0644 before packing"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    args = parser.parse_args()

    errors = validate(Path(args.root).resolve())
    for error in errors:
        print(f"ERROR {error}")
    print(f"Release gate check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
