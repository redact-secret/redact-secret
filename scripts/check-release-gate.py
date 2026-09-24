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

Issue #417 pins a third thing this graph alone did not cover: `needs:` gets
the qualification jobs to run, but nothing verified that the `common` and
`full` browser artifacts `publish-wasm-dependency` is about to pack still are
what their package identities promise. This script now requires that job to
carry a `PROFILE_VERIFICATION_STEP` step, that it precedes `WASM_PUBLISH_STEP`
(packing an artifact nothing has just checked would defeat the point), and
that its body still asserts on both the `full` root artifact and the `common`
artifact -- not just whichever one a future edit happened to keep.

Issue #527 removed `python-wheels` from `REQUIRED_GATES`: this workflow used
to call `./.github/workflows/python-wheels.yml` a second time as its own
top-level job, on top of the call `artifact-qualification.yml` already makes
internally, so every Python wheel and the source distribution were built
twice from independent, non-byte-reproducible builds. `python-wheels.yml` is
now only ever invoked from inside `artifact-qualification`, which remains a
required gate. That structural fix removes the second build, but it does not
by itself prove the property the issue asks for -- this script additionally
requires `publish-pypi` to carry a `PYPI_DIGEST_STEP` step that precedes
`PYPI_PUBLISH_STEP`, so a runtime check comparing what is about to be
published against `artifact-qualification`'s own recorded inventory cannot be
silently deleted or reordered after the fact.

Issue #528 generalizes that same "cannot be silently deleted or reordered"
requirement to crates: `publish-crates` must carry a digest-verification step
for each crate that runs `scripts/verify-crate-digest.py`. Unlike the PyPI
and WASM checks, these run *after* their crate's publish step, not before --
crates.io only reports the published checksum once the crate is live, so
"verify, then publish" is not available here the way it is for an artifact
already sitting in a local `dist/` directory.

Issue #614 adds a quoting rule for both release workflows: a `run:` block
must not splice a `${{ needs.* }}` job output into shell source. Expression
substitution happens before the shell parses the script, so one apostrophe
in a job output (the wasm digest note) ended a single-quoted string and
failed the beta.6 manifest step. Job outputs must reach the script through
`env:` and be read as "$VAR" -- also the standard script-injection
mitigation.

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

# Issue #732: the wrapper's recorded identity must be the shasum of a built
# package, and the publish step must publish that exact tarball. Before
# `js:build`, `packages/javascript/dist/` does not exist, so an identity
# computed ahead of the build describes a tarball with no `dist/` and fails
# verification against a correct publish, as beta.7's Release did.
WRAPPER_JOB = "publish"
WRAPPER_BUILD_STEP = "Qualify release"
WRAPPER_IDENTITY_STEP = "Compute the wrapper package identity"
WRAPPER_PUBLISH_STEP = "Release package"
WRAPPER_BUILD_COMMAND = "npm run js:build"
WRAPPER_TARBALL_OUTPUT = "steps.pack.outputs.tarball"

# Issue #417: `publish-wasm-dependency` must verify, at publish time, that the
# artifact it is about to pack under the `@redact-secret/wasm` package
# identity actually reports the profile that identity promises -- and that
# check must run before the step that packs and publishes it, not after.
# Without this, the verification step could be deleted, reordered after the
# publish step, or narrowed to skip the `common` artifact, and nothing here
# would notice.
WASM_DEPENDENCY_JOB = "publish-wasm-dependency"
PROFILE_VERIFICATION_STEP = "Verify the root artifact reports the full profile"
WASM_PUBLISH_STEP = "Pack, content-check, publish, and verify"
FULL_ARTIFACT_GLUE = "redact_secret_wasm.js"
FULL_PROFILE_ASSERTION = '!== "full"'
COMMON_ARTIFACT_GLUE = "redact_secret_wasm_common.js"
COMMON_PROFILE_ASSERTION = '!== "common"'

# Issue #527: `publish-pypi` must verify, at publish time, that the wheels
# and source distribution it is about to hand to PyPI are byte-identical to
# what `artifact-qualification` qualified for this commit -- and that check
# must run before the step that actually publishes them, not after.
PYPI_JOB = "publish-pypi"
PYPI_DIGEST_STEP = "Verify published wheels match the qualified inventory"
PYPI_PUBLISH_STEP = "Publish to PyPI"
PYPI_DIGEST_SCRIPT = "scripts/verify-python-digest.py"

# Issue #528: `publish-crates` must verify each crate's crates.io checksum
# against what `artifact-qualification` qualified, and that check must run
# after the crate's own publish step (crates.io has nothing to check before
# then) but must exist and must not be deleted silently.
CRATES_JOB = "publish-crates"
CRATE_DIGEST_SCRIPT = "scripts/verify-crate-digest.py"
CRATE_DIGEST_STEPS = (
    ("Publish redact-secret", "Verify redact-secret publication matches the qualified crate"),
    ("Publish redact-secret-cli", "Verify redact-secret-cli publication matches the qualified crate"),
)

# Issue #614: workflows whose `run:` blocks must read `needs.*` job outputs
# through `env:` rather than inline `${{ }}` substitution.
INLINE_NEEDS_WORKFLOWS = (
    RELEASE_WORKFLOW,
    Path(".github") / "workflows" / "reconcile-release.yml",
)
INLINE_NEEDS_PATTERN = re.compile(r"\$\{\{\s*needs\.")
RUN_BLOCK_HEADER = re.compile(r"^(?P<indent>\s*)(?:- )?run:\s*(?P<rest>.*)$")

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


def extract_step_blocks(job_body: str) -> list[tuple[int, str, str]]:
    """Return `(offset, name, body)` for every step in a job, in file order.

    Steps share `needs:`'s list-item indent (`LIST_ITEM_PREFIX`), so a step
    header is exactly that prefix followed by `name: `.
    """
    step_name_prefix = LIST_ITEM_PREFIX + "name: "
    headers = [
        (offset, line[len(step_name_prefix) :].strip())
        for offset, line in _line_starts(job_body)
        if line.startswith(step_name_prefix)
    ]
    blocks = []
    for index, (offset, name) in enumerate(headers):
        end = headers[index + 1][0] if index + 1 < len(headers) else len(job_body)
        blocks.append((offset, name, job_body[offset:end]))
    return blocks


def inline_needs_in_run(text: str) -> list[int]:
    """Return 1-based line numbers of `${{ needs.` inside a `run:` script.

    Covers both a one-line `run: ...` and a block scalar (`run: |` / `>`),
    whose body is every following line indented deeper than the `run:` key
    (blank lines included). `env:`, `with:`, `if:`, and every other key may
    still use `needs.*` expressions -- only shell source is rejected.
    """
    offending: list[int] = []
    lines = text.splitlines()
    block_indent: int | None = None
    for number, line in enumerate(lines, start=1):
        if block_indent is not None:
            if not line.strip() or len(line) - len(line.lstrip()) > block_indent:
                if INLINE_NEEDS_PATTERN.search(line):
                    offending.append(number)
                continue
            block_indent = None
        match = RUN_BLOCK_HEADER.match(line)
        if match is None:
            continue
        rest = match.group("rest").strip()
        if rest[:1] in ("|", ">"):
            # The key's own column: a `- run:` list item's key sits two
            # columns past the dash.
            block_indent = len(match.group("indent")) + (2 if line.lstrip().startswith("- ") else 0)
        elif INLINE_NEEDS_PATTERN.search(rest):
            offending.append(number)
    return offending


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

    wasm_job = jobs.get(WASM_DEPENDENCY_JOB)
    if wasm_job is None:
        errors.append(
            f"{RELEASE_WORKFLOW.as_posix()}: missing job '{WASM_DEPENDENCY_JOB}'"
        )
    else:
        steps = extract_step_blocks(wasm_job)
        verify_step = next(
            (step for step in steps if step[1] == PROFILE_VERIFICATION_STEP), None
        )
        publish_step = next(
            (step for step in steps if step[1] == WASM_PUBLISH_STEP), None
        )
        if verify_step is None:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: job '{WASM_DEPENDENCY_JOB}' is missing "
                f"the '{PROFILE_VERIFICATION_STEP}' step"
            )
        if publish_step is None:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: job '{WASM_DEPENDENCY_JOB}' is missing "
                f"the '{WASM_PUBLISH_STEP}' step"
            )
        if verify_step is not None and publish_step is not None and verify_step[0] > publish_step[0]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{PROFILE_VERIFICATION_STEP}' must precede "
                f"'{WASM_PUBLISH_STEP}' in job '{WASM_DEPENDENCY_JOB}'"
            )
        if verify_step is not None:
            body = verify_step[2]
            if FULL_ARTIFACT_GLUE not in body or FULL_PROFILE_ASSERTION not in body:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: '{PROFILE_VERIFICATION_STEP}' does not "
                    'assert the root artifact reports "full"'
                )
            if COMMON_ARTIFACT_GLUE not in body or COMMON_PROFILE_ASSERTION not in body:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: '{PROFILE_VERIFICATION_STEP}' does not "
                    'assert the common artifact reports "common"'
                )

    wrapper_job = jobs.get(WRAPPER_JOB)
    if wrapper_job is not None:
        steps = extract_step_blocks(wrapper_job)
        found = {
            name: next((step for step in steps if step[1] == name), None)
            for name in (WRAPPER_BUILD_STEP, WRAPPER_IDENTITY_STEP, WRAPPER_PUBLISH_STEP)
        }
        for name, step in found.items():
            if step is None:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: job '{WRAPPER_JOB}' is missing the '{name}' step"
                )
        build, identity, publish = (found[name] for name in (WRAPPER_BUILD_STEP, WRAPPER_IDENTITY_STEP, WRAPPER_PUBLISH_STEP))
        if build is not None and identity is not None and identity[0] < build[0]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{WRAPPER_IDENTITY_STEP}' must follow "
                f"'{WRAPPER_BUILD_STEP}' in job '{WRAPPER_JOB}' -- before the build the "
                "packed wrapper has no dist/"
            )
        if identity is not None and publish is not None and identity[0] > publish[0]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{WRAPPER_IDENTITY_STEP}' must precede "
                f"'{WRAPPER_PUBLISH_STEP}' in job '{WRAPPER_JOB}'"
            )
        if identity is not None and WRAPPER_BUILD_COMMAND not in identity[2]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{WRAPPER_IDENTITY_STEP}' does not run "
                f"{WRAPPER_BUILD_COMMAND} before packing"
            )
        if publish is not None and WRAPPER_TARBALL_OUTPUT not in publish[2]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{WRAPPER_PUBLISH_STEP}' does not publish "
                f"the tarball '{WRAPPER_IDENTITY_STEP}' recorded ({WRAPPER_TARBALL_OUTPUT})"
            )

    pypi_job = jobs.get(PYPI_JOB)
    if pypi_job is None:
        errors.append(f"{RELEASE_WORKFLOW.as_posix()}: missing job '{PYPI_JOB}'")
    else:
        steps = extract_step_blocks(pypi_job)
        digest_step = next((step for step in steps if step[1] == PYPI_DIGEST_STEP), None)
        publish_step = next((step for step in steps if step[1] == PYPI_PUBLISH_STEP), None)
        if digest_step is None:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: job '{PYPI_JOB}' is missing "
                f"the '{PYPI_DIGEST_STEP}' step"
            )
        if publish_step is None:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: job '{PYPI_JOB}' is missing "
                f"the '{PYPI_PUBLISH_STEP}' step"
            )
        if digest_step is not None and publish_step is not None and digest_step[0] > publish_step[0]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{PYPI_DIGEST_STEP}' must precede "
                f"'{PYPI_PUBLISH_STEP}' in job '{PYPI_JOB}'"
            )
        if digest_step is not None and PYPI_DIGEST_SCRIPT not in digest_step[2]:
            errors.append(
                f"{RELEASE_WORKFLOW.as_posix()}: '{PYPI_DIGEST_STEP}' does not run "
                f"{PYPI_DIGEST_SCRIPT}"
            )

    crates_job = jobs.get(CRATES_JOB)
    if crates_job is None:
        errors.append(f"{RELEASE_WORKFLOW.as_posix()}: missing job '{CRATES_JOB}'")
    else:
        steps = extract_step_blocks(crates_job)
        for publish_step_name, digest_step_name in CRATE_DIGEST_STEPS:
            publish_step = next((step for step in steps if step[1] == publish_step_name), None)
            digest_step = next((step for step in steps if step[1] == digest_step_name), None)
            if publish_step is None:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: job '{CRATES_JOB}' is missing "
                    f"the '{publish_step_name}' step"
                )
            if digest_step is None:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: job '{CRATES_JOB}' is missing "
                    f"the '{digest_step_name}' step"
                )
            if publish_step is not None and digest_step is not None and digest_step[0] < publish_step[0]:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: '{digest_step_name}' must follow "
                    f"'{publish_step_name}' in job '{CRATES_JOB}' -- crates.io reports no checksum "
                    "before that crate is published"
                )
            if digest_step is not None and CRATE_DIGEST_SCRIPT not in digest_step[2]:
                errors.append(
                    f"{RELEASE_WORKFLOW.as_posix()}: '{digest_step_name}' does not run "
                    f"{CRATE_DIGEST_SCRIPT}"
                )

    for workflow in INLINE_NEEDS_WORKFLOWS:
        path = root / workflow
        if not path.is_file():
            continue
        for number in inline_needs_in_run(path.read_text(encoding="utf-8")):
            errors.append(
                f"{workflow.as_posix()}:{number}: a `run:` script substitutes a "
                "`${{ needs.* }}` job output inline -- pass it through `env:` and read it as \"$VAR\""
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
