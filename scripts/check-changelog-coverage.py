#!/usr/bin/env python3
"""Require a `## Unreleased` changelog entry when a pull request changes
detection behavior or a binding's public surface (issue #633).

The beta.6 retrospective (`docs/audits/beta6-release-retrospective.md`, "What
went wrong", item 5) found nine detector pull requests merged with no
changelog entry, one entry describing a state that never shipped, and an
unrecorded finding-type compatibility break; beta.5's second readiness pass
found the same class of gap. Both were caught at candidate review, long after
the change merged, because nothing checked at pull-request time. Between
beta.6 and this script, six more finding types shipped with no entry.

What counts as "requires an entry" is [`GUARDED_PATHS`] below -- the single
place the guarded surface is stated. It covers the detector registry and the
policy that classifies its findings, plus each binding's own source, because
those are the changes a consumer can observe without reading this repository.

What counts as "has an entry" is a changed `## Unreleased` section: the
section's text at the head commit differs from its text at the base commit.
That is deliberately coarse. It cannot judge whether the prose is *right* --
only a human review can -- but it does make the omission impossible to merge
silently.

The waiver is the `no-changelog` pull-request label, for a refactor, a test,
or a comment change that alters no observable behavior. `CONTRIBUTION.md`
documents it. A waiver is recorded in the pull request, where a reviewer sees
it, rather than in a file the same commit can edit.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

CHANGELOG = "CHANGELOG.md"
UNRELEASED_HEADING = "## Unreleased"
WAIVER_LABEL = "no-changelog"

# The guarded surface, stated once. A changed file under any of these paths
# requires a `## Unreleased` entry unless the waiver label is set.
GUARDED_PATHS: tuple[str, ...] = (
    "crates/secret-scan-core/src/detectors/",
    "crates/secret-scan-core/src/policy.rs",
    "crates/secret-scan-cli/src/",
    "bindings/node/src/",
    "bindings/python/src/",
    "bindings/wasm/src/",
    "packages/javascript/src/",
)


def guarded(paths: list[str]) -> list[str]:
    """Every changed path that requires a changelog entry."""
    return sorted(path for path in paths if path.startswith(GUARDED_PATHS))


def unreleased_section(changelog: str) -> str:
    """The `## Unreleased` section's body, empty when there is none."""
    lines = changelog.splitlines()
    try:
        start = next(
            index for index, line in enumerate(lines) if line.strip() == UNRELEASED_HEADING
        )
    except StopIteration:
        return ""
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body).strip()


def evaluate(
    changed_paths: list[str],
    base_changelog: str,
    head_changelog: str,
    labels: list[str],
) -> list[str]:
    """Errors for this diff; an empty list means the check passes."""
    required = guarded(changed_paths)
    if not required:
        return []
    if WAIVER_LABEL in labels:
        return []
    if unreleased_section(head_changelog) != unreleased_section(base_changelog):
        return []
    listed = "\n".join(f"  {path}" for path in required[:10])
    more = "" if len(required) <= 10 else f"\n  ... and {len(required) - 10} more"
    return [
        f"{CHANGELOG}'s `{UNRELEASED_HEADING}` section is unchanged, but this "
        f"pull request changes {len(required)} guarded file(s):\n"
        f"{listed}{more}\n"
        f"Add an entry describing what a consumer can now observe, or apply the "
        f"`{WAIVER_LABEL}` label when the change alters no observable behavior."
    ]


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def changed_paths(root: Path, base: str, head: str) -> list[str]:
    diff = git(root, "diff", "--name-only", f"{base}...{head}")
    return [line for line in diff.splitlines() if line]


def file_at(root: Path, ref: str, path: str) -> str:
    try:
        return git(root, "show", f"{ref}:{path}")
    except subprocess.CalledProcessError:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="the merge base side")
    parser.add_argument("--head", default="HEAD", help="the commit under review")
    parser.add_argument(
        "--labels",
        default="",
        help=f"comma-separated pull-request labels; `{WAIVER_LABEL}` waives the check",
    )
    parser.add_argument("--root", default=".", help="repository root")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    errors = evaluate(
        changed_paths(root, args.base, args.head),
        file_at(root, args.base, CHANGELOG),
        file_at(root, args.head, CHANGELOG),
        labels,
    )
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    print(f"Changelog coverage check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
