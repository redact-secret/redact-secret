#!/usr/bin/env python3
"""Decide whether Reconcile Release may repair a recorded manifest's commit.

The repair source must be an ancestor of the dispatched main branch's current
tip, including that exact tip.
A manifest records the source, or an explicitly authorized --source-commit
input supplies it. A source outside main's history is rejected even when an
override is provided. The workflow separately requires a valid requested
version before invoking this guard.

This module only decides; it never creates a tag, publishes anything, or
queries a registry. `reconcile-release.yml` performs the tag creation itself,
using the `source_revision` this guard reports, once it reports `ok`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    source_revision: str | None
    reason: str


def load_manifest(path: Path | None) -> dict | None:
    """Return the parsed manifest, or None when there is no record to read."""
    if path is None or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def is_ancestor(repo: Path, commit: str, candidate_ref: str) -> bool:
    """True when `commit` is `candidate_ref` or one of its ancestors."""
    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, candidate_ref],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def evaluate(
    manifest: dict | None,
    *,
    repo: Path,
    candidate_ref: str,
    version: str,
    source_commit_override: str | None = None,
) -> GuardResult:
    """Decide whether reconcile may tag a commit for `version`.

    An explicit `source_commit_override` (the workflow's `source_commit`
    input) is authoritative on its own -- it satisfies acceptance criterion 2
    without requiring a manifest record. Otherwise the manifest must exist,
    must record `version`, and must carry a `source_revision`.
    """
    if source_commit_override:
        source_revision = source_commit_override
    else:
        if manifest is None:
            return GuardResult(
                False,
                None,
                "no release manifest record was found for the requested version, "
                "and no source_commit input was given",
            )
        if manifest.get("version") != version:
            return GuardResult(
                False,
                None,
                f"manifest records version {manifest.get('version')!r}, requested {version!r}",
            )
        source_revision = manifest.get("source_revision")
        if not source_revision:
            return GuardResult(False, None, "manifest record has no source_revision")

    try:
        ancestor = is_ancestor(repo, source_revision, candidate_ref)
    except FileNotFoundError:
        return GuardResult(False, None, "git is not available to verify ancestry")

    if not ancestor:
        return GuardResult(
            False,
            None,
            f"{source_revision} is not an ancestor of {candidate_ref}",
        )

    return GuardResult(True, source_revision, "source_revision is an ancestor of main and may be tagged")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=None, help="path to the downloaded manifest.json, if any")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--candidate-ref", required=True, help="main's current tip commit or ref")
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--source-commit",
        default=None,
        help="override the manifest's source_revision, e.g. the source_commit workflow input",
    )
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    result = evaluate(
        manifest,
        repo=args.repo,
        candidate_ref=args.candidate_ref,
        version=args.version,
        source_commit_override=args.source_commit,
    )
    print(json.dumps(asdict(result)))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
