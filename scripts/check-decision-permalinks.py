#!/usr/bin/env python3
"""Verify every ADR blob permalink names a real commit *and* a real path at it.

`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`'s
permalink rule requires a permalink to name a 40-hex `main` commit
(`scripts/validate-decisions.py` checks the *shape*; this script checks the
commit exists in this repository's history and that the cited path exists at
that commit). That needs the full git history, not the single-commit checkout
the main `npm run ci` job uses, so it runs as its own CI job with
`fetch-depth: 0` (issue #597, DS6a).

Every blob permalink in a record is checked wherever it sits: the frontmatter
`full_record:` line and each row of a `Folded records` table alike (issue
#640, item 1).

    python3 -B scripts/check-decision-permalinks.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PERMALINK = re.compile(
    r"https://github\.com/redact-secret/redact-secret/blob/([0-9a-f]{40})/([^\s)>\]`\"']+)"
)


def collect_permalinks(decision_dir: Path) -> dict[tuple[str, str], list[Path]]:
    """Map each unique (commit SHA, path) permalink to the ADR file(s) citing it."""
    links: dict[tuple[str, str], list[Path]] = {}
    if not decision_dir.is_dir():
        return links
    for record in sorted(decision_dir.glob("*.md")):
        if record.name == "DECISIONS.md":
            continue
        for sha, path in PERMALINK.findall(record.read_text(encoding="utf-8")):
            cited_by = links.setdefault((sha, path.split("#", 1)[0]), [])
            if record not in cited_by:
                cited_by.append(record)
    return links


def _git_ok(root: Path, *args: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def commit_exists(root: Path, sha: str) -> bool:
    """True when `sha` names a commit reachable in `root`'s local git history."""
    return _git_ok(root, "cat-file", "-e", f"{sha}^{{commit}}")


def path_exists_at(root: Path, sha: str, path: str) -> bool:
    """True when `path` is a file in the tree of commit `sha`."""
    return _git_ok(root, "cat-file", "-e", f"{sha}:{path}")


def validate(root: Path) -> list[str]:
    root = root.resolve()
    decision_dir = root / "docs" / "decisions"
    errors: list[str] = []
    for (sha, path), records in sorted(collect_permalinks(decision_dir).items()):
        if not commit_exists(root, sha):
            for record in records:
                errors.append(f"{record}: permalink commit {sha} is not reachable in local history")
        elif not path_exists_at(root, sha, path):
            for record in records:
                errors.append(f"{record}: permalink path {path} does not exist at commit {sha}")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    errors = validate(root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Decision permalink check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
