#!/usr/bin/env python3
"""Verify every ADR `full_record:` permalink names a commit reachable in local history.

`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`'s
permalink rule requires `full_record:` to name a 40-hex `main` commit
(`scripts/validate-decisions.py` checks the *shape*; this script checks the
commit actually *exists* in this repository's history). That needs the full
git history, not the single-commit checkout the main `npm run ci` job uses,
so it runs as its own CI job with `fetch-depth: 0` (issue #597, DS6a).

Every ADR summarized in place under issue #591's disposition grades
(DS6b-d) carries `full_record:`; a merged record's folded permalinks sit in
its `Folded records` table, which this script does not parse.

    python3 -B scripts/check-decision-permalinks.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


FULL_RECORD_SHA = re.compile(
    r"^full_record:\s*https://github\.com/redact-secret/redact-secret/blob/([0-9a-f]{40})/"
)


def collect_permalink_commits(decision_dir: Path) -> dict[str, list[Path]]:
    """Map each unique 40-hex commit SHA to the ADR file(s) whose `full_record:` names it."""
    commits: dict[str, list[Path]] = {}
    if not decision_dir.is_dir():
        return commits
    for record in sorted(decision_dir.glob("*.md")):
        if record.name == "DECISIONS.md":
            continue
        for line in record.read_text(encoding="utf-8").splitlines():
            match = FULL_RECORD_SHA.match(line.strip())
            if match is not None:
                commits.setdefault(match.group(1), []).append(record)
    return commits


def commit_exists(root: Path, sha: str) -> bool:
    """True when `sha` names a commit reachable in `root`'s local git history."""
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{sha}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def validate(root: Path) -> list[str]:
    root = root.resolve()
    decision_dir = root / "docs" / "decisions"
    errors: list[str] = []
    for sha, records in sorted(collect_permalink_commits(decision_dir).items()):
        if commit_exists(root, sha):
            continue
        for record in records:
            errors.append(f"{record}: full_record commit {sha} is not reachable in local history")
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
