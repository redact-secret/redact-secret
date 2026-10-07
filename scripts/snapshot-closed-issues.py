#!/usr/bin/env python3
"""Write the closed-issue snapshot that `check-audit-lifecycle.py --closed-issues` reads.

`check-audit-lifecycle.py` stays offline (#1266): it cannot know whether the
issue an `after-issue:#N` unit waits on is still open. The qualification
workflows therefore generate the snapshot here, with the workflow's own
read-only token, and pass the file to the check. This script is the only
networked half of that pair, and it never writes anything but `--out`.

The snapshot is a list of closed issue numbers, one per line. It is refused,
and no file is left behind, when it cannot be trusted:

* `gh` fails or prints something that is not an issue number;
* it lists no issue at all (a repository with a history of work has closed
  issues, so an empty list means the query silently found nothing);
* it lists `--limit` issues or more. `gh issue list --limit N` stops silently
  after N rows, so a result that reaches N is indistinguishable from a
  truncated one and is treated as truncated. Raise `--limit` instead of
  trusting it.

`--closed-on-or-before TIMESTAMP` (UTC, `YYYY-MM-DDTHH:MM:SSZ`) keeps only the
issues closed at or before that instant. Reconcile uses it with the source
revision's commit time, so a unit that was valid when its release was
qualified is not failed because its issue closed afterwards.

Exit codes: 0 snapshot written, 2 the snapshot cannot be trusted.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_LIMIT = 5000
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class SnapshotError(Exception):
    """The snapshot cannot be trusted."""


def fetch(repo: str | None, limit: int, closed_on_or_before: str | None) -> list[int]:
    command = [
        os.environ.get("GH_BIN", "gh"),
        "issue",
        "list",
        "--state",
        "closed",
        "--limit",
        str(limit),
        "--json",
        "number",
        "--jq",
        ".[].number",
    ]
    if repo:
        command += ["--repo", repo]
    if closed_on_or_before:
        command += ["--search", f"closed:<={closed_on_or_before}"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
    except (OSError, subprocess.SubprocessError) as error:
        raise SnapshotError(f"cannot run gh: {error}") from error
    if completed.returncode != 0:
        raise SnapshotError(f"gh exited {completed.returncode}: {completed.stderr.strip()[:300]}")
    numbers: list[int] = []
    for line in completed.stdout.splitlines():
        if not re.fullmatch(r"[1-9][0-9]*", line.strip()):
            raise SnapshotError(f"gh printed a line that is not an issue number: {line.strip()[:40]!r}")
        numbers.append(int(line))
    if not numbers:
        raise SnapshotError("the snapshot is empty: no closed issue was returned")
    if len(numbers) >= limit:
        raise SnapshotError(
            f"the snapshot is truncated: {len(numbers)} issues reached --limit {limit}; raise the limit and rerun"
        )
    return sorted(set(numbers))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo", help="OWNER/REPO (default: the repository of the working directory)")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--closed-on-or-before", help="UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
    args = parser.parse_args(argv)
    if args.limit < 2:
        print("UNAVAILABLE --limit must be at least 2", file=sys.stderr)
        return 2
    if args.closed_on_or_before and not TIMESTAMP.fullmatch(args.closed_on_or_before):
        print("UNAVAILABLE --closed-on-or-before must be a UTC timestamp YYYY-MM-DDTHH:MM:SSZ", file=sys.stderr)
        return 2
    args.out.unlink(missing_ok=True)
    try:
        numbers = fetch(args.repo, args.limit, args.closed_on_or_before)
    except SnapshotError as error:
        print(f"UNAVAILABLE {error}", file=sys.stderr)
        return 2
    args.out.write_text("".join(f"{number}\n" for number in numbers), encoding="utf-8")
    print(f"Closed-issue snapshot: {len(numbers)} issues (limit {args.limit}) written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
