#!/usr/bin/env python3
"""Gate `docs/README.md` on reaching every tracked docs page (issue #640, item 3).

`audits-index:check` covers `docs/audits/README.md` only. This script walks
Markdown links breadth-first from `docs/README.md` and fails when a tracked
`docs/**/*.md` page is not reachable through any chain of relative Markdown
links. A prose mention (`docs/specs/engine.md` in backticks) does not count; only a
link destination does, because only a link is clickable.

A page that should stay off the index goes in `EXEMPT`, with the reason beside
it, so an exemption is a reviewed decision rather than silent drift.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Pages deliberately not reachable from docs/README.md: path relative to the repo root -> reason.
EXEMPT: dict[str, str] = {}

LINK = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")


def tracked_docs(root: Path) -> set[Path]:
    """Every tracked docs/**/*.md page; falls back to the filesystem outside a git checkout."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "docs"],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout:
        names = [n for n in result.stdout.decode("utf-8").split("\0") if n.endswith(".md")]
        return {(root / name).resolve() for name in names}
    return {path.resolve() for path in (root / "docs").rglob("*.md")}


def link_targets(page: Path) -> list[Path]:
    """Resolved local Markdown link targets in `page`, ignoring fenced code."""
    targets: list[Path] = []
    in_fence = False
    for line in page.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for raw in LINK.findall(line):
            if re.match(r"^[a-z][a-z0-9+.-]*:", raw) or raw.startswith("#"):
                continue
            target = (page.parent / raw.split("#", 1)[0].split("?", 1)[0]).resolve()
            if target.suffix == ".md" and target.is_file():
                targets.append(target)
    return targets


def reachable(start: Path) -> set[Path]:
    seen = {start}
    queue = [start]
    while queue:
        for target in link_targets(queue.pop()):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def validate(root: Path, exempt: dict[str, str] | None = None) -> list[str]:
    root = root.resolve()
    exempt = EXEMPT if exempt is None else exempt
    index = root / "docs" / "README.md"
    if not index.is_file():
        return [f"{index}: missing docs index"]
    pages = tracked_docs(root)
    seen = reachable(index)
    exempt_paths = {(root / name).resolve() for name in exempt}
    errors: list[str] = []
    for page in sorted(pages - seen - exempt_paths):
        errors.append(f"{page.relative_to(root)} is not reachable by Markdown links from docs/README.md")
    for name in sorted(exempt):
        path = (root / name).resolve()
        if path not in pages:
            errors.append(f"exempt entry {name} is not a tracked docs page")
        elif path in seen:
            errors.append(f"exempt entry {name} is reachable from docs/README.md; remove the exemption")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Docs reachability check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
