#!/usr/bin/env python3
"""Gate `docs/audits/README.md` on indexing every long-lived audit unit (#593; #1266).

`docs/audits/` holds temporary reviews: a standalone review document sitting
next to `evidence/<unit>/`, each declaring its lifecycle in a front matter
block (`decision-retire-historical-audit-bodies-before-release-qualification`,
checked by `check-audit-lifecycle.py`). A unit that stays in the tree is not
useful to a reader who cannot find it. This script re-derives the two unit
sets straight from the filesystem -- every `docs/audits/*.md` file except
`README.md` itself, and every `docs/audits/evidence/<unit>/` directory -- and
fails when a unit's own path is never a link target anywhere in
`docs/audits/README.md`.

A unit whose valid block says `status: in-progress` or `final` is temporary and
tracked by the lifecycle check, so writing one never requires an index edit;
`deferred`, `retained` and any unit without a block must be indexed. Indexing
is a navigation aid and never implies permanent retention: the index lists
what is in the tree and shrinks when a unit is retired.

It checks that the unit is *linked*, not merely mentioned: an issue number
can appear in ordinary prose (as `#145`, for instance) without the document
or evidence folder it names ever being reachable by a click. Only a Markdown
link destination counts.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDITS_DIR = ROOT / "docs" / "audits"
INDEX_PATH = AUDITS_DIR / "README.md"

LINK_RE = re.compile(r"\]\(([^)]+)\)")


def list_audit_docs(audits_dir: Path) -> list[str]:
    return sorted(p.name for p in audits_dir.glob("*.md") if p.name != "README.md")


def list_evidence_units(audits_dir: Path) -> list[str]:
    evidence_dir = audits_dir / "evidence"
    if not evidence_dir.is_dir():
        return []
    return sorted(p.name for p in evidence_dir.iterdir() if p.is_dir())


def index_link_targets(index_text: str) -> list[str]:
    return [match.group(1).split("#", 1)[0] for match in LINK_RE.finditer(index_text)]


def temporary_units(audits_dir: Path) -> set[str]:
    """Unit paths relative to `audits_dir` that the lifecycle check tracks instead."""
    spec = importlib.util.spec_from_file_location(
        "check_audit_lifecycle", Path(__file__).with_name("check-audit-lifecycle.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_audit_lifecycle", module)
    spec.loader.exec_module(module)
    resolved = audits_dir.resolve()
    root = resolved.parent.parent
    if resolved != root / "docs" / "audits":
        return set()
    prefix = "docs/audits/"
    return {path[len(prefix) :] for path in module.temporary_units(root)}


def validate(audits_dir: Path, index_text: str) -> list[str]:
    targets = index_link_targets(index_text)
    errors: list[str] = []
    temporary = temporary_units(audits_dir)

    for name in list_audit_docs(audits_dir):
        if name in temporary:
            continue
        if not any(target == name for target in targets):
            errors.append(f"docs/audits/{name} is not indexed in docs/audits/README.md")

    for unit in list_evidence_units(audits_dir):
        if f"evidence/{unit}" in temporary:
            continue
        prefix = f"evidence/{unit}/"
        if not any(target.startswith(prefix) for target in targets):
            errors.append(f"docs/audits/evidence/{unit}/ is not indexed in docs/audits/README.md")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--audits-dir", type=Path, default=AUDITS_DIR)
    parser.add_argument("--index", type=Path, default=None, help="defaults to <audits-dir>/README.md")
    args = parser.parse_args()

    index_path = args.index if args.index is not None else args.audits_dir / "README.md"
    try:
        index_text = index_path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"ERROR could not read {index_path}: {error}", file=sys.stderr)
        return 1

    errors = validate(args.audits_dir, index_text)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Audits-index check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
