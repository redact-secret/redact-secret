#!/usr/bin/env python3
"""Gate `docs/audits/README.md` on indexing every audit and evidence unit (#593; DS1).

`docs/audits/` is the review and audit archive: a standalone review document
sitting next to `evidence/<issue>/`, frozen evidence for a product judgement
(`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`).
Neither kind is useful to a reader who cannot find it. This script re-derives
the two unit sets straight from the filesystem -- every `docs/audits/*.md`
file except `README.md` itself, and every `docs/audits/evidence/<unit>/`
directory -- and fails when a unit's own path is never a link target
anywhere in `docs/audits/README.md`.

It checks that the unit is *linked*, not merely mentioned: an issue number
can appear in ordinary prose (as `#145`, for instance) without the document
or evidence folder it names ever being reachable by a click. Only a Markdown
link destination counts.
"""

from __future__ import annotations

import argparse
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


def validate(audits_dir: Path, index_text: str) -> list[str]:
    targets = index_link_targets(index_text)
    errors: list[str] = []

    for name in list_audit_docs(audits_dir):
        if not any(target == name for target in targets):
            errors.append(f"docs/audits/{name} is not indexed in docs/audits/README.md")

    for unit in list_evidence_units(audits_dir):
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
