#!/usr/bin/env python3
"""Fail loudly if a Python artifact about to publish differs from the one qualified.

Issue #527: `release.yml` used to build the Python wheels and source
distribution twice from the same commit -- once in the standalone
`python-wheels` job `publish-pypi` downloaded from, and independently again
inside `artifact-qualification.yml`, whose output fed the checked-in artifact
inventory. Building each artifact exactly once (`python-wheels.yml` is now
invoked only from within `artifact-qualification.yml`) removes that topology,
but this check is the property itself, not a proxy for it: it compares the
SHA-256 of every file `publish-pypi` is about to hand to PyPI against the
SHA-256 `record-artifact-inventory.py` recorded for that same file name when
`artifact-qualification.yml` qualified it. A future refactor that
reintroduces a second build fails here even if nobody notices the extra
`uses:` line, because the two builds would then disagree on bytes the way
beta.5's did.

    scripts/verify-python-digest.py --inventory artifact-inventory.json dist/*
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

QUALIFIED_FAMILIES = ("python-wheel", "python-sdist")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualified_digests(inventory_path: Path) -> dict[str, str]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    return {
        entry["file"]: entry["sha256"]
        for entry in inventory["artifacts"]
        if entry["family"] in QUALIFIED_FAMILIES
    }


def verify(artifacts: list[Path], qualified: dict[str, str]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for artifact in artifacts:
        if not artifact.is_file():
            errors.append(f"{artifact}: not a file")
            continue
        name = artifact.name
        seen.add(name)
        expected = qualified.get(name)
        if expected is None:
            errors.append(f"{name}: not present in the qualified artifact inventory")
            continue
        actual = digest(artifact)
        if actual != expected:
            errors.append(
                f"{name}: published digest {actual} does not match the qualified "
                f"digest {expected} -- this would ship a file artifact-qualification.yml "
                "never qualified"
            )
    for missing in sorted(set(qualified) - seen):
        errors.append(
            f"{missing}: qualified by artifact-qualification.yml but not present "
            "among the artifacts about to publish"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "artifacts", nargs="+", type=Path, help="wheels and the source distribution about to publish"
    )
    parser.add_argument(
        "--inventory",
        required=True,
        type=Path,
        help="artifact-inventory.json recorded by artifact-qualification.yml",
    )
    args = parser.parse_args()

    if not args.inventory.is_file():
        print(f"ERROR {args.inventory}: not a file")
        print("Python artifact digest verification complete: 0 artifact(s) checked, 1 error(s)")
        return 1

    qualified = qualified_digests(args.inventory)
    errors = verify(args.artifacts, qualified)

    for error in errors:
        print(f"ERROR {error}")
    print(
        f"Python artifact digest verification complete: {len(args.artifacts)} artifact(s) checked, "
        f"{len(errors)} error(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
