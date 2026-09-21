#!/usr/bin/env python3
"""Fail loudly if a published crate's checksum differs from the one qualified.

Issue #528: unlike an npm tarball, crates.io records the exact SHA-256 of the
`.crate` file it received (`reconcile-release.yml`'s own crate reconciliation
already relies on this: it rebuilds the crate locally and compares its
checksum against crates.io's `.version.checksum` field), so a byte comparison
here is meaningful, not just a repackaged proxy for one. `.github/workflows/
artifact-qualification.yml`'s `inventory` job now packages both crates once,
before publication, and `record-artifact-inventory.py` records each one's
SHA-256 under the `crate` family; this script compares that recorded digest
against the checksum crates.io reports once `release.yml`'s `publish-crates`
job has actually published the crate, so a divergence between what was
qualified and what crates.io received fails the run instead of shipping
unnoticed.

    scripts/verify-crate-digest.py --inventory artifact-inventory.json \\
        --crate redact-secret --published-checksum <sha256 from crates.io>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FAMILY = "crate"


def qualified_digest(inventory_path: Path, crate: str) -> tuple[str, str] | None:
    """Return `(file, sha256)` for `crate`'s qualified `.crate` package, or None."""
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    for entry in inventory["artifacts"]:
        if entry["family"] == FAMILY and entry["target"] == crate:
            return entry["file"], entry["sha256"]
    return None


def verify(crate: str, qualified: tuple[str, str] | None, published_checksum: str) -> list[str]:
    if qualified is None:
        return [f"{crate}: not present in the qualified artifact inventory"]
    file_name, qualified_checksum = qualified
    if qualified_checksum != published_checksum:
        return [
            f"{crate} ({file_name}): published checksum {published_checksum} does not match the "
            f"qualified digest {qualified_checksum} -- this would ship a package "
            "artifact-qualification.yml never qualified"
        ]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--crate", required=True, help="the crate name, e.g. redact-secret")
    parser.add_argument(
        "--inventory",
        required=True,
        type=Path,
        help="artifact-inventory.json recorded by artifact-qualification.yml",
    )
    parser.add_argument(
        "--published-checksum",
        required=True,
        help="the SHA-256 checksum crates.io reports for the published version",
    )
    args = parser.parse_args()

    if not args.inventory.is_file():
        print(f"ERROR {args.inventory}: not a file")
        print("Crate digest verification complete: 0 crate(s) checked, 1 error(s)")
        return 1

    if not args.published_checksum:
        print(f"ERROR {args.crate}: no published checksum was supplied")
        print("Crate digest verification complete: 0 crate(s) checked, 1 error(s)")
        return 1

    errors = verify(args.crate, qualified_digest(args.inventory, args.crate), args.published_checksum)

    for error in errors:
        print(f"ERROR {error}")
    print(f"Crate digest verification complete: 1 crate(s) checked, {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
