#!/usr/bin/env python3
"""Fail loudly if an artifact about to publish differs from the one qualified.

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

Issue #528 generalizes this beyond Python: `--family` (repeatable, defaulting
to the Python wheel and source-distribution families so the `publish-pypi`
call below is unchanged) and `--target` (optional) let `publish-native-
dependencies` and `publish-wasm-dependency` run the exact same check against
the single compiled addon or WebAssembly build they are about to pack, before
packing it -- the same "built once, compared at publish time" property,
independently of which registry ends up repackaging the qualified bytes.

`--suffix` (optional) narrows the qualified set to file names ending in it.
A family records every file its qualification artifact uploaded, which is not
always what one package ships: `node-addon-<target>` also carries napi's
generated `index.js`/`index.d.ts` loader, but a platform package ships only
the compiled `.node` library, so its caller passes `--suffix .node`. Every
qualified file left after narrowing must still be present, so the check stays
"everything this package ships, and nothing it does not".

    scripts/verify-python-digest.py --inventory artifact-inventory.json dist/*
    scripts/verify-python-digest.py --inventory artifact-inventory.json \\
        --family node-addon --target aarch64-apple-darwin --suffix .node \\
        bindings/node/redact-secret.darwin-arm64.node
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


def qualified_digests(
    inventory_path: Path,
    families: tuple[str, ...] = QUALIFIED_FAMILIES,
    target: str | None = None,
    suffix: str | None = None,
) -> dict[str, str]:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    return {
        entry["file"]: entry["sha256"]
        for entry in inventory["artifacts"]
        if entry["family"] in families
        and (target is None or entry["target"] == target)
        and (suffix is None or entry["file"].endswith(suffix))
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
        "artifacts", nargs="+", type=Path, help="the artifact file(s) about to publish"
    )
    parser.add_argument(
        "--inventory",
        required=True,
        type=Path,
        help="artifact-inventory.json recorded by artifact-qualification.yml",
    )
    parser.add_argument(
        "--family",
        dest="families",
        action="append",
        default=[],
        help="repeatable: the artifact family/families to check (default: python-wheel, python-sdist)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="restrict the qualified inventory to entries with this target (e.g. a Rust triple)",
    )
    parser.add_argument(
        "--suffix",
        default=None,
        help="restrict the qualified inventory to file names ending in this suffix (e.g. .node)",
    )
    args = parser.parse_args()
    families = tuple(args.families) if args.families else QUALIFIED_FAMILIES

    if not args.inventory.is_file():
        print(f"ERROR {args.inventory}: not a file")
        print("Artifact digest verification complete: 0 artifact(s) checked, 1 error(s)")
        return 1

    qualified = qualified_digests(args.inventory, families, args.target, args.suffix)
    errors = verify(args.artifacts, qualified)

    for error in errors:
        print(f"ERROR {error}")
    print(
        f"Artifact digest verification complete: {len(args.artifacts)} artifact(s) checked, "
        f"{len(errors)} error(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
