#!/usr/bin/env python3
"""Record the npm dependency cutover's intended publish order and inventory.

Issue #141: before `@redact-secret/core` (the wrapper) may publish, every
runtime dependency package it declares -- the eight native
`@redact-secret/node-<platform>` packages and `@redact-secret/wasm`
-- must already be packed, content-checked, published, and verified at its
declared, immutable version. `.github/workflows/release.yml` enforces the
ordering itself through `needs:` (checked by `scripts/check-release-gate.py`,
not this script); this script is the no-publication rehearsal's other half:
given a directory of artifacts a qualification run already produced for one
source commit, it resolves exactly which dependency packages that commit
would need to publish, in what order, and whether the artifact each one packs
was actually produced -- so a qualification run that silently dropped a
target is caught here rather than surfacing as an obscure `npm publish`
failure later. It publishes nothing and calls no registry.

Issue #417: the `wasm` entry also names its companion `common`-profile
artifact (`WASM_COMMON_ARTIFACT`) and whether it was produced, so
`.github/workflows/package-release-rehearsal.yml` can assemble it from the
name this plan gives rather than a second, independently hard-coded path,
and so a qualification run that produced `wasm-web` but dropped
`wasm-web-common` is caught here too.

    python3 -B scripts/record-dependency-cutover-plan.py \\
        --artifacts qualification-artifacts --out dependency-cutover-plan.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
NATIVE_NPM_DIR = Path("bindings") / "node" / "npm"
WASM_MANIFEST = Path("bindings") / "wasm" / "npm" / "package.json"
WRAPPER_MANIFEST = Path("packages") / "javascript" / "package.json"
ADDON_QUALIFIER = Path("scripts") / "qualify-node-addon.mjs"
CHECK_ARTIFACT_MATRIX = Path(__file__).resolve().parent / "check-artifact-matrix.py"

# The `common` detector profile's browser artifact (issue #382,
# `decision-define-detector-profile-and-pack-contract`) ships inside the same
# `@redact-secret/wasm` package as `wasm-web`, under its own file names, so it
# is a companion of the `wasm` dependency entry rather than a dependency of
# its own. Naming it here, once, is what lets `package-release-rehearsal.yml`
# read it from the plan instead of hard-coding it a second time (issue #417).
WASM_COMMON_ARTIFACT = "wasm-web-common"


def _load_check_artifact_matrix():
    """Reuses `platform_names()` from `check-artifact-matrix.py` -- the one
    place the addon-target-triple to platform-directory-name mapping is
    spelled out -- rather than re-deriving it here and risking the two
    falling out of agreement."""
    spec = importlib.util.spec_from_file_location(
        "check_artifact_matrix", CHECK_ARTIFACT_MATRIX
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def declared_matrix(root: Path) -> dict:
    with (root / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest["workspace"]["metadata"]["redact-secret"]


def source_commit(root: Path) -> str:
    """The revision the qualification artifacts were built from -- see
    `record-artifact-inventory.py`'s identical helper for why `GITHUB_SHA`
    alone is not this on a pull request."""
    for name in ("SOURCE_COMMIT", "GITHUB_SHA"):
        commit = os.environ.get(name, "").strip()
        if commit:
            return commit
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def read_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def native_dependency_plan(root: Path, policy: dict, artifacts: Path) -> list[dict]:
    matrix = _load_check_artifact_matrix()
    qualifier_text = (root / ADDON_QUALIFIER).read_text(encoding="utf-8")
    names = matrix.platform_names(qualifier_text)

    plan = []
    for target in sorted(policy.get("node-publish-targets") or []):
        platform = names.get(target)
        expected_artifact = f"node-addon-{target}"
        entry = {
            "kind": "native",
            "target": target,
            "platform": platform,
            "expectedArtifact": expected_artifact,
            "artifactPresent": (artifacts / expected_artifact).is_dir(),
            "package": None,
            "version": None,
        }
        manifest_path = root / NATIVE_NPM_DIR / (platform or "") / "package.json"
        if platform is not None and manifest_path.is_file():
            manifest = read_manifest(manifest_path)
            entry["package"] = manifest.get("name")
            entry["version"] = manifest.get("version")
        plan.append(entry)
    return plan


def wasm_dependency_plan(root: Path, artifacts: Path) -> dict:
    entry = {
        "kind": "wasm",
        "target": None,
        "platform": None,
        "expectedArtifact": "wasm-web",
        "artifactPresent": (artifacts / "wasm-web").is_dir(),
        "companionArtifact": WASM_COMMON_ARTIFACT,
        "companionArtifactPresent": (artifacts / WASM_COMMON_ARTIFACT).is_dir(),
        "package": None,
        "version": None,
    }
    manifest_path = root / WASM_MANIFEST
    if manifest_path.is_file():
        manifest = read_manifest(manifest_path)
        entry["package"] = manifest.get("name")
        entry["version"] = manifest.get("version")
    return entry


def wrapper_plan(root: Path, dependencies: list[dict]) -> dict:
    manifest_path = root / WRAPPER_MANIFEST
    manifest = read_manifest(manifest_path) if manifest_path.is_file() else {}
    return {
        "package": manifest.get("name"),
        "version": manifest.get("version"),
        # Every dependency package this plan lists must publish and verify
        # before the wrapper is eligible -- the fact `release.yml`'s
        # `publish` job encodes with `needs:`.
        "gatedOn": [entry["package"] for entry in dependencies if entry["package"]],
    }


def build_plan(root: Path, artifacts: Path) -> dict:
    policy = declared_matrix(root)
    dependencies = native_dependency_plan(root, policy, artifacts)
    dependencies.append(wasm_dependency_plan(root, artifacts))
    return {
        "sourceCommit": source_commit(root),
        "dependencies": dependencies,
        "wrapper": wrapper_plan(root, dependencies),
    }


def plan_errors(plan: dict, artifacts: Path) -> list[str]:
    missing = [entry for entry in plan["dependencies"] if not entry["artifactPresent"]]
    missing_companions = [
        entry
        for entry in plan["dependencies"]
        if entry.get("companionArtifact") and not entry["companionArtifactPresent"]
    ]
    unresolved = [entry for entry in plan["dependencies"] if entry["package"] is None]
    return (
        [f"{entry['expectedArtifact']}: no qualified artifact in {artifacts}" for entry in missing]
        + [
            f"{entry['companionArtifact']}: no qualified companion artifact in {artifacts}"
            for entry in missing_companions
        ]
        + [
            f"{entry['expectedArtifact']}: no dependency package manifest resolved for it"
            for entry in unresolved
        ]
    )


def render_summary(plan: dict) -> str:
    lines = [
        "## npm dependency cutover plan",
        "",
        f"- Source commit: `{plan['sourceCommit']}`",
        f"- Wrapper: `{plan['wrapper']['package']}@{plan['wrapper']['version']}`",
        "",
        "| Order | Kind | Package | Version | Expected artifact | Present |",
        "| --- | --- | --- | --- | --- | :---: |",
    ]
    for index, entry in enumerate(plan["dependencies"], start=1):
        present = "yes" if entry["artifactPresent"] else "**missing**"
        lines.append(
            f"| {index} | {entry['kind']} | `{entry['package']}` | {entry['version']} | "
            f"`{entry['expectedArtifact']}` | {present} |"
        )
    lines.append(
        f"| {len(plan['dependencies']) + 1} | wrapper | `{plan['wrapper']['package']}` | "
        f"{plan['wrapper']['version']} | (publishes after every row above) | - |"
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--artifacts", type=Path, required=True, help="directory of downloaded qualification artifacts"
    )
    parser.add_argument("--out", type=Path, required=True, help="plan JSON to write")
    parser.add_argument("--summary", type=Path, help="markdown summary to append to")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="repository root")
    arguments = parser.parse_args()

    if not arguments.artifacts.is_dir():
        print(f"{arguments.artifacts}: missing", file=sys.stderr)
        return 1

    plan = build_plan(arguments.root.resolve(), arguments.artifacts)

    arguments.out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.out} ({len(plan['dependencies'])} dependency package(s))")

    if arguments.summary is not None:
        with arguments.summary.open("a", encoding="utf-8") as handle:
            handle.write(render_summary(plan) + "\n")

    errors = plan_errors(plan, arguments.artifacts)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"\n{len(errors)} error(s); the dependency cutover is not eligible", file=sys.stderr)
        return 1
    print("every declared dependency package has a qualified artifact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
