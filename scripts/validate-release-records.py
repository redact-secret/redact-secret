#!/usr/bin/env python3
"""Validate checked-in release records without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

EXPECTED_ARTIFACTS = {
    "crate:redact-secret", "crate:redact-secret-cli", "npm:@redact-secret/core",
    "npm:@redact-secret/wasm", "npm:@redact-secret/node-darwin-arm64",
    "npm:@redact-secret/node-darwin-x64", "npm:@redact-secret/node-linux-arm64-gnu",
    "npm:@redact-secret/node-linux-x64-gnu", "npm:@redact-secret/node-win32-arm64-msvc",
    "npm:@redact-secret/node-win32-x64-msvc", "pypi:redact-secret",
}
# `decision-publish-musl-node-addons` extends `node-publish-targets` to eight
# triples, but every recorded release under `docs/releases/` to date
# (0.1.0-beta.1/2/4) genuinely shipped only these eleven artifacts — this set
# validates those real, frozen records and must not be edited to match a
# capability this repository has not yet released under. Add the two musl
# npm artifacts here only once an actual release record reflects them.
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")


class InvalidRecord(ValueError):
    """A durable release record is incomplete or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidRecord(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidRecord(f"{path}: cannot read valid JSON: {error}") from error
    require(isinstance(value, dict), f"{path}: root must be an object")
    return value


def git_value(root: Path, *args: str) -> str | None:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def conformance_identity(root: Path, source: str) -> str | None:
    return git_value(root, "rev-parse", f"{source}:conformance")


def validate_evidence(manifest: dict, inventory: dict, label: str) -> None:
    evidence = manifest.get("release_evidence") or manifest.get("recovery_evidence")
    require(isinstance(evidence, dict), f"{label}: missing release/recovery evidence")
    registries = evidence.get("registries")
    require(isinstance(registries, dict) and set(registries) == EXPECTED_ARTIFACTS,
            f"{label}: registry evidence artifact set mismatch")
    for artifact, record in registries.items():
        require(isinstance(record, dict), f"{label}: {artifact} evidence must be an object")
        if artifact.startswith("npm:"):
            require(bool(record.get("shasum")) and bool(record.get("integrity")),
                    f"{label}: {artifact} missing npm checksums")
        elif artifact.startswith("crate:"):
            require(SHA64.fullmatch(str(record.get("checksum", ""))) is not None,
                    f"{label}: {artifact} missing checksum")
        else:
            files = record.get("files")
            require(isinstance(files, list) and len(files) == 9,
                    f"{label}: PyPI evidence must contain nine files")
            inventory_python = {item["file"]: item["sha256"] for item in inventory.get("artifacts", [])
                                if item.get("family") in {"python-wheel", "python-sdist"}}
            observed = {item.get("filename"): item.get("sha256") for item in files}
            require(observed == inventory_python, f"{label}: PyPI hashes do not match artifact inventory")

    tag = evidence.get("tag")
    require(isinstance(tag, dict), f"{label}: missing annotated tag evidence")
    require(tag.get("name") == f"v{manifest['version']}", f"{label}: tag name mismatch")
    require(SHA40.fullmatch(str(tag.get("object", ""))) is not None, f"{label}: invalid tag object")
    require(tag.get("target") == manifest["source_revision"], f"{label}: tag target mismatch")
    runs = evidence.get("runs") or evidence.get("recovery_runs")
    require(isinstance(runs, list) and runs, f"{label}: missing workflow run references")
    for run in runs:
        require(isinstance(run, dict) and isinstance(run.get("id"), int) and bool(run.get("result")),
                f"{label}: invalid workflow run reference")
    verification = evidence.get("verification")
    require(isinstance(verification, dict), f"{label}: missing clean-install verification")
    require(len(verification.get("node", [])) == 6, f"{label}: six Node install lanes required")
    require(verification.get("browser") == "chromium", f"{label}: Chromium verification required")


def validate_record(root: Path, directory: Path, changelog: str) -> None:
    version, label = directory.name, str(directory.relative_to(root))
    require(VERSION.fullmatch(version) is not None, f"{label}: invalid version directory")
    for name in ("README.md", "artifact-inventory.json", "manifest.json"):
        require((directory / name).is_file(), f"{label}: missing {name}")
    inventory_path = directory / "artifact-inventory.json"
    inventory, manifest = load_json(inventory_path), load_json(directory / "manifest.json")
    source = manifest.get("source_revision")
    require(SHA40.fullmatch(str(source or "")) is not None, f"{label}: invalid source revision")
    require(manifest.get("version") == version and inventory.get("productVersion") == version,
            f"{label}: version mismatch")
    require(inventory.get("sourceCommit") == source, f"{label}: source revision mismatch")
    require(set(manifest.get("artifact_set", [])) == EXPECTED_ARTIFACTS, f"{label}: artifact set mismatch")
    state = manifest.get("registry_state")
    require(isinstance(state, dict) and set(state) == EXPECTED_ARTIFACTS,
            f"{label}: registry state artifact set mismatch")
    require(set(state.values()) == {"published"}, f"{label}: final registry state must be complete and published")
    fixtures = inventory.get("conformanceFixtures")
    require(isinstance(fixtures, dict) and fixtures and all(SHA64.fullmatch(str(v)) for v in fixtures.values()),
            f"{label}: invalid conformance fixture hashes")
    local_identity = conformance_identity(root, source)
    if local_identity is not None:
        require(manifest.get("conformance_identity") == local_identity, f"{label}: conformance identity mismatch")
    evidence = manifest.get("release_evidence") or manifest.get("recovery_evidence") or {}
    reconstructed = manifest.get("record_kind") == "reconstructed" or evidence.get("manifest_reconstructed")
    if reconstructed:
        require(bool(evidence.get("reason")), f"{label}: reconstructed record missing reason")
        # Beta.1 predates the schema marker and is retained as the accepted
        # legacy shape. Newly reconstructed records must embed the partial
        # workflow manifest instead of silently replacing its state.
        if manifest.get("record_kind") == "reconstructed":
            require(isinstance(evidence.get("original_manifest"), dict),
                    f"{label}: reconstructed record missing original manifest provenance")
    if "artifact_inventory_sha256" in manifest:
        digest = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
        require(manifest["artifact_inventory_sha256"] == digest, f"{label}: artifact inventory digest mismatch")
    validate_evidence(manifest, inventory, label)
    require(f"docs/releases/{version}/README.md" in changelog,
            f"{label}: CHANGELOG.md lacks publication-evidence link")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", action="append", default=[])
    args = parser.parse_args(argv)
    root, releases = args.root.resolve(), args.root.resolve() / "docs/releases"
    try:
        require(releases.is_dir(), "missing docs/releases directory")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        versions = args.version or sorted(path.name for path in releases.iterdir() if path.is_dir())
        require(bool(versions), "no release records found")
        for version in versions:
            directory = releases / version
            require(directory.is_dir(), f"missing release record directory for {version}")
            validate_record(root, directory, changelog)
    except (InvalidRecord, OSError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    print(f"Validated {len(versions)} durable release record(s): {', '.join(versions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
