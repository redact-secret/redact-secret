#!/usr/bin/env python3
"""Generate the public site feed from the generated release and support
manifests (issue #945; redact-secret-www#14, part of redact-secret-www#6).

The public site (`redact-secret-www`) must not scrape this repository's
Markdown for release identity or support claims. This script projects the
two machine-readable sources that already own those facts into one small,
schema-versioned JSON document the site can fetch at an exact commit:

  docs/releases/<version>/manifest.json   The durable release record of the
                                          highest released version: version,
                                          annotated tag, source revision, and
                                          the published artifact set.
  benchmarks/support-matrix.json          The pinned support matrix: one
                                          status per provider x credential
                                          family.

Only fields a public marketing or documentation site may claim are copied;
digests, run ids, internal reasons, fixture profiles, and evidence bodies
stay in their owners. Nothing here re-derives a status or a version.

    python3 -B scripts/generate-site-feed.py            # rewrite the feed
    python3 -B scripts/generate-site-feed.py --check    # fail when stale or invalid

Output is deterministic given its inputs: fixed key order, no wall-clock
time, no network access. `generatedAt` is the latest timestamp the inputs
themselves carry, so regenerating without an input change yields identical
bytes. The contract and its compatibility policy are in
`docs/specs/distribution.md` and
`docs/decisions/2026-09-28-publish-a-commit-bound-public-site-feed.md`.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEED_DIR = Path("docs/contracts/site-feed/v1")
FEED_PATH = FEED_DIR / "feed.json"
SCHEMA_PATH = FEED_DIR / "feed.schema.json"
RELEASES_DIR = Path("docs/releases")
MATRIX_PATH = Path("benchmarks/support-matrix.json")

SCHEMA_VERSION = "redact-secret.site-feed/v1"
STATUS_ORDER = ("stable", "provisional", "pending", "unsupported")
ECOSYSTEM_ORDER = ("npm", "crates", "pypi")
ARTIFACT_ECOSYSTEM = {"npm": "npm", "crate": "crates", "pypi": "pypi"}

VERSION = re.compile(r"^(?P<core>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?:-(?P<pre>[0-9A-Za-z.-]+))?$")
BETA = re.compile(r"^(?P<core>\d+\.\d+\.\d+)-(?P<kind>alpha|beta|rc)\.(?P<number>\d+)$")
PEP440_KIND = {"alpha": "a", "beta": "b", "rc": "rc"}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class FeedError(ValueError):
    """An input manifest cannot back a public claim."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FeedError(message)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The same JSON Schema (draft 2020-12) subset validator the other live
# contracts use; the feed schema restricts itself to its keywords.
_SCHEMA_SUPPORT = load_module("site_feed_schema_support", Path(__file__).with_name("check-scoring-artifact.py"))


def read_bytes(root: Path, path: Path) -> bytes:
    return (root / path).read_bytes()


def load_json(root: Path, path: Path) -> dict:
    try:
        value = json.loads(read_bytes(root, path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FeedError(f"{path}: cannot read JSON ({error})") from error
    require(isinstance(value, dict), f"{path}: expected a JSON object")
    return value


def version_key(version: str) -> tuple:
    """SemVer 2.0.0 precedence: a release sorts after its prereleases, and
    numeric prerelease identifiers compare numerically (beta.10 > beta.9)."""
    match = VERSION.match(version)
    require(match is not None, f"{version!r} is not a SemVer version")
    core = tuple(int(part) for part in match["core"].split("."))
    pre = match["pre"]
    if pre is None:
        return core, 1, ()
    identifiers = tuple((0, int(item), "") if item.isdigit() else (1, 0, item) for item in pre.split("."))
    return core, 0, identifiers


def pep440(version: str) -> str:
    """The PEP 440 spelling PyPI carries for a Cargo/npm version."""
    match = BETA.match(version)
    if match is None:
        require(VERSION.match(version) is not None and "-" not in version, f"no PEP 440 spelling for {version!r}")
        return version
    return f"{match['core']}{PEP440_KIND[match['kind']]}{int(match['number'])}"


def latest_release_record(root: Path) -> Path:
    directory = root / RELEASES_DIR
    versions = [
        path.name
        for path in directory.iterdir()
        if path.is_dir() and VERSION.match(path.name) and (path / "manifest.json").is_file()
    ]
    require(bool(versions), f"{RELEASES_DIR}: no release record with a manifest.json")
    return RELEASES_DIR / max(versions, key=version_key) / "manifest.json"


def utc_instant(value: str, label: str) -> datetime:
    """An input timestamp as an aware UTC instant; a bare date is its midnight."""
    require(isinstance(value, str), f"{label}: expected a timestamp string")
    text = f"{value}T00:00:00+00:00" if DATE.match(value) else value.replace("Z", "+00:00")
    try:
        instant = datetime.fromisoformat(text)
    except ValueError as error:
        raise FeedError(f"{label}: {value!r} is not an ISO 8601 timestamp") from error
    require(instant.tzinfo is not None, f"{label}: {value!r} has no UTC offset")
    return instant.astimezone(timezone.utc)


def release_section(manifest: dict, path: Path) -> tuple[dict, datetime]:
    version = manifest.get("version")
    require(isinstance(version, str) and VERSION.match(version), f"{path}: version is not SemVer")
    require(path.parent.name == version, f"{path}: version {version} does not match its directory")
    source = manifest.get("source_revision")
    require(isinstance(source, str) and SHA40.match(source), f"{path}: source_revision is not a 40-hex commit")
    evidence = manifest.get("release_evidence")
    require(isinstance(evidence, dict), f"{path}: no release_evidence; the record is not final")
    tag = evidence.get("tag")
    require(
        isinstance(tag, dict) and tag.get("name") == f"v{version}",
        f"{path}: release_evidence.tag.name is not v{version}",
    )
    require(tag.get("target") == source, f"{path}: the annotated tag does not target source_revision")
    observed = evidence.get("observed_at")
    require(isinstance(observed, str) and DATE.match(observed), f"{path}: release_evidence.observed_at is not a date")

    artifact_set = manifest.get("artifact_set")
    state = manifest.get("registry_state")
    require(isinstance(artifact_set, list) and artifact_set, f"{path}: artifact_set is empty")
    require(isinstance(state, dict), f"{path}: registry_state is missing")
    packages = []
    for artifact in artifact_set:
        require(
            state.get(artifact) == "published",
            f"{path}: {artifact} is not recorded as published; a partial release is never claimed",
        )
        kind, _, name = artifact.partition(":")
        require(kind in ARTIFACT_ECOSYSTEM and name, f"{path}: unknown artifact identity {artifact!r}")
        ecosystem = ARTIFACT_ECOSYSTEM[kind]
        registry_version = pep440(version) if ecosystem == "pypi" else version
        if ecosystem == "pypi":
            files = [entry.get("file") for entry in manifest.get("artifact_digests", {}).get(artifact, [])]
            require(
                f"{name.replace('-', '_')}-{registry_version}.tar.gz" in files,
                f"{path}: {artifact} has no source distribution spelled {registry_version}",
            )
        packages.append({"ecosystem": ecosystem, "name": name, "version": registry_version})
    packages.sort(key=lambda item: (ECOSYSTEM_ORDER.index(item["ecosystem"]), item["name"]))

    section = {
        "version": version,
        "tag": tag["name"],
        "sourceRevision": source,
        "verifiedOn": observed,
        "packages": packages,
    }
    return section, utc_instant(observed, f"{path}: release_evidence.observed_at")


def support_section(matrix: dict, release_manifest: dict) -> tuple[dict, datetime]:
    report = matrix.get("sourceReport")
    require(isinstance(report, dict), f"{MATRIX_PATH}: sourceReport is missing")
    revision = report.get("revision")
    require(
        isinstance(revision, str) and SHA40.match(revision),
        f"{MATRIX_PATH}: sourceReport.revision is not a 40-hex commit",
    )
    require(report.get("dirty") is False, f"{MATRIX_PATH}: produced from a dirty benchmarks checkout")
    product = report.get("product") or {}
    families_in = matrix.get("families")
    require(isinstance(families_in, list) and families_in, f"{MATRIX_PATH}: families is empty")
    require(matrix.get("familyCount") == len(families_in), f"{MATRIX_PATH}: familyCount disagrees with families")

    families = []
    distribution = {status: 0 for status in STATUS_ORDER}
    for entry in families_in:
        status = entry.get("status")
        require(status in distribution, f"{MATRIX_PATH}: {entry.get('family')}: unknown status {status!r}")
        distribution[status] += 1
        families.append(
            {
                "provider": entry.get("provider"),
                "family": entry.get("family"),
                "name": entry.get("familyName"),
                "status": status,
                "evidenceTier": entry.get("evidenceTier"),
                "qualificationProfile": entry.get("qualificationProfile"),
            }
        )
    require(
        {key: matrix.get("distribution", {}).get(key) for key in STATUS_ORDER} == distribution,
        f"{MATRIX_PATH}: distribution disagrees with the family statuses",
    )
    candidate = (release_manifest.get("support_matrix_drift") or {}).get("candidate") or {}
    section = {
        "benchmarksRevision": revision,
        "generatedAt": utc_instant(report.get("generatedAt"), f"{MATRIX_PATH}: sourceReport.generatedAt").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "measuredProductVersion": product.get("declaredVersion"),
        "measuredProductRevision": product.get("sourceCommit"),
        "gatedLatestRelease": candidate.get("revision") == revision and candidate.get("runId") == report.get("runId"),
        "providerCount": matrix.get("providerCount"),
        "familyCount": len(families),
        "distribution": distribution,
        "families": families,
    }
    return section, utc_instant(report.get("generatedAt"), f"{MATRIX_PATH}: sourceReport.generatedAt")


def build_feed(root: Path = ROOT) -> dict:
    release_path = latest_release_record(root)
    release_manifest = load_json(root, release_path)
    matrix = load_json(root, MATRIX_PATH)
    release, release_time = release_section(release_manifest, release_path)
    support, support_time = support_section(matrix, release_manifest)
    sources = [
        {"role": role, "path": path.as_posix(), "sha256": hashlib.sha256(read_bytes(root, path)).hexdigest()}
        for role, path in (("release-manifest", release_path), ("support-matrix", MATRIX_PATH))
    ]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": max(release_time, support_time).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": sources,
        "release": release,
        "supportMatrix": support,
    }


def render(feed: dict) -> str:
    return json.dumps(feed, indent=2, ensure_ascii=False) + "\n"


def schema_errors(feed: dict, root: Path = ROOT) -> list[str]:
    schema = load_json(root, SCHEMA_PATH)
    errors = []
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{SCHEMA_PATH}: $schema is not JSON Schema draft 2020-12")
    if (schema.get("properties", {}).get("schemaVersion") or {}).get("const") != SCHEMA_VERSION:
        errors.append(f"{SCHEMA_PATH}: schemaVersion const is not {SCHEMA_VERSION}")
    errors.extend(f"{FEED_PATH}: {error}" for error in _SCHEMA_SUPPORT.validate_schema(feed, schema, schema))
    return errors


def check(root: Path = ROOT) -> list[str]:
    try:
        expected = render(build_feed(root))
    except FeedError as error:
        return [str(error)]
    errors = schema_errors(json.loads(expected), root)
    committed_path = root / FEED_PATH
    if not committed_path.is_file():
        errors.append(f"{FEED_PATH}: missing; run `npm run site-feed:generate`")
    elif committed_path.read_text(encoding="utf-8") != expected:
        errors.append(f"{FEED_PATH}: out of date with its source manifests; run `npm run site-feed:generate`")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="fail when the committed feed is stale or invalid")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.check:
        errors = check(args.root)
        for error in errors:
            print(f"site-feed: {error}", file=sys.stderr)
        if not errors:
            print(f"site-feed: {FEED_PATH} is current and valid")
        return 1 if errors else 0
    try:
        feed = build_feed(args.root)
    except FeedError as error:
        print(f"site-feed: {error}", file=sys.stderr)
        return 1
    errors = schema_errors(feed, args.root)
    if errors:
        for error in errors:
            print(f"site-feed: {error}", file=sys.stderr)
        return 1
    (args.root / FEED_PATH).write_text(render(feed), encoding="utf-8")
    print(f"site-feed: wrote {FEED_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
