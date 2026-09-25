#!/usr/bin/env python3
"""Record the artifact inventory a qualification run produced.

The last job of ``.github/workflows/artifact-qualification.yml``: it proves the whole
declared matrix was actually built from one revision, and writes down what
was built. Publication is not part of it and never happens here
(``decision-release-bindings-in-lockstep``).

Four things are recorded, all tied to one source commit:

1. **Every artifact** the run produced - family, target, file name, size, and
   SHA-256 - required to cover ``node-addon-targets``,
   ``cli-release-targets``, and ``python-wheel-targets`` exactly, plus the
   source distribution and the browser artifact. A missing or unexpected
   artifact fails the run.
2. **The contents of every package a release would publish** - the npm
   package and the public Rust crate, each listed file by file, so "inspect
   all package contents" is a recorded fact rather than a claim.
3. **The conformance corpus identity** - the SHA-256 of each canonical
   fixture file, because the artifact set only means something alongside the
   behavioral contract it was qualified against
   (``decision-govern-cross-language-conformance``).
4. **Installed JavaScript qualification** - one safe result for every declared
   Node major and browser engine, naming the candidate package digests,
   commands, runtime, and public incremental/stream outcomes.
5. **Clean-install qualification** (issue #586) - one result per
   ``docs/quickstart.md`` lane (Node, Python, browser bundler), each tied to
   that page's digest and to binaries that must be byte-identical to
   artifacts recorded in (1).
6. **Golden-path qualification** (issue #720) - one result per
   ``examples/mcp-redact`` lane (Node, Python): ``buildSafeContext`` run on
   the installed candidate, tied to this revision's example files, the pinned
   adapter packages, and binaries that must be byte-identical to artifacts
   recorded in (1).

    python3 -B scripts/record-artifact-inventory.py \\
        --artifacts qualification-artifacts --out artifact-inventory.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance" / "fixtures"

NPM_PACKAGE = Path("packages") / "javascript"
CRATE = "redact-secret"
# Issue #528: unlike the Node addon, browser, and Python artifacts, neither
# crate was ever packaged (only listed, via `crate_contents()`'s `cargo
# package --list`) before this run reached the registry -- `cargo publish`
# built and hashed each `.crate` file for the first time. `.github/workflows/
# artifact-qualification.yml`'s `inventory` job now runs `cargo package
# --no-verify --locked` for both crates before this script, so their bytes
# are recorded here the same way every other artifact family's are, and
# `publish-crates` can compare crates.io's own published checksum against
# this recorded digest instead of trusting the two builds agree.
CRATES = (CRATE, "redact-secret-cli")
CRATE_PACKAGE_DIR = Path("target") / "package"
PUBLIC_API_REVIEW = Path("docs/audits/candidate-public-contract-review.md")
CURRENT_PUBLIC_API_REVIEW = Path("docs/audits/beta6-candidate-public-contract-review.md")
CHANGELOG = Path("CHANGELOG.md")
RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
REGISTRY_INSTALL_VERIFIER = Path("scripts/verify-registry-install.mjs")


def declared_matrix() -> dict:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return manifest["workspace"]["metadata"]["redact-secret"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_commit() -> str:
    """The revision every artifact in this run was built from.

    ``GITHUB_SHA`` is not that revision on a ``pull_request`` event: it names
    the ephemeral ``refs/pull/N/merge`` commit GitHub synthesizes, which no
    clone of this repository can resolve. The workflow therefore passes the
    real head commit as ``SOURCE_COMMIT``, and an inventory that recorded an
    unresolvable id would defeat its own purpose
    (``decision-release-bindings-in-lockstep``).
    """
    for name in ("SOURCE_COMMIT", "GITHUB_SHA"):
        commit = os.environ.get(name, "").strip()
        if commit:
            return commit
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def collect(artifacts: Path) -> list[dict]:
    """One entry per file, with the artifact directory naming its family and
    target the way the workflow uploaded it.

    ``wasm-web-common`` (issue #382,
    ``decision-define-detector-profile-and-pack-contract``) is the `common`
    detector profile's browser artifact, uploaded from the same `browser` job
    as `wasm-web`, on the chromium leg only. It is recorded as its own
    `browser-common` family -- satisfying the qualification obligation that
    the inventory record each artifact's profile, size, and SHA-256 -- and
    `require_matrix` requires it alongside `browser`.
    """
    collected: list[dict] = []
    for directory in sorted(p for p in artifacts.iterdir() if p.is_dir()):
        name = directory.name
        if name.startswith(("installed-javascript-", "clean-install-", "golden-path-")):
            continue
        if name == "support-matrix-drift":
            # Issue #511: a release-decision record consumed by release.yml's
            # record-manifest job, not a per-target build artifact -- it has
            # no family/target and isn't part of what require_matrix checks.
            continue
        if name.startswith("node-addon-"):
            family, target = "node-addon", name.removeprefix("node-addon-")
        elif name.startswith("cli-"):
            family, target = "cli", name.removeprefix("cli-")
        elif name.startswith("python-wheel-"):
            family, target = "python-wheel", name.removeprefix("python-wheel-")
        elif name == "python-sdist":
            family, target = "python-sdist", None
        elif name == "wasm-web":
            family, target = "browser", None
        elif name == "wasm-web-common":
            family, target = "browser-common", None
        else:
            family, target = "unknown", None
        for path in sorted(p for p in directory.rglob("*") if p.is_file()):
            collected.append(
                {
                    "family": family,
                    "target": target,
                    "artifact": name,
                    "file": path.relative_to(directory).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                }
            )
    return collected


def collect_installed_javascript_qualification(
    artifacts: Path,
) -> tuple[list[dict], list[str]]:
    """Read the safe, installed-package result from every runtime matrix row."""
    results: list[dict] = []
    errors: list[str] = []
    for directory in sorted(artifacts.glob("installed-javascript-*")):
        files = sorted(path for path in directory.rglob("*") if path.is_file())
        if len(files) != 1 or files[0].suffix != ".json":
            errors.append(f"{directory.name}: expected exactly one JSON report")
            continue
        try:
            report = json.loads(files[0].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            errors.append(f"{directory.name}: invalid JSON report")
            continue
        if not isinstance(report, dict):
            errors.append(f"{directory.name}: report must be a JSON object")
            continue
        report["artifact"] = directory.name
        report["reportSha256"] = digest(files[0])
        results.append(report)
    return results, errors


def collect_clean_install_qualification(artifacts: Path) -> tuple[list[dict], list[str]]:
    """Read the one JSON report each `clean-install-<lane>` job uploaded."""
    return collect_lane_reports(artifacts, "clean-install-")


def collect_golden_path_qualification(artifacts: Path) -> tuple[list[dict], list[str]]:
    """Read the one JSON report each `golden-path-<lane>` job uploaded."""
    return collect_lane_reports(artifacts, "golden-path-")


def require_installed_javascript_qualification(
    matrix: dict, results: list[dict], expected_commit: str, expected_version: str
) -> list[str]:
    errors: list[str] = []
    incremental_hash = corpus_identity().get("incremental-corpus.json")
    incremental_count = incremental_corpus_fixture_count()
    expected = {
        "node": {str(value) for value in matrix["node-support-majors"]},
        "browser": set(matrix["browser-engines"]),
    }
    found = {"node": set(), "browser": set()}
    for result in results:
        lane = result.get("lane")
        runtime = result.get("runtime") or {}
        target = (
            str(runtime.get("version", "")).removeprefix("v").split(".")[0]
            if lane == "node"
            else runtime.get("name")
        )
        if lane not in found or not target:
            errors.append(f"{result.get('artifact', 'installed JavaScript')}: invalid lane/runtime")
            continue
        found[lane].add(target)
        label = f"installed JavaScript {lane} {target}"
        if result.get("artifact") != f"installed-javascript-{lane}-{target}":
            errors.append(f"{label}: artifact directory does not match its runtime")
        if result.get("schemaVersion") != 1:
            errors.append(f"{label}: unsupported evidence schema")
        if result.get("sourceCommit") != expected_commit:
            errors.append(f"{label}: source revision does not match the inventory")
        if result.get("published") is not False:
            errors.append(f"{label}: must record published=false")
        if result.get("productVersion") != expected_version:
            errors.append(f"{label}: product version does not match the inventory")
        if not result.get("commands"):
            errors.append(f"{label}: records no commands")
        checks = result.get("results") or {}
        for check in ("initialize", "scan", "incremental", "incrementalCorpus", "stream", "aiContextBoundary"):
            if checks.get(check) != "passed":
                errors.append(f"{label}: {check} did not pass")
        corpus = result.get("incrementalCorpus") or {}
        if corpus.get("path") != "conformance/fixtures/incremental-corpus.json":
            errors.append(f"{label}: incremental corpus path is incomplete")
        if corpus.get("sha256") != incremental_hash:
            errors.append(f"{label}: incremental corpus hash does not match the inventory")
        if corpus.get("offsetUnit") != "utf8-byte":
            errors.append(f"{label}: incremental corpus offset unit is invalid")
        if corpus.get("fixtureCount") != incremental_count:
            errors.append(f"{label}: incremental corpus fixture count does not match the inventory")
        packages = result.get("packageArtifacts") or []
        names = {package.get("name") for package in packages}
        if (
            "@redact-secret/core" not in names
            or "@redact-secret/wasm" not in names
            or not any(str(name).startswith("@redact-secret/node-") for name in names)
        ):
            errors.append(f"{label}: package artifact identity is incomplete")
        for package in packages:
            if package.get("version") != expected_version or not package.get("file"):
                errors.append(f"{label}: package artifact version/file identity is incomplete")
            if re.fullmatch(r"[0-9a-f]{64}", str(package.get("sha256", ""))) is None:
                errors.append(f"{label}: package artifact has no SHA-256 identity")

    for lane, declared in expected.items():
        counts = [
            str((result.get("runtime") or {}).get("version", "")).removeprefix("v").split(".")[0]
            if lane == "node"
            else (result.get("runtime") or {}).get("name")
            for result in results
            if result.get("lane") == lane
        ]
        for duplicate in sorted({target for target in counts if counts.count(target) > 1}):
            errors.append(f"installed JavaScript {lane}: duplicate qualification for {duplicate}")
        for missing in sorted(declared - found[lane]):
            errors.append(f"installed JavaScript {lane}: no qualification for {missing}")
        for extra in sorted(found[lane] - declared):
            errors.append(
                f"installed JavaScript {lane}: qualified {extra}, which Cargo.toml does not declare"
            )
    return errors


QUICKSTART = Path("docs") / "quickstart.md"
CLEAN_INSTALL_CHECKS = {
    "node": ("install", "contents", "output", "artifact", "fallback", "failure"),
    "python": ("install", "contents", "output", "artifact", "failure"),
    "browser": ("install", "contents", "bundle", "output", "artifact", "failure"),
}
CLEAN_INSTALL_ARTIFACT = {"node": "addon", "python": "native", "browser": "wasm"}
# The issue's own bound: the documented path completes in about five minutes.
CLEAN_INSTALL_MAX_BUDGET_SECONDS = 300

GOLDEN_PATH_EXAMPLE = Path("examples") / "mcp-redact"
ADAPTER_PIN = Path("adapters") / "pin-source.json"
GOLDEN_PATH_CHECKS = {
    "node": ("install", "contents", "artifact", "toolInput", "sanitized"),
    "python": ("install", "contents", "artifact", "toolInput", "sanitized"),
}
GOLDEN_PATH_ARTIFACT = {"node": "addon", "python": "native"}


def collect_lane_reports(artifacts: Path, prefix: str) -> tuple[list[dict], list[str]]:
    """Read the one JSON report each `<prefix><lane>` job uploaded."""
    results: list[dict] = []
    errors: list[str] = []
    for directory in sorted(artifacts.glob(f"{prefix}*")):
        files = sorted(path for path in directory.rglob("*") if path.is_file())
        if len(files) != 1 or files[0].suffix != ".json":
            errors.append(f"{directory.name}: expected exactly one JSON report")
            continue
        try:
            report = json.loads(files[0].read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            errors.append(f"{directory.name}: invalid JSON report")
            continue
        if not isinstance(report, dict):
            errors.append(f"{directory.name}: report must be a JSON object")
            continue
        report["artifact"] = directory.name
        report["reportSha256"] = digest(files[0])
        results.append(report)
    return results, errors


def require_clean_install_qualification(
    results: list[dict],
    collected: list[dict],
    expected_commit: str,
    expected_version: str,
    quickstart_sha256: str,
) -> list[str]:
    """Every quickstart lane passed, from this revision's page, on binaries
    this run built: each reported binary must match a recorded artifact's file
    name and SHA-256, which is what makes it the exact candidate."""
    errors: list[str] = []
    built = {(Path(entry["file"]).name, entry["sha256"]) for entry in collected}
    lanes = [result.get("lane") for result in results]
    for result in results:
        lane = result.get("lane")
        label = f"clean install {lane}"
        if lane not in CLEAN_INSTALL_CHECKS:
            errors.append(f"{result.get('artifact', 'clean install')}: invalid lane")
            continue
        if result.get("artifact") != f"clean-install-{lane}":
            errors.append(f"{label}: artifact directory does not match its lane")
        if result.get("schemaVersion") != 1:
            errors.append(f"{label}: unsupported evidence schema")
        if result.get("sourceCommit") != expected_commit:
            errors.append(f"{label}: source revision does not match the inventory")
        if result.get("published") is not False:
            errors.append(f"{label}: must qualify candidate artifacts (published=false)")
        if result.get("productVersion") != expected_version:
            errors.append(f"{label}: product version does not match the inventory")
        document = result.get("document") or {}
        if document.get("path") != QUICKSTART.as_posix() or document.get("sha256") != quickstart_sha256:
            errors.append(f"{label}: did not run this revision's {QUICKSTART.as_posix()}")
        if not result.get("commands"):
            errors.append(f"{label}: records no commands")
        if result.get("loadedArtifact") != CLEAN_INSTALL_ARTIFACT[lane]:
            errors.append(f"{label}: did not load the {CLEAN_INSTALL_ARTIFACT[lane]} artifact")
        checks = result.get("results") or {}
        for check in CLEAN_INSTALL_CHECKS[lane]:
            if checks.get(check) != "passed":
                errors.append(f"{label}: {check} did not pass")
        budget = result.get("budgetSeconds")
        elapsed = result.get("elapsedSeconds")
        if (
            not isinstance(budget, (int, float))
            or not isinstance(elapsed, (int, float))
            or budget > CLEAN_INSTALL_MAX_BUDGET_SECONDS
            or elapsed > budget
        ):
            errors.append(
                f"{label}: documented path did not finish within {CLEAN_INSTALL_MAX_BUDGET_SECONDS}s"
            )
        binaries = result.get("binaries") or []
        suffixes = sorted(Path(str(binary.get("file", ""))).suffix for binary in binaries)
        expected_suffixes = [".whl"] if lane == "python" else [".node", ".wasm", ".wasm"]
        if suffixes != expected_suffixes:
            errors.append(f"{label}: expected binaries {expected_suffixes}, reported {suffixes}")
        for binary in binaries:
            key = (Path(str(binary.get("file", ""))).name, binary.get("sha256"))
            if key not in built:
                errors.append(f"{label}: {key[0]} is not an artifact this run qualified")
    for lane in sorted(set(CLEAN_INSTALL_CHECKS) - set(lanes)):
        errors.append(f"clean install {lane}: no qualification")
    for lane in sorted({lane for lane in lanes if lanes.count(lane) > 1}):
        errors.append(f"clean install {lane}: duplicate qualification")
    return errors


def require_matrix(matrix: dict, collected: list[dict]) -> list[str]:
    errors: list[str] = []
    families = {
        "node-addon": set(matrix["node-addon-targets"]),
        "cli": set(matrix["cli-release-targets"]),
        "python-wheel": set(matrix["python-wheel-targets"]),
    }
    for family, declared in families.items():
        built = {entry["target"] for entry in collected if entry["family"] == family}
        for missing in sorted(declared - built):
            errors.append(f"{family}: no artifact for {missing}")
        for extra in sorted(built - declared):
            errors.append(f"{family}: built {extra}, which Cargo.toml does not declare")

    for family in ("python-sdist", "browser", "browser-common"):
        if not any(entry["family"] == family for entry in collected):
            errors.append(f"{family}: no artifact was produced")

    unknown = sorted({entry["artifact"] for entry in collected if entry["family"] == "unknown"})
    if unknown:
        errors.append(f"unrecognized artifact(s): {', '.join(unknown)}")

    # An addon that is only a loader with no compiled library is not an
    # artifact; the same for a CLI directory with no executable.
    for family, predicate, description in (
        ("node-addon", lambda f: f.endswith(".node"), "compiled .node library"),
        ("cli", lambda f: f in ("redact-secret", "redact-secret.exe"), "executable"),
    ):
        for target in sorted(families[family]):
            files = [
                entry["file"]
                for entry in collected
                if entry["family"] == family and entry["target"] == target
            ]
            # A target with no artifact at all is already reported above.
            if files and not any(predicate(name) for name in files):
                errors.append(f"{family} {target}: carries no {description}")
    return errors


def npm_package_contents() -> list[str]:
    """Packs `packages/javascript` itself, the way `packages/javascript/test/
    package-contents.test.ts` does: `LICENSE` is a tracked file there, so
    nothing needs to be staged in from elsewhere."""
    result = subprocess.run(
        ["npm", "pack", "--dry-run", "--json", str(ROOT / NPM_PACKAGE)],
        check=True,
        capture_output=True,
        text=True,
        shell=os.name == "nt",
    )
    return sorted(entry["path"] for entry in json.loads(result.stdout)[0]["files"])


def crate_contents() -> list[str]:
    # `--allow-dirty` only affects the refusal to list an uncommitted tree;
    # the listing itself is still the exact file set the crate would carry,
    # and a qualification run is always on a committed revision anyway.
    result = subprocess.run(
        ["cargo", "package", "--list", "--locked", "--allow-dirty", "-p", CRATE],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(line for line in result.stdout.splitlines() if line)


def crate_package_digests(package_dir: Path | None = None) -> list[dict]:
    """Hash whatever `.crate` files `cargo package` already produced.

    Issue #528: `cargo package --no-verify --locked` runs once, in the same
    `inventory` job as this script, for each crate in `CRATES` -- `--no-verify`
    because `redact-secret-cli` packages a registry dependency on
    `redact-secret` that does not resolve until `redact-secret` is actually
    live on crates.io (`decision-ship-first-release-artifact-set`); skipping
    the verify build does not change the tarball bytes it produces, only
    whether it compiles the extracted copy. An empty or missing directory
    (a PR run that skipped `full` qualification) yields no entries rather
    than an error -- `require_crates` is what turns their absence into a
    failure when a full qualification run was expected to produce them.
    """
    directory = package_dir if package_dir is not None else (ROOT / CRATE_PACKAGE_DIR)
    if not directory.is_dir():
        return []
    names_by_length = sorted(CRATES, key=len, reverse=True)
    entries: list[dict] = []
    for path in sorted(directory.glob("*.crate")):
        target = next((name for name in names_by_length if path.name.startswith(f"{name}-")), "unknown")
        entries.append(
            {
                "family": "crate",
                "target": target,
                "artifact": "crate-package",
                "file": path.name,
                "bytes": path.stat().st_size,
                "sha256": digest(path),
            }
        )
    return entries


def require_crates(crate_entries: list[dict]) -> list[str]:
    errors: list[str] = []
    built = {entry["target"] for entry in crate_entries}
    declared = set(CRATES)
    for missing in sorted(declared - built):
        errors.append(f"crate: no packaged .crate artifact for {missing}")
    for extra in sorted(built - declared):
        errors.append(f"crate: packaged {extra}, which is not a declared crate")
    return errors


def corpus_identity() -> dict[str, str]:
    return {
        path.name: digest(path)
        for path in sorted(FIXTURES.glob("*.json"))
    }


def incremental_corpus_fixture_count() -> int:
    with (FIXTURES / "incremental-corpus.json").open(encoding="utf-8") as handle:
        corpus = json.load(handle)
    fixtures = corpus.get("fixtures")
    return len(fixtures) if isinstance(fixtures, list) else 0


def release_readiness_record() -> dict:
    """Record the non-artifact review and post-publication boundaries."""
    return {
        "issue": 606,
        "publicApiAndChangelogReview": {
            "status": "required-before-release-approval",
            "currentPublicApiReview": {
                "path": str(CURRENT_PUBLIC_API_REVIEW),
                "sha256": digest(ROOT / CURRENT_PUBLIC_API_REVIEW),
            },
            "publicApiReview": {
                "path": str(PUBLIC_API_REVIEW),
                "sha256": digest(ROOT / PUBLIC_API_REVIEW),
                "scope": "historical-beta.1-candidate-review",
            },
            "changelog": {
                "path": str(CHANGELOG),
                "sha256": digest(ROOT / CHANGELOG),
            },
        },
        "registryInstallVerification": {
            "status": "post-publication-release-workflow",
            "workflow": str(RELEASE_WORKFLOW),
            "verifier": str(REGISTRY_INSTALL_VERIFIER),
            "nodeTargets": "declared node-publish-targets",
            "browserLane": "chromium",
            "authorization": "separate release approval required",
        },
    }


def require_golden_path_qualification(
    results: list[dict],
    collected: list[dict],
    expected_commit: str,
    expected_version: str,
) -> list[str]:
    """Both golden-path lanes passed on this revision's example, the Node lane
    on the pinned adapter packages, and every reported binary is an artifact
    this run built (file name and SHA-256), which is what makes the installed
    core the exact candidate the rest of this run qualified."""
    errors: list[str] = []
    built = {(Path(entry["file"]).name, entry["sha256"]) for entry in collected}
    pin = json.loads((ROOT / ADAPTER_PIN).read_text(encoding="utf-8"))
    pinned_adapters = {
        "repository": pin["repository"],
        "commit": pin["commit"],
        "packages": sorted(
            (
                {"name": package["name"], "version": package["version"], "contentDigest": package["contentDigest"]}
                for package in pin["packages"]
            ),
            key=lambda package: package["name"],
        ),
    }
    example = GOLDEN_PATH_EXAMPLE.as_posix()
    lanes = [result.get("lane") for result in results]
    for result in results:
        lane = result.get("lane")
        label = f"golden path {lane}"
        if lane not in GOLDEN_PATH_CHECKS:
            errors.append(f"{result.get('artifact', 'golden path')}: invalid lane")
            continue
        if result.get("artifact") != f"golden-path-{lane}":
            errors.append(f"{label}: artifact directory does not match its lane")
        if result.get("schemaVersion") != 1:
            errors.append(f"{label}: unsupported evidence schema")
        if result.get("sourceCommit") != expected_commit:
            errors.append(f"{label}: source revision does not match the inventory")
        if result.get("published") is not False:
            errors.append(f"{label}: must qualify candidate artifacts (published=false)")
        if result.get("productVersion") != expected_version:
            errors.append(f"{label}: product version does not match the inventory")
        record = result.get("example") or {}
        files = record.get("files") or []
        paths = [str(entry.get("path", "")) for entry in files]
        stale = [
            entry
            for entry in files
            if not str(entry.get("path", "")).startswith(f"{example}/")
            or not (ROOT / str(entry.get("path"))).is_file()
            or digest(ROOT / str(entry.get("path"))) != entry.get("sha256")
        ]
        if record.get("path") != example or not files or record.get("entry") not in paths or stale:
            errors.append(f"{label}: did not run this revision's {example}")
        if lane == "node" and result.get("adapters") != pinned_adapters:
            errors.append(f"{label}: did not install the adapters pinned in {ADAPTER_PIN.as_posix()}")
        if result.get("loadedArtifact") != GOLDEN_PATH_ARTIFACT[lane]:
            errors.append(f"{label}: did not load the {GOLDEN_PATH_ARTIFACT[lane]} artifact")
        checks = result.get("results") or {}
        for check in GOLDEN_PATH_CHECKS[lane]:
            if checks.get(check) != "passed":
                errors.append(f"{label}: {check} did not pass")
        binaries = result.get("binaries") or []
        suffixes = sorted(Path(str(binary.get("file", ""))).suffix for binary in binaries)
        expected_suffixes = [".whl"] if lane == "python" else [".node", ".wasm", ".wasm"]
        if suffixes != expected_suffixes:
            errors.append(f"{label}: expected binaries {expected_suffixes}, reported {suffixes}")
        for binary in binaries:
            key = (Path(str(binary.get("file", ""))).name, binary.get("sha256"))
            if key not in built:
                errors.append(f"{label}: {key[0]} is not an artifact this run qualified")
    for lane in sorted(set(GOLDEN_PATH_CHECKS) - set(lanes)):
        errors.append(f"golden path {lane}: no qualification")
    for lane in sorted({lane for lane in lanes if lanes.count(lane) > 1}):
        errors.append(f"golden path {lane}: duplicate qualification")
    return errors


def render_summary(inventory: dict) -> str:
    lines = [
        "## Qualification matrix",
        "",
        f"- Source commit: `{inventory['sourceCommit']}`",
        f"- Product version: `{inventory['productVersion']}`",
        f"- Artifacts: {len(inventory['artifacts'])} file(s)",
        "- Published: no",
        "- Release authority: separate approval required",
        "",
        "| Family | Target | File | Bytes | SHA-256 |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for entry in inventory["artifacts"]:
        lines.append(
            f"| {entry['family']} | {entry['target'] or '-'} | `{entry['file']}` | "
            f"{entry['bytes']} | `{entry['sha256'][:16]}…` |"
        )
    lines.extend(
        [
            "",
            "### Installed JavaScript qualification",
            "",
            "| Lane | Runtime | Incremental corpus | Stream | Evidence SHA-256 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for result in inventory.get("installedJavaScriptQualification", []):
        runtime = result["runtime"]
        corpus = result.get("incrementalCorpus") or {}
        lines.append(
            f"| {result['lane']} | {runtime['name']} {runtime['version']} | "
            f"{result['results']['incrementalCorpus']} "
            f"({corpus.get('fixtureCount', '?')} fixtures) | "
            f"{result['results']['stream']} | "
            f"`{result['reportSha256'][:16]}…` |"
        )
    lines.extend(
        [
            "",
            "### Clean-install qualification",
            "",
            "| Lane | Runtime | Loaded | Elapsed | Evidence SHA-256 |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for result in inventory.get("cleanInstallQualification", []):
        runtime = result.get("runtime") or {}
        lines.append(
            f"| {result.get('lane')} | {runtime.get('name')} {runtime.get('version')} | "
            f"{result.get('loadedArtifact')} | {result.get('elapsedSeconds')}s | "
            f"`{result['reportSha256'][:16]}…` |"
        )
    lines.extend(
        [
            "",
            "### Golden-path qualification",
            "",
            "| Lane | Runtime | Loaded | Evidence SHA-256 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for result in inventory.get("goldenPathQualification", []):
        runtime = result.get("runtime") or {}
        lines.append(
            f"| {result.get('lane')} | {runtime.get('name')} {runtime.get('version')} | "
            f"{result.get('loadedArtifact')} | `{result['reportSha256'][:16]}…` |"
        )
    readiness = inventory.get("releaseReadiness", {})
    review = readiness.get("publicApiAndChangelogReview", {})
    registry = readiness.get("registryInstallVerification", {})
    if review or registry:
        lines.extend(
            [
                "",
                "### Release readiness boundaries",
                "",
                f"- Public API/changelog review: {review.get('status', 'not recorded')}",
                f"- Registry install verification: {registry.get('status', 'not recorded')}",
                f"- Registry verifier: `{registry.get('verifier', 'not recorded')}`",
                "- This inventory does not authorize publication, tagging, deployment, or release approval.",
            ]
        )
    lines.append("")
    for package, files in inventory["packageContents"].items():
        lines.append(f"<details><summary>{package} — {len(files)} file(s)</summary>")
        lines.append("")
        lines.extend(f"- `{name}`" for name in files)
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts", type=Path, required=True, help="directory of downloaded artifacts"
    )
    parser.add_argument("--out", type=Path, required=True, help="inventory JSON to write")
    parser.add_argument("--summary", type=Path, help="markdown summary to append to")
    arguments = parser.parse_args()

    if not arguments.artifacts.is_dir():
        print(f"{arguments.artifacts}: missing", file=sys.stderr)
        return 1

    matrix = declared_matrix()
    collected = collect(arguments.artifacts)
    crate_entries = crate_package_digests()
    collected = collected + crate_entries
    qualification, qualification_errors = collect_installed_javascript_qualification(
        arguments.artifacts
    )
    revision = source_commit()
    with (ROOT / NPM_PACKAGE / "package.json").open(encoding="utf-8") as handle:
        product_version = json.load(handle)["version"]
    errors = require_matrix(matrix, collected)
    errors.extend(require_crates(crate_entries))
    errors.extend(qualification_errors)
    errors.extend(
        require_installed_javascript_qualification(
            matrix, qualification, revision, product_version
        )
    )
    clean_install, clean_install_errors = collect_clean_install_qualification(arguments.artifacts)
    errors.extend(clean_install_errors)
    errors.extend(
        require_clean_install_qualification(
            clean_install, collected, revision, product_version, digest(ROOT / QUICKSTART)
        )
    )
    golden_path, golden_path_errors = collect_golden_path_qualification(arguments.artifacts)
    errors.extend(golden_path_errors)
    errors.extend(
        require_golden_path_qualification(golden_path, collected, revision, product_version)
    )

    inventory = {
        "sourceCommit": revision,
        "sourceRef": os.environ.get("GITHUB_REF", ""),
        "workflowRun": os.environ.get("GITHUB_RUN_ID", ""),
        "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "productVersion": product_version,
        "published": False,
        "conformanceFixtures": corpus_identity(),
        "declaredMatrix": {
            "nodeAddonTargets": matrix["node-addon-targets"],
            "nodePublishTargets": matrix["node-publish-targets"],
            "cliReleaseTargets": matrix["cli-release-targets"],
            "pythonWheelTargets": matrix["python-wheel-targets"],
            "browserEngines": matrix["browser-engines"],
            "nodeSupportMajors": matrix["node-support-majors"],
        },
        "packageContents": {
            "@redact-secret/core": npm_package_contents(),
            f"{CRATE} (crate)": crate_contents(),
        },
        "artifacts": collected,
        "installedJavaScriptQualification": qualification,
        "cleanInstallQualification": clean_install,
        "goldenPathQualification": golden_path,
        "releaseReadiness": release_readiness_record(),
    }

    arguments.out.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {arguments.out} ({len(collected)} artifact file(s))")

    if arguments.summary is not None:
        with arguments.summary.open("a", encoding="utf-8") as handle:
            handle.write(render_summary(inventory) + "\n")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"\n{len(errors)} error(s); the declared matrix is incomplete", file=sys.stderr)
        return 1
    print("every declared artifact is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
