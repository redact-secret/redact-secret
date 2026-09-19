#!/usr/bin/env python3
"""Enforce the Rust workspace policies declared in the root Cargo.toml.

Checks, in order:

1. Core dependency boundary: the core crate's transitive normal and build
   dependency graph contains only packages listed in
   ``[workspace.metadata.redact-secret] allowed-dependencies`` and never a
   package listed in ``forbidden-dependencies``.
2. Unsafe-code policy: every member inherits workspace lints, the workspace
   denies ``unsafe_code``, and the core and CLI crate roots forbid it.
3. Version lockstep: the workspace version, every member, every manifest
   named in ``LOCKSTEP_MANIFESTS`` (``package.json``, ``bindings/node/package.json``,
   ``packages/javascript/package.json``), the WebAssembly package manifest
   (``bindings/wasm/npm/package.json``), and every native platform package
   manifest discovered under ``bindings/node/npm/*/package.json`` share one
   product version, and every ``@redact-secret/*`` dependency those manifests
   declare is pinned to exactly that version.
4. Node engines: every manifest in ``LOCKSTEP_MANIFESTS`` and every native
   platform package manifest declares ``engines.node`` as exactly the Node
   majors ``ci.yml``'s ``test`` job matrix exercises, so the promised
   platform and the tested platform cannot drift apart. The WebAssembly
   package declares no ``engines.node`` at all — it ships no Node.js-specific
   claim to keep in lockstep.
5. MSRV: the declared ``rust-version`` is inherited by every member, is at
   least the highest ``rust-version`` required by any resolved dependency, and
   matches the ``MSRV`` value exercised by the CI workflow.
6. Public API: the names the core crate root exports, and the names its
   documented "Public surface" table cites, both match ``core-public-api``
   exactly — so nothing joins or leaves the published surface without a
   manifest change to review, and the documentation cannot fall behind it.
7. Source boundary: no core source names a runtime I/O, environment,
   process, clock, or thread facility, and no core source reaches for a
   binding crate. This is the compile-time half of the "no runtime I/O"
   guarantee; the dependency boundary in check 1 is the other half.
8. Core manifest shape: the core declares no Cargo features, no optional or
   target-specific dependencies, and no dependency named in
   ``binding-dependencies`` — the crate a dependent gets is the crate this
   repository tests, with no feature-selected variants.
9. Package contents: every file ``cargo package`` would publish for the core
   matches ``core-package-globs``, and the files in
   ``core-package-required`` are all present.

Run ``--recheck-crate-name`` to also query crates.io for the preferred crate
name; that is the only check that uses the network and it is off by default.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath


CI_WORKFLOW = Path(".github") / "workflows" / "ci.yml"
CI_MSRV = re.compile(r"^\s*MSRV:\s*[\"']?(\d+\.\d+(?:\.\d+)?)[\"']?\s*$", re.M)
# The `test` job's `node-version` matrix: one or more `- <major>` entries
# immediately under the `node-version:` key.
CI_NODE_VERSIONS = re.compile(r"node-version:\s*\n((?:\s*-\s*\d+\s*\n)+)")
NODE_VERSION_ENTRY = re.compile(r"-\s*(\d+)")
FORBID_UNSAFE = re.compile(r"^\s*#!\[forbid\(unsafe_code\)\]\s*$", re.M)
FORBID_UNSAFE_ROOTS = {"redact-secret": "src/lib.rs", "redact-secret-cli": "src/main.rs"}
LOCKSTEP_MANIFESTS = ("package.json", "bindings/node/package.json", "packages/javascript/package.json")
# The WebAssembly package: an ordinary lockstep manifest for version
# purposes, but it declares no `engines.node` (it ships no Node.js-specific
# claim), so it is not part of the engines check below.
WASM_MANIFEST = "bindings/wasm/npm/package.json"
# `bindings/node/npm/<platform>/package.json` per published N-API target,
# discovered rather than hardcoded: adding or removing one of these
# directories changes what this script checks without editing the script,
# which is what keeps `scripts/check-artifact-matrix.py`'s target-list
# enforcement (`node-publish-targets`) and this version/engines enforcement
# from being able to drift apart from each other.
NATIVE_PLATFORM_MANIFEST_DIR = Path("bindings") / "node" / "npm"

# `pub use path::{A, B};`, `pub use path::name;`, and the `pub const NAME`
# items the crate root declares directly.
PUB_USE = re.compile(r"^pub use\s+(?P<path>[^;]+);", re.M)
PUB_ITEM = re.compile(r"^pub (?:mod|const|fn|struct|enum|trait|type)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.M)
TEST_MODULE = re.compile(r"^#\[cfg\(test\)\]", re.M)

# Rows of the "Public surface" table in the crate-root documentation, and the
# `[`Name`]` / `Name` items they cite.
DOC_TABLE_ROW = re.compile(r"^//! \|.*\|$", re.M)
DOC_TABLE_ITEM = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")

# Facilities a side-effect-free core must never name. `env!` is deliberately
# absent: it is resolved by the compiler and reads nothing at runtime.
FORBIDDEN_SOURCE = {
    "std::fs": "filesystem access",
    "std::net": "network access",
    "std::env": "process environment access",
    "std::process": "process control",
    "std::io": "standard stream access",
    "std::thread": "thread spawning",
    "std::time": "clock access",
    "std::os": "platform-specific host access",
    "option_env!": "build-environment lookup",
    "include_str!": "file inclusion",
    "include_bytes!": "file inclusion",
    "println!": "standard output",
    "eprintln!": "standard error",
}
USER_AGENT = "redact-secret workspace check (https://github.com/redact-secret/redact-secret)"


def version_key(version: str) -> tuple[int, int, int]:
    """Normalize ``1.88`` and ``1.88.0`` to the same comparable key."""
    parts = [int(part) for part in version.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def load_metadata(root: Path) -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(output)


def workspace_members(metadata: dict) -> dict[str, dict]:
    members = set(metadata["workspace_members"])
    return {package["id"]: package for package in metadata["packages"] if package["id"] in members}


def transitive_dependencies(metadata: dict, package_id: str, kinds: frozenset[str | None]) -> set[str]:
    """Return the package ids reachable from ``package_id`` through ``kinds``."""
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    seen: set[str] = set()
    pending = [package_id]
    while pending:
        current = pending.pop()
        for dep in nodes[current]["deps"]:
            if not any(kind["kind"] in kinds for kind in dep["dep_kinds"]):
                continue
            if dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                pending.append(dep["pkg"])
    return seen


def check_core_boundary(metadata: dict, policy: dict) -> list[str]:
    errors: list[str] = []
    core_name = policy["core-package"]
    packages = {package["id"]: package for package in metadata["packages"]}
    core = core_package(metadata, policy)
    if core is None:
        return [f"core package {core_name} is not a workspace member"]

    allowed = set(policy.get("allowed-dependencies", []))
    forbidden = set(policy.get("forbidden-dependencies", []))
    for dep_id in sorted(transitive_dependencies(metadata, core["id"], frozenset({None, "build"}))):
        name = packages[dep_id]["name"]
        if name in forbidden:
            errors.append(f"{core_name}: forbidden dependency {name} is in the core dependency graph")
        elif name not in allowed:
            errors.append(f"{core_name}: dependency {name} is not in allowed-dependencies")
    return errors


def check_unsafe_policy(root: Path, metadata: dict, root_manifest: dict) -> list[str]:
    errors: list[str] = []
    lints = root_manifest.get("workspace", {}).get("lints", {}).get("rust", {})
    level = lints.get("unsafe_code")
    if isinstance(level, dict):
        level = level.get("level")
    if level not in {"deny", "forbid"}:
        errors.append("Cargo.toml: [workspace.lints.rust] must set unsafe_code to deny or forbid")

    for package in workspace_members(metadata).values():
        manifest_path = Path(package["manifest_path"]).resolve()
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
        if manifest.get("lints", {}).get("workspace") is not True:
            errors.append(f"{manifest_path.relative_to(root)}: must set [lints] workspace = true")
        source = FORBID_UNSAFE_ROOTS.get(package["name"])
        if source is None:
            continue
        source_path = manifest_path.parent / source
        if not source_path.is_file() or not FORBID_UNSAFE.search(source_path.read_text(encoding="utf-8")):
            errors.append(f"{source_path.relative_to(root)}: must contain #![forbid(unsafe_code)]")
    return errors


def native_platform_manifests(root: Path) -> list[str]:
    """Every native N-API platform package manifest, as paths relative to
    ``root``, discovered under ``bindings/node/npm/*/package.json`` rather
    than enumerated by hand."""
    directory = root / NATIVE_PLATFORM_MANIFEST_DIR
    if not directory.is_dir():
        return []
    return sorted(
        (NATIVE_PLATFORM_MANIFEST_DIR / child.name / "package.json").as_posix()
        for child in directory.iterdir()
        if child.is_dir() and (child / "package.json").is_file()
    )


def check_version_lockstep(root: Path, metadata: dict, root_manifest: dict) -> list[str]:
    errors: list[str] = []
    version = root_manifest.get("workspace", {}).get("package", {}).get("version")
    if not version:
        return ["Cargo.toml: [workspace.package] must declare version"]
    for package in workspace_members(metadata).values():
        if package["version"] != version:
            errors.append(f"{package['name']}: version {package['version']} differs from workspace version {version}")
    manifests = LOCKSTEP_MANIFESTS + (WASM_MANIFEST,) + tuple(native_platform_manifests(root))
    for relative in manifests:
        path = root / relative
        if not path.is_file():
            errors.append(f"{relative}: missing lockstep manifest")
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        found = manifest.get("version")
        if found != version:
            errors.append(f"{relative}: version {found} differs from workspace version {version}")
        # The facade pins its runtime packages exactly. Pre-publish consumer
        # qualification substitutes local tarballs for them, so a stale pin
        # would first surface as a registry install of the wrong version.
        for field in ("dependencies", "optionalDependencies"):
            for name, pinned in sorted((manifest.get(field) or {}).items()):
                if name.startswith("@redact-secret/") and pinned != version:
                    errors.append(
                        f"{relative}: {field} pins {name} to {pinned}, not workspace version {version}"
                    )
    return errors


def ci_node_majors(workflow_text: str) -> list[int]:
    """The Node majors the `test` job's matrix exercises, ascending."""
    match = CI_NODE_VERSIONS.search(workflow_text)
    if not match:
        return []
    return sorted(int(entry) for entry in NODE_VERSION_ENTRY.findall(match.group(1)))


def expected_node_engines(majors: list[int]) -> str:
    """The `engines.node` range that names exactly these majors, no others.

    `>=20` cannot be bound to a finite CI matrix: it also claims every future
    major CI has never run. `20.x || 22.x` claims exactly the majors tested,
    so a manifest and the CI matrix can be checked against each other.
    """
    return " || ".join(f"{major}.x" for major in majors)


def check_node_engines(root: Path) -> list[str]:
    """Every lockstep manifest's and every native platform package's
    `engines.node` names exactly the Node majors `ci.yml`'s `test` job matrix
    exercises — narrowed to that finite set rather than left open-ended, so
    the two cannot drift apart (`docs/audits/release-gap-disposition.md`
    `R/F-23`). A native platform package that claims fewer majors than the
    wrapper silently narrows what an installer can actually run on without
    that narrowing ever being reviewed."""
    workflow = root / CI_WORKFLOW
    if not workflow.is_file():
        return [f"{CI_WORKFLOW}: missing CI workflow"]
    majors = ci_node_majors(workflow.read_text(encoding="utf-8"))
    if not majors:
        return [f"{CI_WORKFLOW}: no Node major versions found in the test job's node-version matrix"]

    expected = expected_node_engines(majors)
    errors: list[str] = []
    manifests = LOCKSTEP_MANIFESTS + tuple(native_platform_manifests(root))
    for relative in manifests:
        path = root / relative
        if not path.is_file():
            errors.append(f"{relative}: missing lockstep manifest")
            continue
        declared = json.loads(path.read_text(encoding="utf-8")).get("engines", {}).get("node")
        if declared != expected:
            errors.append(
                f"{relative}: engines.node {declared!r} must be {expected!r}, "
                f"the exact Node majors {CI_WORKFLOW.as_posix()} tests"
            )
    return errors


def derived_msrv(metadata: dict) -> tuple[str | None, list[tuple[str, str, str]]]:
    """Return the highest dependency rust-version and the packages that set it."""
    members = set(metadata["workspace_members"])
    requirements = [
        (package["rust_version"], package["name"], package["version"])
        for package in metadata["packages"]
        if package["id"] not in members and package.get("rust_version")
    ]
    if not requirements:
        return None, []
    highest = max(version_key(requirement[0]) for requirement in requirements)
    culprits = sorted(
        (name, version, rust_version)
        for rust_version, name, version in requirements
        if version_key(rust_version) == highest
    )
    return culprits[0][2], culprits


def check_msrv(root: Path, metadata: dict, root_manifest: dict) -> list[str]:
    errors: list[str] = []
    declared = root_manifest.get("workspace", {}).get("package", {}).get("rust-version")
    if not declared:
        return ["Cargo.toml: [workspace.package] must declare rust-version"]
    for package in workspace_members(metadata).values():
        if package.get("rust_version") != declared:
            errors.append(f"{package['name']}: rust-version {package.get('rust_version')} differs from workspace MSRV {declared}")

    derived, culprits = derived_msrv(metadata)
    if derived is not None and version_key(derived) > version_key(declared):
        names = ", ".join(f"{name} {version}" for name, version, _ in culprits)
        errors.append(f"MSRV {declared} is below {derived} required by {names}")

    workflow = root / CI_WORKFLOW
    if not workflow.is_file():
        errors.append(f"{CI_WORKFLOW}: missing CI workflow")
    else:
        found = CI_MSRV.findall(workflow.read_text(encoding="utf-8"))
        if found != [declared]:
            errors.append(f"{CI_WORKFLOW}: expected exactly one MSRV: {declared}, found {found or 'none'}")
    return errors


def core_package(metadata: dict, policy: dict) -> dict | None:
    core_name = policy["core-package"]
    return next((p for p in workspace_members(metadata).values() if p["name"] == core_name), None)


def core_root(metadata: dict, policy: dict) -> Path | None:
    """The directory of the core crate, or ``None`` when it is not a member."""
    core = core_package(metadata, policy)
    return None if core is None else Path(core["manifest_path"]).resolve().parent


def exported_names(crate_root_source: str) -> set[str]:
    """The public names a crate root re-exports or declares.

    Only the surface above the first ``#[cfg(test)]`` counts; a test module
    is not part of the published API.
    """
    boundary = TEST_MODULE.search(crate_root_source)
    source = crate_root_source[: boundary.start()] if boundary else crate_root_source

    names: set[str] = set()
    for match in PUB_USE.finditer(source):
        path = " ".join(match.group("path").split())
        if "{" in path:
            inner = path[path.index("{") + 1 : path.rindex("}")]
            leaves = inner.split(",")
        else:
            leaves = [path]
        for leaf in leaves:
            leaf = leaf.strip().split("::")[-1].strip()
            if leaf:
                names.add(leaf)
    for match in PUB_ITEM.finditer(source):
        names.add(match.group("name"))
    return names


def check_core_public_api(root: Path, metadata: dict, policy: dict) -> list[str]:
    """The core crate root exports exactly ``core-public-api``."""
    declared = policy.get("core-public-api")
    if declared is None:
        return ["Cargo.toml: [workspace.metadata.redact-secret] must declare core-public-api"]
    crate = core_root(metadata, policy)
    if crate is None:
        return []
    source_path = crate / "src" / "lib.rs"
    if not source_path.is_file():
        return [f"{source_path.relative_to(root)}: missing core crate root"]

    source = source_path.read_text(encoding="utf-8")
    relative = source_path.relative_to(root)
    found = exported_names(source)
    expected = set(declared)
    errors = []
    for name in sorted(found - expected):
        errors.append(f"{relative}: {name} is public but not in core-public-api")
    for name in sorted(expected - found):
        errors.append(f"Cargo.toml: core-public-api lists {name}, which the core crate root does not export")

    # The crate-root documentation claims its table is the whole surface, so
    # the table has to carry every name — an omission there is a false claim,
    # not a formatting nit.
    documented: set[str] = set()
    for row in DOC_TABLE_ROW.findall(source):
        documented |= set(DOC_TABLE_ITEM.findall(row))
    if not documented:
        errors.append(f"{relative}: the crate documentation must carry a public-surface table")
    for name in sorted(expected - documented):
        errors.append(f"{relative}: {name} is public but absent from the documented public-surface table")
    for name in sorted(documented - expected):
        errors.append(f"{relative}: the public-surface table cites {name}, which is not in core-public-api")
    return errors


def check_core_source_boundary(root: Path, metadata: dict, policy: dict) -> list[str]:
    """No core source names a runtime I/O facility or a binding crate."""
    crate = core_root(metadata, policy)
    if crate is None:
        return []
    bindings = set(policy.get("binding-dependencies", []))
    binding_paths = {name.replace("-", "_") for name in bindings}

    errors = []
    for source_path in sorted((crate / "src").rglob("*.rs")):
        source = source_path.read_text(encoding="utf-8")
        relative = source_path.relative_to(root)
        for needle, reason in FORBIDDEN_SOURCE.items():
            if needle in source:
                errors.append(f"{relative}: names {needle} ({reason}); the core performs no runtime I/O")
        for name in sorted(binding_paths):
            if re.search(rf"\b{re.escape(name)}::", source):
                errors.append(f"{relative}: names the binding crate {name}; the core is binding-neutral")
    return errors


def check_core_manifest(root: Path, metadata: dict, policy: dict) -> list[str]:
    """The core ships one shape: no features, no optional or target deps."""
    crate = core_root(metadata, policy)
    if crate is None:
        return []
    manifest_path = crate / "Cargo.toml"
    with manifest_path.open("rb") as handle:
        manifest = tomllib.load(handle)
    relative = manifest_path.relative_to(root)

    errors = []
    if manifest.get("features"):
        errors.append(f"{relative}: the core declares no Cargo features; found {sorted(manifest['features'])}")
    if manifest.get("target"):
        errors.append(f"{relative}: the core declares no target-specific dependencies")
    bindings = set(policy.get("binding-dependencies", []))
    for section in ("dependencies", "build-dependencies"):
        for name, spec in (manifest.get(section) or {}).items():
            if name in bindings:
                errors.append(f"{relative}: [{section}] {name} is a binding dependency; the core is binding-neutral")
            if isinstance(spec, dict) and spec.get("optional"):
                errors.append(f"{relative}: [{section}] {name} is optional, which would feature-gate the core")
    if not manifest.get("package", {}).get("include"):
        errors.append(f"{relative}: [package] must declare include so the published file set is explicit")
    return errors


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a package-content glob: ``**`` spans directories, ``*`` does not."""
    out = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out += "(?:[^/]+/)*"
            index += 3
        elif pattern.startswith("**", index):
            out += ".*"
            index += 2
        elif pattern[index] == "*":
            out += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            out += "[^/]"
            index += 1
        else:
            out += re.escape(pattern[index])
            index += 1
    return re.compile(f"^{out}$")


def cargo_package_list(root: Path, package: str) -> list[str]:
    """The files ``cargo package`` would publish for ``package``."""
    output = subprocess.run(
        ["cargo", "package", "--list", "--locked", "--no-verify", "--allow-dirty", "-p", package],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line.strip() for line in output.splitlines() if line.strip()]


def check_core_package_contents(policy: dict, listed: list[str]) -> list[str]:
    """Every published file matches an allowed glob, and none is missing."""
    globs = policy.get("core-package-globs")
    if globs is None:
        return ["Cargo.toml: [workspace.metadata.redact-secret] must declare core-package-globs"]
    allowed = [glob_to_regex(pattern) for pattern in globs]
    errors = []
    for path in listed:
        normalized = PurePosixPath(path).as_posix()
        if not any(rule.match(normalized) for rule in allowed):
            errors.append(f"{policy['core-package']}: packaged file {normalized} matches no core-package-globs entry")
    for required in policy.get("core-package-required", []):
        if required not in listed:
            errors.append(f"{policy['core-package']}: core-package-required file {required} is not in the package")
    return errors


def validate(root: Path, metadata: dict, package_lister=None) -> list[str]:
    root = root.resolve()
    with (root / "Cargo.toml").open("rb") as handle:
        root_manifest = tomllib.load(handle)
    policy = metadata.get("metadata") or {}
    policy = policy.get("redact-secret")
    if not policy:
        return ["Cargo.toml: missing [workspace.metadata.redact-secret] policy"]
    errors: list[str] = []
    errors.extend(check_core_boundary(metadata, policy))
    errors.extend(check_unsafe_policy(root, metadata, root_manifest))
    errors.extend(check_version_lockstep(root, metadata, root_manifest))
    errors.extend(check_node_engines(root))
    errors.extend(check_msrv(root, metadata, root_manifest))
    errors.extend(check_core_public_api(root, metadata, policy))
    errors.extend(check_core_source_boundary(root, metadata, policy))
    errors.extend(check_core_manifest(root, metadata, policy))
    if package_lister is not None:
        errors.extend(check_core_package_contents(policy, package_lister(policy["core-package"])))
    return errors


def crate_exists(name: str) -> bool:
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=30):
            return True
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise


def recheck_crate_name(policy: dict) -> list[str]:
    """Report whether the preferred registry name is still free on crates.io."""
    name = policy["core-package"]
    # crates.io treats `-` and `_` as the same name.
    variants = sorted({name, name.replace("-", "_")})
    taken = [variant for variant in variants if crate_exists(variant)]
    if taken:
        return [f"crates.io: {', '.join(taken)} already exist; use the documented fallback name"]
    print(f"crates.io: {' and '.join(variants)} are available")
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument("--recheck-crate-name", action="store_true", help="query crates.io for the preferred crate name")
    args = parser.parse_args()

    metadata = load_metadata(args.root)
    errors = validate(args.root, metadata, lambda package: cargo_package_list(args.root, package))
    derived, culprits = derived_msrv(metadata)
    if derived is not None:
        print(f"Derived MSRV {derived} from " + ", ".join(f"{name} {version}" for name, version, _ in culprits))
    if args.recheck_crate_name and not errors:
        errors.extend(recheck_crate_name(metadata["metadata"]["redact-secret"]))
    for error in errors:
        print(f"ERROR {error}")
    print(f"Rust workspace check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
