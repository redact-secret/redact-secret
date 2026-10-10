#!/usr/bin/env python3
"""Throwaway, never-published product version for the release rehearsal.

`Package Release Rehearsal` qualifies whatever version its branch carries, and
on `main` that is always a version already on every registry. Release-path
steps that behave differently for a version no registry has yet (issue #632:
beta.6's #607 `cargo package` resolution and #608 digest scope) therefore never
ran until an RC was cut. This script lets the rehearsal check out the branch,
move the whole lockstep version set to a version nothing has published, and
qualify that -- in its own checkout, never committed or pushed.

    rehearsal-version.py derive --run-id 9876543210
    rehearsal-version.py apply --version 0.1.0-beta.9876543210
    rehearsal-version.py check-unpublished --version 0.1.0-beta.9876543210

The throwaway version keeps the workspace's `X.Y.Z-beta.N` grammar, with `N`
the GitHub run id, because the Python wheel qualification and the quickstart
pin check (`scripts/qualify-python-wheel.py`, `scripts/clean-install-doc.mjs`)
only understand that shape and PEP 440 has no spelling for a `-rehearsal`
segment. Run ids are far above any published beta number, and
`check-unpublished` proves the absence on npm, crates.io and PyPI rather than
assuming it.

`apply` rewrites exactly the set `docs/rust-workspace.md#version-lockstep`
names -- the workspace `Cargo.toml` (version and the exact core requirement),
`Cargo.lock`'s workspace members, every lockstep JSON manifest with its exact
`@redact-secret/*` pins, both npm lockfiles, the TypeScript `VERSION` constant
-- plus the version pins in `docs/quickstart.md` and `docs/getting-started.md`,
so `--locked` builds and the `clean-install` job see one consistent version.
It refuses to run outside a CI checkout unless `--force-local` is given, so a
developer's working tree is not bumped by accident.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]

# The version grammar the rest of the release path understands.
VERSION = re.compile(r"^(?P<release>\d+\.\d+\.\d+)-beta\.(?P<number>\d+)$")

JSON_MANIFESTS = (
    "package.json",
    "bindings/node/package.json",
    "packages/javascript/package.json",
    "bindings/wasm/npm/package.json",
)
NATIVE_PLATFORM_DIR = Path("bindings/node/npm")
LOCKFILES = ("package-lock.json", "bindings/node/package-lock.json")
TYPESCRIPT_VERSION = "packages/javascript/src/version.ts"
DOC_PINS = ("docs/quickstart.md", "docs/getting-started.md")
CARGO_LOCK = "Cargo.lock"
CARGO_TOML = "Cargo.toml"

NPM_REGISTRY = "https://registry.npmjs.org/"
CRATES_REGISTRY = "https://crates.io/api/v1/crates/"
PYPI_REGISTRY = "https://pypi.org/pypi/"
CRATE_NAMES = ("redact-secret", "redact-secret-cli")
PYPI_NAME = "redact-secret"


class RehearsalError(Exception):
    pass


def workspace_version(root: Path) -> str:
    with (root / CARGO_TOML).open("rb") as handle:
        return tomllib.load(handle)["workspace"]["package"]["version"]


def pep440(version: str) -> str:
    match = VERSION.match(version)
    if not match:
        raise RehearsalError(f"unsupported product version {version!r}: expected X.Y.Z-beta.N")
    return f"{match['release']}b{int(match['number'])}"


def derive(run_id: str, current: str) -> str:
    """`<X.Y.Z>-beta.<run id>` for the branch's current `X.Y.Z-beta.N`."""
    match = VERSION.match(current)
    if not match:
        raise RehearsalError(f"the branch version {current!r} is not X.Y.Z-beta.N")
    if not run_id.isdigit() or int(run_id) <= int(match["number"]):
        raise RehearsalError(f"run id {run_id!r} must be a number above the current beta number {match['number']}")
    return f"{match['release']}-beta.{int(run_id)}"


def manifests(root: Path) -> list[str]:
    directory = root / NATIVE_PLATFORM_DIR
    native = sorted(
        (NATIVE_PLATFORM_DIR / child.name / "package.json").as_posix()
        for child in directory.iterdir()
        if child.is_dir() and (child / "package.json").is_file()
    )
    return list(JSON_MANIFESTS) + native


def _replace_exactly(path: Path, old: str, new: str, *, minimum: int) -> int:
    """Replace every quoted `old` with `new`; fail if fewer than `minimum` hit."""
    text = path.read_text(encoding="utf-8")
    count = text.count(f'"{old}"')
    if count < minimum:
        raise RehearsalError(f"{path.name}: expected at least {minimum} occurrence(s) of {old!r}, found {count}")
    path.write_text(text.replace(f'"{old}"', f'"{new}"'), encoding="utf-8")
    return count


def _bump_cargo_lock(path: Path, old: str, new: str) -> int:
    """Move workspace members (path packages: no `source`) from `old` to `new`."""
    lines = path.read_text(encoding="utf-8").split("\n")
    changed = 0
    index = 0
    while index < len(lines):
        if lines[index] == "[[package]]":
            end = index + 1
            while end < len(lines) and lines[end] != "[[package]]":
                end += 1
            block = lines[index:end]
            has_source = any(line.startswith("source = ") for line in block)
            for offset, line in enumerate(block):
                if line == f'version = "{old}"' and not has_source:
                    lines[index + offset] = f'version = "{new}"'
                    changed += 1
            index = end
        else:
            index += 1
    if changed == 0:
        raise RehearsalError("Cargo.lock: no workspace member carries the current version")
    path.write_text("\n".join(lines), encoding="utf-8")
    return changed


def apply(root: Path, new: str) -> dict[str, int]:
    """Move every lockstep file under `root` to `new`; returns edits per file."""
    old = workspace_version(root)
    pep440(new)
    if new == old:
        raise RehearsalError(f"{new} is already the branch version")
    edits: dict[str, int] = {}
    edits[CARGO_TOML] = _replace_exactly(root / CARGO_TOML, old, new, minimum=1)
    # The exact core requirement in `[workspace.dependencies]` is `=<version>`.
    cargo = root / CARGO_TOML
    text = cargo.read_text(encoding="utf-8")
    if f'version = "={old}"' not in text:
        raise RehearsalError(f"{CARGO_TOML}: no exact `=` requirement on {old}")
    cargo.write_text(text.replace(f'"={old}"', f'"={new}"'), encoding="utf-8")
    edits[CARGO_LOCK] = _bump_cargo_lock(root / CARGO_LOCK, old, new)
    for relative in manifests(root):
        edits[relative] = _replace_exactly(root / relative, old, new, minimum=1)
    for relative in LOCKFILES:
        edits[relative] = _replace_exactly(root / relative, old, new, minimum=1)
    edits[TYPESCRIPT_VERSION] = _replace_exactly(root / TYPESCRIPT_VERSION, old, new, minimum=1)
    old_py, new_py = pep440(old), pep440(new)
    for relative in DOC_PINS:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        edits[relative] = text.count(old) + text.count(old_py)
        path.write_text(text.replace(old, new).replace(old_py, new_py), encoding="utf-8")
    return edits


def provenance(root: Path, source: str, version: str, run_id: str) -> dict:
    """Prove the checkout differs from source only by the exact version transform."""

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=root)

    if not re.fullmatch(r"[0-9a-f]{40}", source) or git("rev-parse", "HEAD").decode().strip() != source:
        raise RehearsalError("rehearsal source must be the exact checked-out commit")
    tracked = git("ls-tree", "-r", "--name-only", source).decode().splitlines()
    if any(entry[0] != "H" for entry in git("ls-files", "-v", "-z").decode().split("\0") if entry):
        raise RehearsalError("hidden index entries cannot be bound to the rehearsal source")
    native = [p for p in tracked if re.fullmatch(r"bindings/node/npm/[^/]+/package.json", p)]
    paths = sorted({CARGO_TOML, CARGO_LOCK, TYPESCRIPT_VERSION, *LOCKFILES, *DOC_PINS, *JSON_MANIFESTS, *native})
    with tempfile.TemporaryDirectory(prefix="rehearsal-provenance-") as temporary:
        expected = Path(temporary)
        originals = {}
        for name in paths:
            originals[name] = git("show", f"{source}:{name}")
            path = expected / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(originals[name])
        original_version = workspace_version(expected)
        if version != derive(run_id, original_version):
            raise RehearsalError("rehearsal version must be derived from this run and committed version")
        apply(expected, version)
        transformed = {name: (expected / name).read_bytes() for name in paths}
    changed = {name for name in paths if originals[name] != transformed[name]}
    disk_changes = set(git("diff", "HEAD", "--name-only").decode().splitlines())
    staged_changes = set(git("diff", "--cached", "--name-only").decode().splitlines())
    if disk_changes != changed or not staged_changes.issubset(changed):
        raise RehearsalError("checkout changes differ from the exact rehearsal version transform")
    for name in paths:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != transformed[name]:
            raise RehearsalError(f"{name}: bytes differ from the rehearsal version transform")
        if name in staged_changes and git("show", f":{name}") != transformed[name]:
            raise RehearsalError(f"{name}: staged bytes differ from the rehearsal version transform")
        mode = git("ls-tree", source, "--", name).decode().split()[0]
        index_mode = git("ls-files", "--stage", "--", name).decode().split()[0]
        if index_mode != mode or bool(path.stat().st_mode & 0o111) != (mode == "100755"):
            raise RehearsalError(f"{name}: file mode differs from committed source")
    # Reject extra engine, wrapper and build-tool source; generated outputs stay ignored.
    untracked = git(
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        "crates",
        "bindings",
        "packages",
        "scripts",
        CARGO_TOML,
        CARGO_LOCK,
    )
    if untracked.strip():
        raise RehearsalError("untracked custom-engine source cannot be bound to the rehearsal")
    files = {
        name: {
            "before": hashlib.sha256(originals[name]).hexdigest(),
            "after": hashlib.sha256(transformed[name]).hexdigest(),
        }
        for name in sorted(changed)
    }
    return {
        "schema": "rehearsal-source/v1",
        "sourceCommit": source,
        "sourceTree": git("rev-parse", f"{source}^{{tree}}").decode().strip(),
        "sourceVersion": original_version,
        "rehearsalVersion": version,
        "runId": run_id,
        "files": files,
    }


def _status(url: str) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "redact-secret-release-rehearsal"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def registry_probes(root: Path, version: str) -> list[tuple[str, str]]:
    """`(label, url)` for every package/version pair the release would publish."""
    probes: list[tuple[str, str]] = []
    for relative in manifests(root):
        name = json.loads((root / relative).read_text(encoding="utf-8"))["name"]
        if not name.startswith("@"):
            continue
        scope, _, package = name.partition("/")
        probes.append((f"npm {name}@{version}", f"{NPM_REGISTRY}{scope}%2f{package}/{version}"))
    for crate in CRATE_NAMES:
        probes.append((f"crates.io {crate}@{version}", f"{CRATES_REGISTRY}{crate}/{version}"))
    probes.append((f"PyPI {PYPI_NAME}=={pep440(version)}", f"{PYPI_REGISTRY}{PYPI_NAME}/{pep440(version)}/json"))
    return probes


def check_unpublished(root: Path, version: str, status=_status) -> list[str]:
    """Errors for every registry that carries `version` or answers inconclusively.

    Only a 404 proves absence; any other answer fails closed, because a
    rehearsal that cannot tell is not known to be publication-free.
    """
    errors = []
    for label, url in registry_probes(root, version):
        code = status(url)
        if code != 404:
            errors.append(f"{label}: registry answered {code}, expected 404 (not published)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    derive_cmd = sub.add_parser("derive", help="print the throwaway version for a run id")
    derive_cmd.add_argument("--run-id", required=True)
    apply_cmd = sub.add_parser("apply", help="move the lockstep version set in this checkout")
    apply_cmd.add_argument("--version", required=True)
    apply_cmd.add_argument("--force-local", action="store_true")
    check_cmd = sub.add_parser("check-unpublished", help="prove no registry carries the version")
    check_cmd.add_argument("--version", required=True)
    provenance_cmd = sub.add_parser("provenance", help="verify and record the exact version-only source transform")
    provenance_cmd.add_argument("--source", required=True)
    provenance_cmd.add_argument("--version", required=True)
    provenance_cmd.add_argument("--run-id", required=True)
    args = parser.parse_args()

    try:
        if args.command == "provenance":
            print(json.dumps(provenance(ROOT, args.source, args.version, args.run_id), sort_keys=True))
            return 0
        if args.command == "derive":
            print(derive(args.run_id, workspace_version(ROOT)))
            return 0
        if args.command == "apply":
            if os.environ.get("GITHUB_ACTIONS") != "true" and not args.force_local:
                raise RehearsalError("refusing to rewrite a local checkout without --force-local")
            edits = apply(ROOT, args.version)
            print(f"Moved {len(edits)} file(s) to {args.version} (not committed):")
            for relative, count in sorted(edits.items()):
                print(f"  {relative}: {count}")
            return 0
        errors = check_unpublished(ROOT, args.version)
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"{args.version}: {len(registry_probes(ROOT, args.version))} registry probe(s), {len(errors)} error(s)")
        return 1 if errors else 0
    except RehearsalError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
