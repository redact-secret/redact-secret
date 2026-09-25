#!/usr/bin/env python3
"""Consume unreleased `redact-secret-adapters` packages as publish-shaped
artifacts, built by `npm pack` from one immutable adapters commit
(redact-secret/redact-secret-adapters#12).

`adapters/pin-source.json` is the product-owned pin, the same shape of
record as `benchmarks/pin-source.json`: the exact 40-hex adapters commit,
the packages built from it, each package's content digest, and the
directories in this repository that consume them. Like
`sast/opengrep.lock.json`, the artifacts themselves are never committed:
they are built into the gitignored `.cache/adapters/<commit>/` and verified
against the pinned digest before anything installs them, failing closed on a
mismatch.

    python3 scripts/adapter-pins.py check              # offline; in `npm run ci`
    python3 scripts/adapter-pins.py install            # network on a cache miss
    python3 scripts/adapter-pins.py verify-installed   # offline; before a consumer's tests
    python3 scripts/adapter-pins.py check-ancestry --adapters-branch develop   # live; its own CI job
    python3 scripts/adapter-pins.py sync --ref <40-sha>   # re-pin

`check` validates the pin record and that every consumer's `package.json`
names exactly the pinned tarballs as `file:` dependencies, and no other
`file:` artifact, so a re-pin that forgets a consumer, a pinned package a
consumer swapped for another source, or an unpinned local tarball fails
`npm run ci`.

`install` fetches the adapters repository at the pinned commit (and nothing
else: `git fetch --depth 1 <commit>`, then `HEAD` is checked against the
pin), runs `npm ci`, builds and packs each pinned workspace in the listed
order (a dependency before its dependents), and verifies each tarball's
content digest. A cached tarball is re-verified, never trusted. It then
installs every consumer from those tarballs, offline, without a lockfile,
and without peer auto-install: a consumer's tests inject their core, so no
registry package enters its tree.

`verify-installed` recomputes each consumer's installed packages' digests.
It is what a consumer's test command runs first, so a stale or missing
install fails with the command to fix it instead of an import error.

`check-ancestry` requires the pinned commit to be on the adapters branch
(`develop` for development; a release would use `main`) through the GitHub
compare API. A commit that is only on an unmerged branch is rejected.

`sync --ref` builds at the new commit, records its digests, and rewrites
every consumer's `file:` specifiers.

The content digest is SHA-256 over the sorted list of `path NUL
sha256(bytes) LF` lines of the tarball's regular files, so it identifies what
npm installs, independent of gzip output, which differs across Node.js
versions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = Path("adapters") / "pin-source.json"
CACHE_DIR = Path(".cache") / "adapters"
ADAPTERS_REPO = "redact-secret/redact-secret-adapters"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME_RE = re.compile(r"^@redact-secret/[a-z0-9-]+$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


class PinError(Exception):
    """A pin, artifact, or consumer disagrees with the record. Fail closed."""


def load_pin(root: Path = ROOT) -> dict:
    return json.loads((root / PIN_PATH).read_text(encoding="utf-8"))


def validate_pin(pin: dict) -> list[str]:
    """Every problem with the pin record itself, as input-free messages."""
    problems: list[str] = []
    if pin.get("schemaVersion") != 1:
        problems.append("schemaVersion must be 1")
    if pin.get("repository") != ADAPTERS_REPO:
        problems.append(f"repository must be {ADAPTERS_REPO}")
    if not isinstance(pin.get("commit"), str) or not COMMIT_RE.match(pin["commit"]):
        problems.append("commit must be a 40-hex commit (a branch or tag is never a pin)")
    packages = pin.get("packages")
    if not isinstance(packages, list) or not packages:
        problems.append("packages must be a non-empty list")
        packages = []
    seen: set[str] = set()
    for index, package in enumerate(packages):
        where = f"packages[{index}]"
        if not isinstance(package, dict):
            problems.append(f"{where} must be an object")
            continue
        name = package.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            problems.append(f"{where}.name must be an @redact-secret/ package name")
        elif name in seen:
            problems.append(f"{where}.name {name} is pinned twice")
        else:
            seen.add(name)
        if not isinstance(package.get("version"), str) or not VERSION_RE.match(package["version"]):
            problems.append(f"{where}.version must be a SemVer version")
        if not isinstance(package.get("contentDigest"), str) or not DIGEST_RE.match(package["contentDigest"]):
            problems.append(f"{where}.contentDigest must be sha256:<64 hex>")
    consumers = pin.get("consumers")
    if not isinstance(consumers, list) or not consumers:
        problems.append("consumers must be a non-empty list of directories")
    elif not all(isinstance(c, str) and c and not c.startswith("/") and ".." not in c for c in consumers):
        problems.append("consumers must be repository-relative directories")
    return problems


def tarball_name(name: str, version: str) -> str:
    """The file name `npm pack` gives `name@version`."""
    return f"{name.lstrip('@').replace('/', '-')}-{version}.tgz"


def cache_dir(root: Path, commit: str) -> Path:
    return root / CACHE_DIR / commit


def expected_specifier(root: Path, consumer: str, commit: str, package: dict) -> str:
    target = cache_dir(root, commit) / tarball_name(package["name"], package["version"])
    relative = Path(*([".."] * len(Path(consumer).parts))) / target.relative_to(root)
    return f"file:{relative.as_posix()}"


def check_consumers(pin: dict, root: Path = ROOT) -> list[str]:
    """Every consumer's `package.json` names exactly the pinned tarballs."""
    problems: list[str] = []
    for consumer in pin["consumers"]:
        manifest_path = root / consumer / "package.json"
        if not manifest_path.is_file():
            problems.append(f"{consumer}: no package.json")
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        declared = {
            **manifest.get("devDependencies", {}),
            **manifest.get("dependencies", {}),
        }
        for package in pin["packages"]:
            want = expected_specifier(root, consumer, pin["commit"], package)
            have = declared.get(package["name"])
            if have != want:
                problems.append(f"{consumer}: {package['name']} must be {want}, is {have}")
        pinned = {p["name"] for p in pin["packages"]}
        for name, spec in declared.items():
            # A local artifact the pin does not cover has no provenance. A
            # published registry version needs none from here.
            if name not in pinned and isinstance(spec, str) and spec.startswith("file:"):
                problems.append(f"{consumer}: {name} is a local file: artifact that {PIN_PATH} does not pin")
    return problems


def digest_entries(entries: list[tuple[str, bytes]]) -> str:
    lines = sorted(f"{path}\0{hashlib.sha256(data).hexdigest()}\n" for path, data in entries)
    return "sha256:" + hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def tarball_digest(path: Path) -> str:
    entries: list[tuple[str, bytes]] = []
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            handle = archive.extractfile(member)
            if handle is None:
                raise PinError(f"{path.name}: unreadable entry")
            entries.append((member.name, handle.read()))
    return digest_entries(entries)


def installed_digest(package_dir: Path) -> str:
    """The same digest over an installed package directory (tarball paths are `package/<file>`)."""
    entries = [
        ("package/" + file.relative_to(package_dir).as_posix(), file.read_bytes())
        for file in sorted(package_dir.rglob("*"))
        if file.is_file() and "node_modules" not in file.relative_to(package_dir).parts
    ]
    return digest_entries(entries)


def fetch_source(commit: str, source: Path) -> None:
    """A checkout of exactly `commit`, verified, in `source`."""
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "fetch", "-q", "--depth", "1", f"https://github.com/{ADAPTERS_REPO}.git", commit],
        check=True,
        timeout=300,
    )
    subprocess.run(["git", "-C", str(source), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != commit:
        raise PinError(f"fetched HEAD {head} is not the pinned commit {commit}")


def build_tarballs(commit: str, names: list[str], destination: Path) -> dict[str, Path]:
    """Builds and packs each named workspace at `commit`, in order, into `destination`."""
    source = destination / "source"
    fetch_source(commit, source)
    subprocess.run(
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=source, check=True, timeout=600
    )
    packed: dict[str, Path] = {}
    for name in names:
        subprocess.run(["npm", "run", "build", "--workspace", name], cwd=source, check=True, timeout=300)
        out = subprocess.run(
            ["npm", "pack", "--json", "--workspace", name, "--pack-destination", str(destination)],
            cwd=source,
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        ).stdout
        [record] = json.loads(out)
        packed[name] = destination / record["filename"]
    shutil.rmtree(source)
    return packed


def verified_tarballs(pin: dict, root: Path = ROOT) -> dict[str, Path]:
    """The pinned tarballs, built on a cache miss, each verified against its digest."""
    destination = cache_dir(root, pin["commit"])
    destination.mkdir(parents=True, exist_ok=True)
    paths = {p["name"]: destination / tarball_name(p["name"], p["version"]) for p in pin["packages"]}
    if not all(path.is_file() for path in paths.values()):
        print(f"adapter-pins: building {ADAPTERS_REPO}@{pin['commit']} (cache miss)", file=sys.stderr)
        built = build_tarballs(pin["commit"], [p["name"] for p in pin["packages"]], destination)
        for name, path in built.items():
            if path != paths[name]:
                raise PinError(f"{name}: npm pack produced {path.name}, expected {paths[name].name}")
    for package in pin["packages"]:
        path = paths[package["name"]]
        actual = tarball_digest(path)
        if actual != package["contentDigest"]:
            path.unlink()
            raise PinError(
                f"{package['name']}: built content digest {actual} is not the pinned "
                f"{package['contentDigest']}; the cached tarball was removed"
            )
    return paths


def install_consumers(pin: dict, root: Path = ROOT) -> None:
    for consumer in pin["consumers"]:
        directory = root / consumer
        shutil.rmtree(directory / "node_modules", ignore_errors=True)
        subprocess.run(
            [
                "npm",
                "install",
                "--offline",
                "--no-package-lock",
                "--legacy-peer-deps",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            cwd=directory,
            check=True,
            timeout=300,
        )


def verify_installed(pin: dict, root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    for consumer in pin["consumers"]:
        for package in pin["packages"]:
            package_dir = root / consumer / "node_modules" / package["name"]
            if not (package_dir / "package.json").is_file():
                problems.append(f"{consumer}: {package['name']} is not installed")
            elif installed_digest(package_dir) != package["contentDigest"]:
                problems.append(f"{consumer}: installed {package['name']} is not the pinned build")
    return problems


def gh_compare_is_ancestor(base: str, head: str) -> bool:
    """True when `base` is `head` or one of its ancestors, per the GitHub compare API."""
    result = subprocess.run(
        ["gh", "api", f"repos/{ADAPTERS_REPO}/compare/{base}...{head}", "--jq", ".status"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip() in ("identical", "ahead")


def rewrite_consumers(pin: dict, root: Path = ROOT) -> None:
    for consumer in pin["consumers"]:
        manifest_path = root / consumer / "package.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        dependencies = manifest.setdefault("dependencies", {})
        for package in pin["packages"]:
            dependencies[package["name"]] = expected_specifier(root, consumer, pin["commit"], package)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def sync(ref: str, root: Path = ROOT) -> dict:
    if not COMMIT_RE.match(ref):
        raise PinError("--ref must be a 40-hex commit")
    pin = load_pin(root)
    destination = cache_dir(root, ref)
    destination.mkdir(parents=True, exist_ok=True)
    built = build_tarballs(ref, [p["name"] for p in pin["packages"]], destination)
    packages = []
    for package in pin["packages"]:
        path = built[package["name"]]
        version = path.name.removeprefix(package["name"].lstrip("@").replace("/", "-") + "-").removesuffix(".tgz")
        packages.append({"name": package["name"], "version": version, "contentDigest": tarball_digest(path)})
    pin = {**pin, "commit": ref, "packages": packages}
    (root / PIN_PATH).write_text(json.dumps(pin, indent=2) + "\n", encoding="utf-8")
    rewrite_consumers(pin, root)
    return pin


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="offline: the pin record and every consumer agree")
    sub.add_parser("install", help="build (on a cache miss), verify, and install every consumer")
    sub.add_parser("verify-installed", help="offline: every consumer's installed packages are the pinned build")
    ancestry = sub.add_parser("check-ancestry", help="live: the pinned commit is on the adapters branch")
    ancestry.add_argument("--adapters-branch", default="develop")
    sync_parser = sub.add_parser("sync", help="re-pin to a new adapters commit")
    sync_parser.add_argument("--ref", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "sync":
            pin = sync(args.ref)
            print(f"adapter-pins: pinned {ADAPTERS_REPO}@{pin['commit']}; run `npm run adapter-pins:install`")
            return 0
        pin = load_pin()
        problems = validate_pin(pin)
        if not problems and args.command in ("check", "install"):
            problems = check_consumers(pin)
        if problems:
            for problem in problems:
                print(f"adapter-pins: {problem}", file=sys.stderr)
            return 1
        if args.command == "check":
            print(f"adapter-pins: {len(pin['packages'])} packages at {pin['commit']}, {len(pin['consumers'])} consumer(s) agree")
        elif args.command == "install":
            verified_tarballs(pin)
            install_consumers(pin)
            problems = verify_installed(pin)
            if problems:
                raise PinError("; ".join(problems))
            print(f"adapter-pins: installed {ADAPTERS_REPO}@{pin['commit']} into {', '.join(pin['consumers'])}")
        elif args.command == "verify-installed":
            problems = verify_installed(pin)
            if problems:
                for problem in problems:
                    print(f"adapter-pins: {problem}", file=sys.stderr)
                print("adapter-pins: run `npm run adapter-pins:install` (builds the pinned adapters once)", file=sys.stderr)
                return 1
        elif args.command == "check-ancestry":
            if not gh_compare_is_ancestor(pin["commit"], args.adapters_branch):
                print(
                    f"adapter-pins: {pin['commit']} is not an ancestor of {ADAPTERS_REPO}@{args.adapters_branch}",
                    file=sys.stderr,
                )
                return 1
            print(f"adapter-pins: {pin['commit']} is on {ADAPTERS_REPO}@{args.adapters_branch}")
    except (PinError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"adapter-pins: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
