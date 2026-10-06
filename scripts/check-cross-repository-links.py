#!/usr/bin/env python3
"""Verify every `github.com/redact-secret/<repo>/blob/<ref>/<path>` link resolves (issue #690).

`doc-links:check` covers relative links, `json-path-citations:check` covers
repo-relative paths in JSON, and `decision-permalinks:check` covers ADR
permalinks in this repository only. Nothing else validated a link that points
into the sibling repository, which is how 134 of them sat broken unnoticed.

For every such link in the scanned files:

- a 40-hex `<ref>`: the commit exists and `<path>` exists at it;
- `main`: `<path>` exists on that repository's `main` today;
- a release tag (`v0.1.0-beta.2`): the path exists at that tag (release tags are
  created once by the release workflow and are not moved);
- any other `<ref>` (a branch): reported as an error, because a moving
  or deletable ref cannot be relied on -- use a pinned permalink for a
  historical citation and `main` for living documentation.

The local repository is resolved from the working tree (`HEAD` stands in for
`main`, so a pull request may link to a file it adds); the other one through
`gh api`, the way `check-benchmark-pins.py` does. It needs network access and
a token, so it runs in its own CI job, never in the offline `npm run ci`.
Placeholders (`{version}`, `<sha>`) and links to other owners are ignored.

Offline use (issue #1264): `--offline` resolves what local git can (every
link into this repository at a commit or tag the checkout holds, and `main` via
`HEAD`) and never calls `gh`. A link that needs the network is then listed as
UNVERIFIED and counted in the summary, never passed silently. Without
`--offline`, a link `gh` cannot answer for (no `gh`, no token, a timeout, a rate
limit) is also UNVERIFIED and the exit status is 2, so an unavailable remote
source is distinguishable from a broken link (exit 1). Historical permalinks
into *this* repository are verified offline, against full history and with
anchors and digests, by `check-historical-permalinks.py`.

    python3 -B scripts/check-cross-repository-links.py [ROOT] --local-repo OWNER/NAME
    python3 -B scripts/check-cross-repository-links.py --offline
    python3 -B scripts/check-cross-repository-links.py --scan-dir WIKI_CHECKOUT --local-repo OWNER/NAME
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable

OWNER = "redact-secret"
REPOS = ("redact-secret", "redact-secret-benchmarks")
DEFAULT_LOCAL_REPO = f"{OWNER}/redact-secret"

LINK = re.compile(r"https://github\.com/" + OWNER + r"/([A-Za-z0-9._-]+)/blob/([^/\s)>\]`\"'#?]+)/([^\s)>\]`\"'#?\\]+)")
SHA = re.compile(r"[0-9a-f]{40}")
RELEASE_TAG = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?")
PLACEHOLDER = re.compile(r"[{}<>*$]")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".wasm", ".node", ".woff", ".woff2", ".zip", ".gz"}

class Unverifiable(Exception):
    """A link's remote source cannot be reached here; it is neither valid nor broken."""


Link = tuple[str, str, str]  # (repo, ref, path)
Resolver = Callable[[str, str, str], bool]  # (repo, ref, path) -> exists


def extract_links(text: str) -> set[Link]:
    links: set[Link] = set()
    for repo, ref, path in LINK.findall(text):
        path = path.rstrip(".,;:")
        if repo not in REPOS or PLACEHOLDER.search(ref + path):
            continue
        links.add((repo, ref, path))
    return links


def collect(files: Iterable[Path]) -> dict[Link, list[Path]]:
    found: dict[Link, list[Path]] = {}
    for file in files:
        if file.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            text = file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for link in extract_links(text):
            found.setdefault(link, []).append(file)
    return found


# Test fixtures hold deliberately fake links; they are not documentation.
EXCLUDED_PREFIXES = ("scripts/tests/",)


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout.decode(
        "utf-8"
    )
    return [
        root / name
        for name in out.split("\0")
        if name and not name.startswith(EXCLUDED_PREFIXES) and (root / name).is_file()
    ]


def walk_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*") if p.is_file() and ".git" not in p.relative_to(directory).parts)


def _git_ok(root: Path, *args: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(root), *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        ).returncode
        == 0
    )


def gh_path_exists(repo_slug: str, ref: str, path: str) -> bool:
    """True when `path` exists in `repo_slug` at `ref`; False only on the API's 404."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo_slug}/contents/{path}?ref={ref}", "--jq", ".sha"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as error:
        raise Unverifiable("the `gh` CLI is not installed") from error
    except subprocess.TimeoutExpired as error:
        raise Unverifiable(f"gh api {repo_slug}@{ref}:{path} timed out") from error
    if result.returncode == 0:
        return True
    if "HTTP 404" in result.stderr or "HTTP 422" in result.stderr:
        return False
    raise Unverifiable(f"gh api {repo_slug}@{ref}:{path} failed: {result.stderr.strip()}")


def make_resolver(root: Path, local_repo: str, offline: bool = False) -> Resolver:
    local_name = local_repo.split("/", 1)[1]

    def remote(repo: str, ref: str, path: str) -> bool:
        if offline:
            raise Unverifiable(f"offline: {repo}@{ref}:{path} needs the GitHub API")
        return gh_path_exists(f"{OWNER}/{repo}", ref, path)

    def resolve(repo: str, ref: str, path: str) -> bool:
        if repo == local_name:
            if RELEASE_TAG.fullmatch(ref):
                if _git_ok(root, "cat-file", "-e", f"refs/tags/{ref}^{{commit}}"):
                    return _git_ok(root, "cat-file", "-e", f"refs/tags/{ref}:{path}")
                return remote(repo, ref, path)
            if SHA.fullmatch(ref):
                if _git_ok(root, "cat-file", "-e", f"{ref}:{path}"):
                    return True
                if _git_ok(root, "cat-file", "-e", f"{ref}^{{commit}}"):
                    return False
                return remote(repo, ref, path)
            return _git_ok(root, "cat-file", "-e", f"HEAD:{path}")
        return remote(repo, ref, path)

    return resolve


def validate(
    links: dict[Link, list[Path]],
    resolve: Resolver,
    base: Path | None = None,
    unverified: list[str] | None = None,
) -> list[str]:
    """Return one error per broken link and citing file.

    A link whose remote source is unreachable raises `Unverifiable` in the
    resolver; it is appended to `unverified` (one line per link) when the caller
    passes a list, and propagates otherwise, so it is never counted as valid.
    """
    errors: list[str] = []
    for (repo, ref, path), files in sorted(links.items()):
        try:
            if SHA.fullmatch(ref) or RELEASE_TAG.fullmatch(ref):
                problem = None if resolve(repo, ref, path) else f"path {path} does not exist at {ref} in {repo}"
            elif ref == "main":
                problem = None if resolve(repo, ref, path) else f"path {path} does not exist on {repo} main"
            else:
                problem = (
                    f"{repo} link uses ref '{ref}'; use a 40-hex permalink for a past state "
                    "or `main` for living documentation"
                )
        except Unverifiable as error:
            if unverified is None:
                raise
            for file in sorted(set(files)):
                shown = file.relative_to(base) if base and file.is_relative_to(base) else file
                unverified.append(f"{shown}: {repo}/{ref}/{path}: {error}")
            continue
        if problem:
            for file in sorted(set(files)):
                shown = file.relative_to(base) if base and file.is_relative_to(base) else file
                errors.append(f"{shown}: {problem}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument("--local-repo", default=DEFAULT_LOCAL_REPO, help="OWNER/NAME of the repository at ROOT")
    parser.add_argument(
        "--scan-dir",
        type=Path,
        help="scan every file under this directory (e.g. a wiki checkout) instead of git-tracked files",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="never call `gh`: resolve with local git only and list every link that needs the network as UNVERIFIED",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.scan_dir:
        base = args.scan_dir.resolve()
        files = walk_files(base)
    else:
        base = root
        files = tracked_files(root)
    links = collect(files)
    unverified: list[str] = []
    errors = validate(links, make_resolver(root, args.local_repo, args.offline), base, unverified)
    for error in errors:
        print(f"ERROR {error}")
    for line in unverified:
        print(f"UNVERIFIED {line}")
    mode = "offline" if args.offline else "online"
    print(
        f"Cross-repository link check complete ({mode}): {len(links)} distinct link(s), "
        f"{len(errors)} error(s), {len(unverified)} unverified"
    )
    if errors:
        return 1
    if unverified and not args.offline:
        print("UNAVAILABLE a remote source could not be reached, so those links were not checked (exit 2)")
        return 2
    if unverified:
        print("OFFLINE the unverified links above were skipped by request; run without --offline to check them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
