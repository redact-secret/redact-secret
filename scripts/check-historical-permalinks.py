#!/usr/bin/env python3
"""Verify every historical permalink into this repository against local history (#1264).

`check-decision-permalinks.py` proves that an ADR permalink names a commit that
exists and a path that exists at it. That is not enough to let a document body
leave the tree: the retirement rule of
`decision-retire-historical-audit-bodies-before-release-qualification` needs a
permalink whose commit is an *ancestor of main*, whose anchor still points at a
heading, and whose integrity records still verify. This script checks all of
that, offline, against the full local history. It never opens a network
connection; links into other repositories belong to
`check-cross-repository-links.py`, which does.

Default mode scans every tracked text file for
`https://github.com/redact-secret/redact-secret/{blob,tree}/<40-hex>/<path>[#fragment]`
and reports, per citing file:

- the commit is not in the local history (a shallow clone cannot verify it: the
  message says so rather than passing silently);
- the commit is not an ancestor of the main ref (`origin/main`, else `main`);
- the path does not exist at the commit, or is a directory in a `blob` link or
  a file in a `tree` link;
- the `#fragment` names no heading or explicit anchor of a Markdown blob, or a
  line past the end of the blob (`#L10`, `#L10-L20`);
- the cited blob is a `SHA256SUMS*` bundle, or a tracked JSON record
  (`{"path": ..., "sha256": ...}`) whose digest no longer matches the blob at a
  permalink that cites the same path.

Retirement mode, run before a deletion commit, proves the pin itself:

    python3 -B scripts/check-historical-permalinks.py --retirement-pin <sha> --retire docs/audits/

The pin must be an ancestor of the main ref, every tracked file under a
`--retire` prefix must exist at the pin byte-identical (same blob id), every
`SHA256SUMS*` bundle under the prefixes must verify at the pin, and every
tracked JSON digest record that names a path under the prefixes must carry the
digest of that path's blob at the pin.

Exit status: 0 clean, 1 an error was found, 2 the check could not run (no main
ref, or a link names a commit the local history lacks). Pass `--no-ancestry` to
run without a main ref; the summary then says ancestry was not checked.

    python3 -B scripts/check-historical-permalinks.py [ROOT] [--main-ref REF]
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote

OWNER_REPO = "redact-secret/redact-secret"
PERMALINK = re.compile(
    r"https://github\.com/" + re.escape(OWNER_REPO) + r"/(blob|tree)/([0-9a-f]{40})/"
    r"([^\s)>\]`\"'#?\\]+)(?:\?[^\s)>\]`\"'#\\]*)?(?:#([^\s)>\]`\"'\\]+))?"
)
LOOSE_REF = re.compile(r"https://github\.com/" + re.escape(OWNER_REPO) + r"/(?:blob|tree)/([0-9a-fA-F]{7,39})/")
LINE_FRAGMENT = re.compile(r"L(\d+)(?:C\d+)?(?:-L(\d+)(?:C\d+)?)?")
HTML_ID = re.compile(r"""<a\s[^>]*?\b(?:name|id)=["']([^"']+)["']""", re.IGNORECASE)
SHA64 = re.compile(r"[0-9a-f]{64}")
SUMS_LINE = re.compile(r"^([0-9a-f]{64})\s+\*?(.+?)\s*$")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".wasm", ".node", ".woff", ".woff2", ".zip", ".gz"}
EXCLUDED_PREFIXES = ("scripts/tests/",)
MAIN_REFS = ("origin/main", "main")

EXIT_OK, EXIT_ERRORS, EXIT_UNAVAILABLE = 0, 1, 2


class Unavailable(Exception):
    """The check cannot run here; distinct from a defect in the checked files."""


def _load_doc_links():
    spec = importlib.util.spec_from_file_location("check_doc_links", Path(__file__).with_name("check-doc-links.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_doc_links", module)
    spec.loader.exec_module(module)
    return module


class Repo:
    """Read-only, cached view of one git repository's full local history."""

    def __init__(self, root: Path, main_ref: str | None = None, check_ancestry: bool = True):
        self.root = root.resolve()
        self.check_ancestry = check_ancestry
        self.main_ref = self._pick_main_ref(main_ref) if check_ancestry else None
        self._commit: dict[str, bool] = {}
        self._ancestor: dict[str, bool] = {}
        self._blobs: dict[tuple[str, str], bytes | None] = {}
        self._types: dict[tuple[str, str], str | None] = {}
        self._doc_links = _load_doc_links()

    def _git(self, *args: str, binary: bool = False) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, check=False, text=not binary)

    def _pick_main_ref(self, requested: str | None) -> str:
        for ref in (requested,) if requested else MAIN_REFS:
            if self._git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode == 0:
                return ref
        wanted = requested or " or ".join(MAIN_REFS)
        raise Unavailable(
            f"no main ref ({wanted}) in this checkout, so permalink ancestry cannot be verified: "
            "fetch it (`git fetch origin main`) or pass --main-ref; --no-ancestry skips the check explicitly"
        )

    def shallow_hint(self) -> str:
        out = self._git("rev-parse", "--is-shallow-repository").stdout.strip()
        return " (this is a shallow clone: fetch the full history)" if out == "true" else ""

    def commit_exists(self, sha: str) -> bool:
        if sha not in self._commit:
            self._commit[sha] = self._git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0
        return self._commit[sha]

    def is_ancestor(self, sha: str) -> bool:
        if sha not in self._ancestor:
            result = self._git("merge-base", "--is-ancestor", sha, self.main_ref or "HEAD")
            self._ancestor[sha] = result.returncode == 0
        return self._ancestor[sha]

    def object_type(self, sha: str, path: str) -> str | None:
        key = (sha, path)
        if key not in self._types:
            result = self._git("cat-file", "-t", f"{sha}:{path}")
            self._types[key] = result.stdout.strip() if result.returncode == 0 else None
        return self._types[key]

    def blob(self, sha: str, path: str) -> bytes | None:
        key = (sha, path)
        if key not in self._blobs:
            result = self._git("cat-file", "blob", f"{sha}:{path}", binary=True)
            self._blobs[key] = result.stdout if result.returncode == 0 else None
        return self._blobs[key]

    def blob_id(self, ref: str, path: str) -> str | None:
        result = self._git("rev-parse", "--verify", "--quiet", f"{ref}:{path}")
        return result.stdout.strip() if result.returncode == 0 else None

    def tracked_files(self) -> list[str]:
        out = self._git("ls-files", "-z", binary=True).stdout.decode("utf-8")
        return [
            name
            for name in out.split("\0")
            if name
            and not name.startswith(EXCLUDED_PREFIXES)
            and Path(name).suffix.lower() not in SKIP_SUFFIXES
            and (self.root / name).is_file()
        ]

    def anchors(self, sha: str, path: str) -> set[str] | None:
        """Heading slugs and explicit anchors of a Markdown blob; None for other files."""
        if not path.lower().endswith(".md"):
            return None
        data = self.blob(sha, path)
        if data is None:
            return None
        text = data.decode("utf-8", errors="replace")
        slugs = set(self._doc_links.heading_slugs(self._doc_links.strip_fences(text)))
        slugs.update(HTML_ID.findall(text))
        return slugs

    def line_count(self, sha: str, path: str) -> int:
        data = self.blob(sha, path) or b""
        return len(data.splitlines())


Link = tuple[str, str, str, str]  # (kind, sha, path, fragment)


def extract_links(text: str) -> set[Link]:
    found: set[Link] = set()
    for kind, sha, path, fragment in PERMALINK.findall(text):
        found.add((kind, sha, path.rstrip(".,;:"), fragment.rstrip(".,;:")))
    return found


def collect(repo: Repo, files: Iterable[str]) -> dict[Link, list[str]]:
    found: dict[Link, list[str]] = {}
    for name in files:
        try:
            text = (repo.root / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for link in extract_links(text):
            found.setdefault(link, []).append(name)
    return found


def check_fragment(repo: Repo, sha: str, path: str, fragment: str) -> str | None:
    fragment = unquote(fragment)
    line = LINE_FRAGMENT.fullmatch(fragment)
    if line:
        last = int(line.group(2) or line.group(1))
        total = repo.line_count(sha, path)
        if last > total or int(line.group(1)) < 1:
            return f"line anchor #{fragment} is past the end of {path} at {sha[:12]} ({total} lines)"
        return None
    slugs = repo.anchors(sha, path)
    if slugs is None:
        return f"anchor #{fragment} cannot be checked in {path} (only Markdown headings and #L<n> lines are verifiable)"
    if fragment not in slugs:
        return f"anchor #{fragment} is not a heading or explicit anchor of {path} at {sha[:12]}"
    return None


def verify_sums_text(repo: Repo, sha: str, directory: str, text: str, label: str) -> list[str]:
    """Check each `<sha256>  <file>` line of a SHA256SUMS bundle against the blobs at `sha`."""
    problems: list[str] = []
    seen = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = SUMS_LINE.match(line)
        if not match:
            problems.append(f"{label}:{number}: not a `<sha256>  <file>` line")
            continue
        seen += 1
        digest, name = match.groups()
        target = f"{directory}/{name}" if directory else name
        data = repo.blob(sha, target)
        if data is None:
            problems.append(f"{label}:{number}: listed file {target} does not exist at {sha[:12]}")
        elif hashlib.sha256(data).hexdigest() != digest:
            problems.append(f"{label}:{number}: invalid digest for {target} at {sha[:12]}")
    if seen == 0:
        problems.append(f"{label}: no digest lines found")
    return problems


def digest_records(value: object) -> list[tuple[str, str]]:
    """Every `{"path": <str>, "sha256": <64-hex>}` object anywhere in a JSON value."""
    found: list[tuple[str, str]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            path, digest = node.get("path"), node.get("sha256")
            if isinstance(path, str) and isinstance(digest, str) and SHA64.fullmatch(digest):
                found.append((path, digest))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(value)
    return found


def json_digest_records(repo: Repo, files: Iterable[str]) -> list[tuple[str, str, str]]:
    """(citing file, path, digest) for each digest record in a tracked JSON file."""
    records: list[tuple[str, str, str]] = []
    for name in files:
        if not name.endswith(".json"):
            continue
        try:
            data = json.loads((repo.root / name).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        records.extend((name, path, digest) for path, digest in digest_records(data))
    return records


def validate(repo: Repo, files: list[str] | None = None) -> tuple[list[str], dict[str, int]]:
    """Return (errors, stats); `stats["missing_commits"]` counts commits the history lacks."""
    names = files if files is not None else repo.tracked_files()
    links = collect(repo, names)
    errors: list[str] = []
    missing_commits: list[str] = []
    stats = {
        "links": len(links),
        "commits": len({sha for _, sha, _, _ in links}),
        "digest_unresolved": 0,
        "missing_commits": 0,
    }

    def report(link: Link, message: str) -> None:
        for citing in sorted(set(links[link])):
            errors.append(f"{citing}: {message}")

    cited: dict[str, set[str]] = {}
    for link in sorted(links):
        kind, sha, path, fragment = link
        if not repo.commit_exists(sha):
            missing_commits.append(sha)
            report(link, f"permalink commit {sha} is not in the local history{repo.shallow_hint()}")
            continue
        if repo.check_ancestry and not repo.is_ancestor(sha):
            report(link, f"permalink commit {sha} is not an ancestor of {repo.main_ref}")
            continue
        actual = repo.object_type(sha, path)
        if actual is None:
            report(link, f"path {path} does not exist at {sha}")
            continue
        wanted = "blob" if kind == "blob" else "tree"
        if actual != wanted:
            report(link, f"{kind} link names a {actual} ({path} at {sha[:12]}); use `{actual}` in the URL")
            continue
        cited.setdefault(path, set()).add(sha)
        if fragment and actual == "blob":
            problem = check_fragment(repo, sha, path, fragment)
            if problem:
                report(link, problem)
        if actual == "blob" and Path(path).name.upper().startswith("SHA256SUMS"):
            text = (repo.blob(sha, path) or b"").decode("utf-8", errors="replace")
            directory = path.rpartition("/")[0]
            for problem in verify_sums_text(repo, sha, directory, text, f"{path}@{sha[:12]}"):
                report(link, problem)

    for citing, path, digest in json_digest_records(repo, names):
        if (repo.root / path).exists():
            continue
        shas = sorted(cited.get(path, ()))
        if not shas:
            stats["digest_unresolved"] += 1
            continue
        observed = [hashlib.sha256(repo.blob(sha, path) or b"").hexdigest() for sha in shas]
        if digest not in observed:
            errors.append(
                f"{citing}: invalid digest for {path}: record {digest[:12]} matches none of {', '.join(s[:12] for s in shas)}"
            )

    stats["missing_commits"] = len(set(missing_commits))
    return sorted(set(errors)), stats


def retirement_errors(repo: Repo, pin: str, prefixes: list[str]) -> tuple[list[str], int]:
    """Prove that `pin` holds every tracked file under `prefixes` byte-identical."""
    errors: list[str] = []
    if not repo.commit_exists(pin):
        return [f"pin {pin} is not in the local history{repo.shallow_hint()}"], 0
    if len(pin) != 40:
        errors.append(f"pin {pin} must be a full 40-hex commit")
    if repo.check_ancestry and not repo.is_ancestor(pin):
        return errors + [f"pin {pin} is not an ancestor of {repo.main_ref}"], 0
    tracked = repo.tracked_files()
    under = [name for name in tracked if name.startswith(tuple(prefixes))]
    for name in under:
        at_pin = repo.blob_id(pin, name)
        if at_pin is None:
            errors.append(f"{name}: does not exist at pin {pin[:12]}")
        elif at_pin != repo.blob_id("HEAD", name) or at_pin != _worktree_blob_id(repo, name):
            errors.append(f"{name}: differs from the tree being removed (blob at pin {at_pin[:12]})")
        if Path(name).name.upper().startswith("SHA256SUMS"):
            text = (repo.blob(pin, name) or b"").decode("utf-8", errors="replace")
            errors.extend(verify_sums_text(repo, pin, name.rpartition("/")[0], text, f"{name}@{pin[:12]}"))
    for citing, path, digest in json_digest_records(repo, tracked):
        if not path.startswith(tuple(prefixes)):
            continue
        data = repo.blob(pin, path)
        if data is None:
            errors.append(f"{citing}: digest record names {path}, which does not exist at pin {pin[:12]}")
        elif hashlib.sha256(data).hexdigest() != digest:
            errors.append(f"{citing}: invalid digest for {path}: record {digest[:12]} != blob at pin {pin[:12]}")
    return sorted(set(errors)), len(under)


def _worktree_blob_id(repo: Repo, name: str) -> str | None:
    result = repo._git("hash-object", "--", name)
    return result.stdout.strip() if result.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument(
        "--main-ref", help="ref that must contain every permalink commit (default: origin/main, then main)"
    )
    parser.add_argument("--no-ancestry", action="store_true", help="skip the ancestry check (reported in the summary)")
    parser.add_argument("--retirement-pin", metavar="SHA", help="verify this commit as the pin for a retirement")
    parser.add_argument(
        "--retire", action="append", default=[], metavar="PREFIX", help="tracked path prefix being retired"
    )
    args = parser.parse_args(argv)

    try:
        repo = Repo(args.root, args.main_ref, check_ancestry=not args.no_ancestry)
        if args.retirement_pin:
            if not args.retire:
                parser.error("--retirement-pin needs at least one --retire PREFIX")
            errors, count = retirement_errors(repo, args.retirement_pin, args.retire)
            for error in errors:
                print(f"ERROR {error}")
            print(
                f"Retirement pin check complete: {count} file(s) under {len(args.retire)} prefix(es), "
                f"pin {args.retirement_pin[:12]}, {len(errors)} error(s)"
            )
            return EXIT_ERRORS if errors else EXIT_OK
        errors, stats = validate(repo)
    except Unavailable as unavailable:
        print(f"UNAVAILABLE {unavailable}")
        return EXIT_UNAVAILABLE

    for error in errors:
        print(f"ERROR {error}")
    ancestry = f"ancestry of {repo.main_ref}" if repo.check_ancestry else "ancestry NOT checked (--no-ancestry)"
    note = (
        f"; {stats['digest_unresolved']} digest record(s) name a path with no permalink to verify"
        if stats["digest_unresolved"]
        else ""
    )
    print(
        f"Historical permalink check complete: {stats['links']} distinct permalink(s) at {stats['commits']} commit(s), "
        f"{ancestry}, {len(errors)} error(s){note}"
    )
    if stats["missing_commits"]:
        print(
            f"UNAVAILABLE {stats['missing_commits']} permalink commit(s) are absent from the local history: "
            "the check could not judge them (fetch the full history)"
        )
        return EXIT_UNAVAILABLE
    return EXIT_ERRORS if errors else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
