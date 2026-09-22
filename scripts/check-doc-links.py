#!/usr/bin/env python3
"""Gate broken relative links and heading anchors in tracked Markdown (#593; DS1).

Repository Markdown is the source documentation
(`convention-feature-documentation`); a link that silently rots is a defect
the same way a failing test is. This script re-derives every tracked `.md`
file's relative links -- `[text](path)` and `![alt](path)`, path optionally
followed by `#anchor` -- and checks that:

1. the target path resolves to a real file or directory, relative to the
   *linking* file's own directory (a leading `/` is repo-root-relative,
   matching how GitHub renders it inside this repository); and
2. when the target is a `.md` file and the link carries an anchor, that
   anchor is a heading in the target file, slugified the same way GitHub
   slugifies a heading into its anchor id: lowercase, strip everything that
   is not a letter, digit, underscore, space, or existing hyphen, then turn
   each remaining space into its own hyphen (adjacent spaces become adjacent
   hyphens, never collapsed) -- and a heading whose slug repeats within one
   file gets `-1`, `-2`, ... appended, in document order, the same as GitHub.

A link inside a fenced code block or an inline code span is never a real
link (both appear throughout this repository's own worked examples) and is
excluded before scanning, by removing fenced lines and stripping inline code
spans line by line -- the same shape of exclusion this script's own docstring
examples would otherwise trip.

This is a read-only gate: it fixes nothing. `docs/audits/evidence/<issue>/`
is frozen evidence (`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`);
a broken link discovered inside a file covered by a sibling `SHA256SUMS.txt`
must be corrected by editing the *linking* prose elsewhere or accepted and
recorded, never by silently rewriting the hashed file's bytes.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FENCE_RE = re.compile(r"^(```|~~~)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+)$")
TRAILING_HASHES_RE = re.compile(r"\s+#+\s*$")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
BAD_SLUG_CHARS_RE = re.compile(r"[^\w\s-]", re.UNICODE)


def list_tracked_markdown_files(root: Path) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [line for line in output.splitlines() if line]


def strip_fences(text: str) -> list[str]:
    """Lines with fenced-code-block bodies removed, so a `#`-prefixed line
    inside a fence (a shell comment, for instance) is never read as a real
    heading. Inline code spans are left alone: GitHub slugifies a heading's
    rendered text, backticks included, not a code-span-stripped version of
    it -- `heading_slugs` relies on that to match a real anchor id."""
    lines = text.splitlines()
    kept: list[str] = []
    in_fence = False
    for line in lines:
        if FENCE_RE.match(line.strip()):
            in_fence = not in_fence
            kept.append("")
            continue
        kept.append("" if in_fence else line)
    return kept


def strip_fences_and_code_spans(text: str) -> list[str]:
    """`strip_fences` plus inline code spans blanked out, so a link written
    as a worked example inside backticks is never read as a real link."""
    return [
        INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), line)
        for line in strip_fences(text)
    ]


def slugify(heading_text: str) -> str:
    text = BAD_SLUG_CHARS_RE.sub("", heading_text.lower())
    return text.replace(" ", "-")


def heading_slugs(lines: list[str]) -> set[str]:
    """Every heading's GitHub anchor id, including `-1`/`-2`/... suffixes
    for a slug that repeats later in the same file."""
    seen: dict[str, int] = {}
    slugs: set[str] = set()
    for line in lines:
        match = HEADING_RE.match(line)
        if match is None:
            continue
        text = TRAILING_HASHES_RE.sub("", match.group(1)).strip()
        slug = slugify(text)
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        slugs.add(slug if count == 0 else f"{slug}-{count}")
    return slugs


def split_url(raw: str) -> str:
    """Drop an optional `"title"`/`'title'` suffix from a link destination."""
    for quote in (' "', " '"):
        index = raw.find(quote)
        if index != -1:
            raw = raw[:index]
    return raw.strip()


def resolve_target(root: Path, source: Path, path_part: str) -> Path:
    if path_part.startswith("/"):
        return (root / path_part.lstrip("/")).resolve()
    return (source.parent / path_part).resolve()


def check_file(root: Path, relative: str, slug_cache: dict[Path, set[str] | None]) -> list[str]:
    errors: list[str] = []
    source = root / relative
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return errors
    lines = strip_fences_and_code_spans(text)

    for number, line in enumerate(lines, start=1):
        for match in LINK_RE.finditer(line):
            url = split_url(match.group(1))
            if not url or SCHEME_RE.match(url) or url.startswith("<"):
                continue

            path_part, _, anchor = url.partition("#")
            target = source if path_part == "" else resolve_target(root, source, path_part)

            if not target.exists():
                errors.append(f"{relative}:{number}: broken relative link target {url!r}")
                continue

            if anchor and target.is_file() and target.suffix == ".md":
                if target not in slug_cache:
                    try:
                        slug_cache[target] = heading_slugs(strip_fences(target.read_text(encoding="utf-8")))
                    except (OSError, UnicodeDecodeError):
                        slug_cache[target] = None
                slugs = slug_cache[target]
                if slugs is not None and anchor not in slugs:
                    errors.append(f"{relative}:{number}: broken anchor '#{anchor}' in link {url!r}")
    return errors


def validate(root: Path, files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    slug_cache: dict[Path, set[str] | None] = {}
    errors: list[str] = []
    for relative in files if files is not None else list_tracked_markdown_files(root):
        errors.extend(check_file(root, relative, slug_cache))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("root", nargs="?", default=ROOT, type=Path)
    args = parser.parse_args()

    errors = validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Doc-links check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
