#!/usr/bin/env python3
"""Gate every published description on one product positioning (#585).

npm, PyPI, crates.io, and the CLI each show a manifest `description` and a
README to a new user. Those surfaces must not contradict one another, so every
one of them opens with the same positioning statement, `POSITIONING`, and each
registry README also states the scope limits a reader needs before adopting:
not a DLP platform, not complete secret coverage, complementary to repository
and history scanners, with support published in the generated support matrix.

The root README's first section must state the runtime boundary and name the
five destinations the product scans for.

The GitHub repository's "About" description is not in the tree; set it to
`POSITIONING` by hand when it changes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

POSITIONING = "Deterministic secret detection and redaction for runtime data and AI context"

# Manifest path -> how to read its published description.
MANIFESTS = {
    "packages/javascript/package.json": "json",
    "bindings/python/pyproject.toml": "pyproject",
    "crates/secret-scan-core/Cargo.toml": "cargo",
    "crates/secret-scan-cli/Cargo.toml": "cargo",
}

# READMEs a registry renders as the package page.
REGISTRY_READMES = (
    "packages/javascript/README.md",
    "bindings/python/README.md",
    "crates/secret-scan-core/README.md",
    "crates/secret-scan-cli/README.md",
)

# Phrases every registry README must carry, lowercased, before its first
# second-level heading.
REQUIRED_SCOPE = {
    "not a DLP platform": "not a dlp platform",
    "no complete-coverage claim": "does not detect every secret",
    "complementary to repository/history scanners": "complements repository and history scanners",
    "support matrix link": "support-matrix.md",
}

USE_CASES = ("logs", "persistence", "telemetry", "tool output", "model context")

FORBIDDEN = (
    re.compile(r"\bcomplete (dlp|secret coverage|coverage)\b", re.IGNORECASE),
    re.compile(r"\bdetects? (all|every) secrets?\b", re.IGNORECASE),
)


def read_description(text: str, kind: str) -> str | None:
    if kind == "json":
        return json.loads(text).get("description")
    data = tomllib.loads(text)
    if kind == "pyproject":
        return data.get("project", {}).get("description")
    return data.get("package", {}).get("description")


def intro(markdown: str) -> str:
    """Text before the first `## ` heading, whitespace-collapsed and lowercased."""
    head = re.split(r"^## ", markdown, maxsplit=1, flags=re.MULTILINE)[0]
    return " ".join(head.split()).lower()


def first_section(markdown: str) -> str:
    """The root README's title block plus its first `## ` section."""
    parts = re.split(r"^(?=## )", markdown, flags=re.MULTILINE)
    return " ".join(" ".join(parts[:2]).split()).lower()


def check_manifest(path: str, text: str, kind: str) -> list[str]:
    description = read_description(text, kind)
    if not description:
        return [f"{path} has no description"]
    if not description.startswith(POSITIONING):
        return [f"{path} description does not start with the shared positioning statement"]
    return []


def check_registry_readme(path: str, text: str) -> list[str]:
    errors: list[str] = []
    head = intro(text)
    if POSITIONING.lower() not in head:
        errors.append(f"{path} intro does not state the shared positioning statement")
    for label, phrase in REQUIRED_SCOPE.items():
        if phrase not in head:
            errors.append(f"{path} intro is missing: {label}")
    return errors


def check_root_readme(text: str) -> list[str]:
    errors: list[str] = []
    first = first_section(text)
    if POSITIONING.lower() not in first:
        errors.append("README.md first section does not state the shared positioning statement")
    for use_case in USE_CASES:
        if use_case not in first:
            errors.append(f"README.md first section does not name the use case: {use_case}")
    return errors


def check_forbidden(path: str, text: str) -> list[str]:
    errors: list[str] = []
    for pattern in FORBIDDEN:
        for match in pattern.finditer(text):
            # A negated claim ("not a complete DLP system") is the point, not a violation.
            window = text[max(0, match.start() - 40) : match.start()].lower()
            if re.search(r"\b(not|never|no)\b", window):
                continue
            errors.append(f"{path} claims coverage it does not have: {match.group(0)!r}")
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for path, kind in MANIFESTS.items():
        errors += check_manifest(path, (root / path).read_text(encoding="utf-8"), kind)
    for path in REGISTRY_READMES:
        text = (root / path).read_text(encoding="utf-8")
        errors += check_registry_readme(path, text)
        errors += check_forbidden(path, text)
    readme = (root / "README.md").read_text(encoding="utf-8")
    errors += check_root_readme(readme)
    errors += check_forbidden("README.md", readme)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        errors = validate(args.root)
    except OSError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"ERROR {error}")
    print(f"Product-positioning check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
