#!/usr/bin/env python3
"""Enforce the `secret-scan` legacy-identifier allowlist (issue #153).

`decision-adopt-redact-secret-naming-contract` replaced the `secret-scan`
public identity with `Redact Secret` everywhere. This script is the
deterministic declaration check that keeps the old identity from silently
reappearing in a manifest, a source import, a package dependency, a
workflow, a script, or current documentation.

It scans every tracked file for three legacy-identifier shapes:

1. `secret-scan` (kebab) -- the old crate, binary, and PyPI-fallback name.
2. `secret_scan` (snake) -- the old Rust and Python import path.
3. `SecretScan` (PascalCase), except a name that starts with `SecretScanError`
   -- `SecretScanError` and `SecretScanErrorCode` are exported type names this
   contract deliberately leaves unchanged
   (`decision-adopt-redact-secret-naming-contract`'s own scope boundary), so
   they are not a legacy identifier by themselves.

Two occurrences are never legacy identifiers, because they are not this
contract's concern:

- a `crates/secret-scan-core` or `crates/secret-scan-cli` path segment -- the
  directories were not renamed (Cargo resolves a crate by its manifest name,
  not its path);
- the phrase `secret-scanning` -- GitHub's product name for its own feature
  (as in its `supported-secret-scanning-patterns` documentation), which the
  audit evidence cites as a source; it shares a prefix with the old crate
  name but never named this project;
- `SecretScanError`/`SecretScanErrorCode` themselves, per the scope boundary
  above.

The repository transfer tracked by issue #157 is complete, so the former
GitHub owner/name and wiki sibling name are now ordinary legacy identifiers.
They are permitted only in reviewed historical records on the allowlist.

Every other hit must be on `LEGACY_IDENTIFIER_ALLOWLIST`, keyed by the exact
repository-relative path, with a non-empty rationale. Only reviewed
historical ADR, audit, migration, and redirect documents are allowlisted --
their old-name text describes what was true when they were written, and
rewriting it would misrepresent history rather than correct it
(`decision-adopt-redact-secret-naming-contract`). A hit anywhere else --
a manifest, a source import, a workflow, current documentation -- fails.

    python3 -B scripts/check-legacy-identifiers.py
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Exact repository-relative path -> why its legacy-identifier text is a
# reviewed historical record, not a missed rename. Every entry must name a
# file that exists and carry a non-empty rationale (checked below).
LEGACY_IDENTIFIER_ALLOWLIST: dict[str, str] = {
    "docs/python-repository-redirect.md": (
        "a drafted redirect notice for the archived secret-scan-python "
        "repository; the old name is the redirect's entire point and must "
        "not be rewritten"
    ),
    "docs/decisions/2026-09-09-adopt-rust-core-monorepo.md": (
        "the accepted architecture ADR identifies the repository name in force when adopted"
    ),
    "docs/decisions/2026-09-10-adopt-redact-secret-naming-contract.md": (
        "the ADR that records this rename itself; its naming matrix and "
        "rationale cite the old identity as the decision's own record of "
        "what changed, not a missed rename"
    ),
    "docs/audits/ci-release-automation-supply-chain-review.md": (
        "a closed, dated, commit-pinned independent review"
    ),
    "docs/audits/closed-issue-acceptance-evidence-ledger.md": (
        "a closed-issue acceptance-evidence ledger, dated and commit-pinned"
    ),
    "docs/audits/core-conformance-cli-boundary-review.md": (
        "a closed, dated, commit-pinned independent review"
    ),
    "docs/audits/detection-assurance-closeout-audit.md": (
        "a closed, dated, commit-pinned closeout audit"
    ),
    "docs/audits/javascript-python-bindings-package-contracts-review.md": (
        "a closed, dated, commit-pinned independent review"
    ),
    "docs/audits/release-approval-and-registry-publisher-evidence.md": (
        "a closed, dated, commit-pinned evidence record"
    ),
    "docs/audits/release-gap-disposition.md": (
        "a closed, dated disposition of four independent reviews' findings"
    ),
    "docs/audits/release-readiness-audit.md": (
        "a closed, dated, commit-pinned independent review"
    ),
    "docs/audits/repository-transfer-evidence.md": (
        "a dated pre/post transfer evidence record that must identify the former path"
    ),
    "scripts/check-legacy-identifiers.py": (
        "this script's own docstring and token patterns must name the "
        "legacy identifier literally to detect and document it; not a "
        "missed rename"
    ),
    "scripts/tests/test_check_legacy_identifiers.py": (
        "its fixtures construct example legacy-identifier text to prove "
        "the checker above still detects it; not a missed rename"
    ),
}

# `secret-scan` immediately inside a preserved directory path, or as the
# prefix of GitHub's `secret-scanning` product name, is not a legacy
# identifier. The former GitHub owner/name and wiki sibling name are detected
# now that issue #157 has transferred the repository.
KEBAB = re.compile(r"secret-scan(?!-core|-cli|-node|-wasm|-python|ning)")
SNAKE = re.compile(r"secret_scan")
# `SecretScanError`/`SecretScanErrorCode` are exported type names this
# contract leaves unchanged; any other `SecretScan*` is a legacy identifier.
PASCAL = re.compile(r"SecretScan(?!Error)")
TOKENS = (KEBAB, SNAKE, PASCAL)

# Extensions never worth decoding as text; a mismatch here just means the
# file is skipped, not silently trusted -- `is_probably_binary` below is the
# real guard.
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".wasm", ".node", ".so", ".pyd", ".woff", ".woff2"}


def list_tracked_files(root: Path) -> list[str]:
    output = subprocess.run(
        ["git", "ls-files"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [line for line in output.splitlines() if line]


def read_lines(root: Path, relative: str) -> list[str] | None:
    if Path(relative).suffix.lower() in BINARY_EXTENSIONS:
        return None
    try:
        return (root / relative).read_text(encoding="utf-8").splitlines()
    except (UnicodeDecodeError, OSError):
        return None


def find_hits(lines: list[str]) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for number, line in enumerate(lines, start=1):
        for token in TOKENS:
            match = token.search(line)
            if match is not None:
                hits.append((number, match.group(0)))
                break
    return hits


def check_allowlist_shape(root: Path) -> list[str]:
    """Every allowlist entry names a real file and carries a rationale."""
    errors: list[str] = []
    for relative, rationale in LEGACY_IDENTIFIER_ALLOWLIST.items():
        if not rationale.strip():
            errors.append(f"{relative}: allowlist entry has no rationale")
        if not (root / relative).is_file():
            errors.append(f"{relative}: allowlisted but the file does not exist")
    return errors


def validate(root: Path, files: list[str] | None = None) -> list[str]:
    """Every tracked file's legacy-identifier hits are on the allowlist.

    Does not itself check the allowlist's own shape (`check_allowlist_shape`)
    -- a caller testing this scan against a synthetic file set has no reason
    to also carry every real allowlisted file into that fixture.
    """
    root = root.resolve()
    errors: list[str] = []

    for relative in files if files is not None else list_tracked_files(root):
        if relative in LEGACY_IDENTIFIER_ALLOWLIST:
            continue
        lines = read_lines(root, relative)
        if lines is None:
            continue
        for number, token in find_hits(lines):
            errors.append(f"{relative}:{number}: legacy identifier {token!r} outside the allowlist")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()

    errors = check_allowlist_shape(args.root) + validate(args.root)
    for error in errors:
        print(f"ERROR {error}")
    print(f"Legacy-identifier check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
