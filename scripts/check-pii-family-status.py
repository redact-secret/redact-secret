#!/usr/bin/env python3
"""Gate: every shipped opt-in PII family has a status row, bound to the exact
revisions it was qualified at (issue #1186, part of #1067).

The pinned support matrix does not carry PII families yet
(redact-secret/redact-secret-benchmarks#647), so the status source is the
hand-written table in `docs/reference/detection.md`, bound by
`docs/coverage/pii-family-status.json`. The gate fails when:

* a shipped family (`const FAMILY_ID` under `crates/secret-scan-core/src`)
  has no row in the binding or in the documented table, or either names a
  family that does not ship;
* the documented status differs from the binding, or a status is not one of
  pending / provisional / stable;
* the pinned matrix already carries a `pii:` family whose status differs from
  the binding (the matrix wins; retire the table when it is complete);
* the qualification core and benchmarks revisions are not full 40-hex ids or
  are missing from the documented page;
* a PII source file changed after the qualification does not exist or is not
  named on the documented page, so the page cannot claim a qualification the
  code has moved past without saying so.

Offline, deterministic, reads files only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "docs" / "coverage" / "pii-family-status.json"
MATRIX = ROOT / "benchmarks" / "support-matrix.json"
DOC = ROOT / "docs" / "reference" / "detection.md"
SRC = ROOT / "crates" / "secret-scan-core" / "src"
STATUSES = ("pending", "provisional", "stable")
FAMILY_ID = re.compile(r'^const FAMILY_ID: &str = "(pii:[a-z0-9:-]+)";', re.MULTILINE)
ROW = re.compile(r"^\| `(pii:[a-z0-9:-]+)` \|.*\| `([a-z]+)` \|$", re.MULTILINE)
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def shipped_families() -> set[str]:
    found: set[str] = set()
    for base in (SRC, SRC / "pii"):
        for path in sorted(base.glob("pii*.rs")):
            found.update(FAMILY_ID.findall(path.read_text(encoding="utf-8")))
    return found


def check(
    shipped: set[str],
    binding: dict,
    doc: str,
    matrix_pii: dict[str, str],
    root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    bound = binding.get("families", {})
    documented = dict(ROW.findall(doc))
    for family in sorted(shipped):
        if family not in bound:
            errors.append(f"{family}: shipped but has no row in docs/coverage/pii-family-status.json")
        if family not in documented:
            errors.append(f"{family}: shipped but has no status row in docs/reference/detection.md")
    for family in sorted(set(bound) - shipped):
        errors.append(f"{family}: in the binding but not shipped")
    for family in sorted(set(documented) - shipped):
        errors.append(f"{family}: documented but not shipped")
    for family, status in sorted(bound.items()):
        if status not in STATUSES:
            errors.append(f"{family}: status {status!r} is not one of {', '.join(STATUSES)}")
        elif family in documented and documented[family] != status:
            errors.append(f"{family}: documented status {documented[family]!r} differs from binding {status!r}")
        if family in matrix_pii and matrix_pii[family] != status:
            errors.append(f"{family}: pinned matrix status {matrix_pii[family]!r} differs from binding {status!r}")
    qualification = binding.get("qualification", {})
    for key in ("coreRevision", "benchmarksRevision"):
        value = qualification.get(key, "")
        if not HEX40.match(value):
            errors.append(f"qualification.{key} must be a full 40-hex revision, got {value!r}")
        elif value not in doc:
            errors.append(f"qualification.{key} {value} is not named on docs/reference/detection.md")
    for rel in binding.get("codeChangedSinceQualification", []):
        if not (root / rel).is_file():
            errors.append(f"codeChangedSinceQualification names a missing file: {rel}")
        if Path(rel).name not in doc:
            errors.append(f"docs/reference/detection.md does not name the changed file {Path(rel).name}")
    return errors


def main() -> int:
    binding = json.loads(BINDING.read_text(encoding="utf-8"))
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    matrix_pii = {f["family"]: f["status"] for f in matrix["families"] if f["family"].startswith("pii:")}
    errors = check(shipped_families(), binding, DOC.read_text(encoding="utf-8"), matrix_pii)
    if errors:
        print("PII family status gate failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"PII family status gate passed: {len(binding['families'])} families bound.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
