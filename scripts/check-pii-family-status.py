#!/usr/bin/env python3
"""Gate: every shipped opt-in PII family has a status, read from the pinned
support matrix and bound to the exact revisions it was qualified at (issue
#1186, part of #1067).

The pinned support matrix carries the PII families as top-level `piiFamilies`,
`piiQualification` and `piiDistribution`
(redact-secret/redact-secret-benchmarks#647, benchmarks 573e128). They are the
status source. The hand-written table in `docs/reference/detection.md` must
agree with them, and `docs/coverage/pii-family-status.json` binds the
qualification identity (core and benchmarks revisions) and the PII source
files that changed after it. For a matrix that predates those keys the
binding's own `families` map is the fallback source; once the matrix carries
them, a `families` map in the binding is an error, so there is one source. The
gate fails when:

* a shipped family (`const FAMILY_ID` under `crates/secret-scan-core/src`)
  has no row in the status source or in the documented table, or either names
  a family that does not ship;
* the documented status differs from the status source, or a status is not
  one of pending / provisional / stable;
* the matrix `piiDistribution` does not match its `piiFamilies`;
* the matrix `piiQualification` is not `not-requalified`, or names a core or
  benchmarks revision other than the binding's, or the documented page does
  not say the statuses were not re-qualified;
* the qualification core and benchmarks revisions are not full 40-hex ids or
  are missing from the documented page;
* a PII source file changed after the qualification does not exist or is not
  named on the documented page, so the page cannot claim a qualification the
  code has moved past without saying so.

The statuses are those of the Beta.11 qualification on core 8b6a5fde. Nothing
here re-qualifies them on a later core commit. Offline, deterministic, reads
files only.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pii_current_qualification import current_qualification_errors, current_qualification_sentence
from support_matrix_source import (
    active_matrix_path,
    historical_pii_matrix,
)

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "docs" / "coverage" / "pii-family-status.json"
MATRIX = active_matrix_path(ROOT)
DOC = ROOT / "docs" / "reference" / "detection.md"
SRC = ROOT / "crates" / "secret-scan-core" / "src"
STATUSES = ("pending", "provisional", "stable")
FAMILY_ID = re.compile(r'^const FAMILY_ID: &str = "(pii:[a-z0-9:-]+)";', re.MULTILINE)
ROW = re.compile(r"^\| `(pii:[a-z0-9:-]+)` \|.*\| `([a-z]+)` \|$", re.MULTILINE)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
NOT_REQUALIFIED_PHRASE = "not re-qualified"


def shipped_families() -> set[str]:
    found: set[str] = set()
    for base in (SRC, SRC / "pii"):
        for path in sorted(base.glob("pii*.rs")):
            found.update(FAMILY_ID.findall(path.read_text(encoding="utf-8")))
    return found


def matrix_pii_statuses(matrix: dict) -> dict[str, str] | None:
    """The `piiFamilies` statuses of a pinned matrix, or None when the matrix
    predates those keys (then the binding's `families` map is the source)."""
    rows = matrix.get("piiFamilies")
    if rows is None:
        return None
    return {row["family"]: row["status"] for row in rows}


def check(
    shipped: set[str],
    binding: dict,
    doc: str,
    matrix_pii: dict[str, str] | None,
    root: Path = ROOT,
    matrix_qualification: dict | None = None,
    matrix_distribution: dict | None = None,
) -> list[str]:
    errors: list[str] = []
    if matrix_pii is not None:
        if "families" in binding:
            errors.append(
                "docs/coverage/pii-family-status.json still carries a `families` map although the pinned "
                "matrix carries piiFamilies; remove it so the matrix is the only status source"
            )
        bound = matrix_pii
        source = "the pinned matrix piiFamilies"
    else:
        bound = binding.get("families", {})
        source = "docs/coverage/pii-family-status.json"
    documented = dict(ROW.findall(doc))
    for family in sorted(shipped):
        if family not in bound:
            errors.append(f"{family}: shipped but has no row in {source}")
        if family not in documented:
            errors.append(f"{family}: shipped but has no status row in docs/reference/detection.md")
    for family in sorted(set(bound) - shipped):
        errors.append(f"{family}: in {source} but not shipped")
    for family in sorted(set(documented) - shipped):
        errors.append(f"{family}: documented but not shipped")
    for family, status in sorted(bound.items()):
        if status not in STATUSES:
            errors.append(f"{family}: status {status!r} is not one of {', '.join(STATUSES)}")
        elif family in documented and documented[family] != status:
            errors.append(f"{family}: documented status {documented[family]!r} differs from {source} {status!r}")
    qualification = binding.get("qualification", {})
    for key in ("coreRevision", "benchmarksRevision"):
        value = qualification.get(key, "")
        if not HEX40.match(value):
            errors.append(f"qualification.{key} must be a full 40-hex revision, got {value!r}")
        elif value not in doc:
            errors.append(f"qualification.{key} {value} is not named on docs/reference/detection.md")
    if matrix_pii is not None:
        errors.extend(check_matrix_identity(binding, doc, matrix_pii, matrix_qualification, matrix_distribution))
    for rel in binding.get("codeChangedSinceQualification", []):
        if not (root / rel).is_file():
            errors.append(f"codeChangedSinceQualification names a missing file: {rel}")
        if Path(rel).name not in doc:
            errors.append(f"docs/reference/detection.md does not name the changed file {Path(rel).name}")
    return errors


def check_matrix_identity(
    binding: dict,
    doc: str,
    matrix_pii: dict[str, str],
    qualification: dict | None,
    distribution: dict | None,
) -> list[str]:
    """The matrix's own PII identity: its distribution agrees with its rows, and
    its qualification is the one the binding names and is not a re-qualification."""
    errors: list[str] = []
    counts = {status: sum(value == status for value in matrix_pii.values()) for status in STATUSES}
    if distribution is None:
        errors.append("the pinned matrix carries piiFamilies but no piiDistribution")
    elif {status: distribution.get(status) for status in STATUSES} != counts:
        errors.append(f"piiDistribution {distribution} does not match the piiFamilies rows {counts}")
    if qualification is None:
        errors.append("the pinned matrix carries piiFamilies but no piiQualification")
        return errors
    state = qualification.get("requalification", {}).get("state")
    if state != "not-requalified":
        errors.append(
            f"piiQualification.requalification.state is {state!r}; this gate only describes statuses that "
            "were not re-qualified, so a re-qualification needs the gate and the page updated together"
        )
    expected = binding.get("qualification", {})
    core = qualification.get("qualifiedAt", {}).get("coreCommit")
    if core != expected.get("coreRevision"):
        errors.append(
            f"piiQualification.qualifiedAt.coreCommit {core!r} differs from the binding {expected.get('coreRevision')!r}"
        )
    record = qualification.get("benchmarks", {}).get("recordRevision")
    if record != expected.get("benchmarksRevision"):
        errors.append(
            f"piiQualification.benchmarks.recordRevision {record!r} differs from the binding "
            f"{expected.get('benchmarksRevision')!r}"
        )
    if NOT_REQUALIFIED_PHRASE not in " ".join(doc.split()):
        errors.append(f"docs/reference/detection.md must say the PII statuses are {NOT_REQUALIFIED_PHRASE!r}")
    return errors


def main() -> int:
    binding = json.loads(BINDING.read_text(encoding="utf-8"))
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    shipped = shipped_families()
    historical = historical_pii_matrix(matrix)
    errors = check(
        shipped,
        binding,
        DOC.read_text(encoding="utf-8"),
        matrix_pii_statuses(historical),
        matrix_qualification=historical.get("piiQualification"),
        matrix_distribution=historical.get("piiDistribution"),
    )
    errors.extend(current_qualification_errors(matrix.get("piiCurrentQualification"), shipped))
    if errors:
        print("PII family status gate failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    source = "pinned matrix" if "piiFamilies" in matrix else "binding"
    print(f"PII family status gate passed: {len(shipped)} families, statuses from the {source}, not re-qualified.")
    print(current_qualification_sentence(matrix.get("piiCurrentQualification")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
