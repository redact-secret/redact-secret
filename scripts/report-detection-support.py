#!/usr/bin/env python3
"""Join every shipped detector and PII family with the pinned support matrix
(issue #1067, part of epic #1065; reconciles #200).

The report answers one question with exact identities: of the detectors and
PII families this source revision ships, how many carry a measured status in
the pinned `benchmarks/support-matrix.json`, and which ship with none?

Shipped set (read from the code-derived artifacts, never typed in):

* credential detectors and finding types: `docs/coverage/detector-inventory.json`
  (reconciled against the real registry by the Rust test
  `built_in_inventory_matches_the_declared_baseline`);
* PII families: the `const FAMILY_ID` of each family under
  `crates/secret-scan-core/src/pii*`. The PII adapter is a single registry slot
  (`pii-domain`) and is deliberately not in the detector inventory.

Measured set: `benchmarks/support-matrix.json`, keyed family -> detector ids.
The matrix carries the PII families apart from the credential families, as
`piiFamilies`; the report shows each family's pinned-matrix status beside the
status documented in `docs/reference/detection.md`. A matrix that predates
those keys reports them as absent from the matrix.

Both revisions are printed: this repository's `git rev-parse HEAD` (or
`--source-revision`) and the pinned benchmarks revision, together with the
product source commit the matrix actually measured. The two product commits
differ whenever this checkout is ahead of the measured candidate; the report
says so rather than hiding it.

    python3 -B scripts/report-detection-support.py            # Markdown
    python3 -B scripts/report-detection-support.py --json     # JSON

Offline and deterministic: no network, no timestamps, sorted output. It writes
nothing; redirect the output where it is needed. It is a report, not a gate:
the gates are `scripts/check-detector-family-coverage.py --strict` and
`scripts/check-pii-family-status.py` (PII statuses).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pii_current_qualification import current_qualification_errors, current_qualification_sentence
from support_matrix_source import (
    active_matrix_path,
    historical_pii_matrix,
    matrix_source,
)

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
MATRIX_PATH = active_matrix_path(ROOT)
PIN_SOURCE_PATH = ROOT / "benchmarks" / "pin-source.json"
PIN_MANIFEST_PATH = ROOT / "benchmarks" / "pin-manifest.json"
ALLOWLIST_PATH = ROOT / "docs" / "coverage" / "detector-family-coverage-allowlist.json"
DETECTION_DOC = ROOT / "docs" / "reference" / "detection.md"
PII_BINDING_PATH = ROOT / "docs" / "coverage" / "pii-family-status.json"
PII_SOURCES = (ROOT / "crates" / "secret-scan-core" / "src" / "pii", ROOT / "crates" / "secret-scan-core" / "src")

STATUSES = ("stable", "provisional", "pending", "unsupported")
# Weakest first: a detector whose families differ is reported at its weakest.
WEAKEST_FIRST = ("unsupported", "pending", "provisional", "stable")
FOLDED_OWNER = re.compile(r"folds (?:it )?into `([^`]+)`")
FAMILY_ID = re.compile(r'^const FAMILY_ID: &str = "(pii:[a-z0-9:-]+)";', re.MULTILINE)
PII_ROW = re.compile(r"^\| `(pii:[a-z0-9:-]+)` \|.*\| `(pending|provisional|stable)` \|$", re.MULTILINE)


def git_head() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def shipped_pii_families() -> list[str]:
    found: set[str] = set()
    for base in PII_SOURCES:
        for path in sorted(base.glob("pii*.rs")):
            found.update(FAMILY_ID.findall(path.read_text(encoding="utf-8")))
    return sorted(found)


def documented_pii_status() -> dict[str, str]:
    return dict(PII_ROW.findall(DETECTION_DOC.read_text(encoding="utf-8")))


def build(source_revision: str) -> dict:
    inventory = load(INVENTORY_PATH)
    matrix = load(MATRIX_PATH)
    allowlist = load(ALLOWLIST_PATH)
    pin_source = load(PIN_SOURCE_PATH)
    pin_manifest = load(PIN_MANIFEST_PATH)

    types_by_detector: dict[str, list[str]] = {}
    for entry in inventory["types"]:
        types_by_detector.setdefault(entry["detector"], []).append(entry["type"])
    # The harness scores some finding types of a shipped detector as their own
    # arrival families, so the matrix keys them by a detector id the inventory
    # does not have. The reviewed allowlist names the owning detector for each
    # such id; attribute those families to it so a weaker folded family is not
    # hidden behind its detector's stable ones.
    folded_owner: dict[str, str] = {}
    for folded, reason in allowlist.get("stale", {}).items():
        owner = FOLDED_OWNER.search(reason)
        if owner and owner.group(1) in types_by_detector:
            folded_owner[folded] = owner.group(1)
    families_by_detector: dict[str, list[dict]] = {}
    for family in matrix["families"]:
        for listed_id in family.get("detectors", []):
            detector = folded_owner.get(listed_id, listed_id)
            if family not in families_by_detector.setdefault(detector, []):
                families_by_detector[detector].append(family)

    rows = []
    for detector in sorted(types_by_detector):
        listed = families_by_detector.get(detector, [])
        statuses = sorted({f["status"] for f in listed}, key=WEAKEST_FIRST.index)
        rows.append(
            {
                "detector": detector,
                "findingTypes": sorted(types_by_detector[detector]),
                "weakestStatus": statuses[0] if statuses else "shipped-but-unmeasured",
                "families": sorted(f["family"] for f in listed),
                "familyStatuses": {f["family"]: f["status"] for f in sorted(listed, key=lambda f: f["family"])},
            }
        )

    shipped = {r["detector"] for r in rows}
    stale = sorted(d for d in families_by_detector if d not in shipped)
    folded = sorted(folded_owner)

    detector_counts = {s: 0 for s in STATUSES}
    detector_counts["shipped-but-unmeasured"] = 0
    for row in rows:
        detector_counts[row["weakestStatus"]] += 1

    family_counts = {s: 0 for s in STATUSES}
    families_without_detector = []
    for family in matrix["families"]:
        family_counts[family["status"]] += 1
        if not family.get("detectors"):
            families_without_detector.append({"family": family["family"], "status": family["status"]})

    pii_ids = shipped_pii_families()
    pii_docs = documented_pii_status()
    current = matrix.get("piiCurrentQualification")
    errors = current_qualification_errors(current, set(pii_ids))
    if errors:
        raise ValueError("; ".join(errors))
    # The PII families are top-level `piiFamilies` of the pinned matrix (benchmarks 573e128),
    # never rows of `families`; a matrix that predates the key has none.
    historical = historical_pii_matrix(matrix)
    pii_matrix_status = {row["family"]: row["status"] for row in historical.get("piiFamilies", [])}
    pii_matrix = sorted(pii_matrix_status)
    pii_rows = [
        {
            "family": family,
            "inPinnedMatrix": family in pii_matrix,
            "pinnedMatrixStatus": pii_matrix_status.get(family),
            "documentedStatus": pii_docs.get(family),
        }
        for family in pii_ids
    ]

    source = matrix_source(matrix)
    measured_commit, measured_version = source["productRevision"], source["productVersion"]
    return {
        "sourceRevision": source_revision,
        "matrixSource": source,
        "benchmarks": {
            "matrixSourceReportRevision": source["revision"],
            "matrixSourceReportDirty": source["dirty"],
            "matrixMeasuredProductCommit": measured_commit,
            "matrixMeasuredProductVersion": measured_version,
            "matrixFixtureCount": source["fixtureCount"],
            "matrixFixtureIndexDigest": source["fixtureDigest"],
            "matrixTaxonomyDigest": source["taxonomyDigest"],
            "pinSourceBenchmarkCommit": pin_source["benchmarkCommit"],
            "pinManifestRevision": pin_manifest["revision"],
            "pinManifestRedactSecretRevision": pin_manifest["pins"]["redactSecretRevision"],
        },
        "measuredProductIsSourceRevision": measured_commit == source_revision,
        "shipped": {
            "credentialDetectors": len(rows),
            "credentialFindingTypes": len(inventory["types"]),
            "piiFamilies": len(pii_ids),
        },
        "matrix": {
            "providers": matrix["providerCount"],
            "families": matrix["familyCount"],
            "familiesByStatus": family_counts,
            "familiesWithoutShippedDetector": families_without_detector,
            "detectorIdsNotInInventory": stale,
            "foldedDetectorIds": {k: folded_owner[k] for k in folded},
            "allowlistedUnmeasured": sorted(allowlist.get("unmeasured", {})),
        },
        "credentialDetectorsByWeakestStatus": detector_counts,
        "shippedButUnmeasuredCredentialDetectors": [
            r["detector"] for r in rows if r["weakestStatus"] == "shipped-but-unmeasured"
        ],
        "piiFamilies": pii_rows,
        "piiCurrentQualification": current,
        "piiQualification": {
            **load(PII_BINDING_PATH)["qualification"],
            "codeChangedSinceQualification": load(PII_BINDING_PATH)["codeChangedSinceQualification"],
        },
        "detectors": rows,
    }


def markdown(report: dict) -> str:
    b = report["benchmarks"]
    measured = (
        f"Product commit the matrix measured: `{b['matrixMeasuredProductCommit']}` (`{b['matrixMeasuredProductVersion']}`)"
        if b["matrixMeasuredProductCommit"]
        else f"Published npm package the matrix measured: `@redact-secret/core@{b['matrixMeasuredProductVersion']}`; source commit not recorded"
    )
    source = report.get("matrixSource", {})
    if source.get("kind") == "qualification-view":
        identity_lines = [
            f"- Canonical qualification view pinned at benchmarks `{source['revision']}`; policy `{source['policyRevision']}`.",
            "- The view records no measurement timestamp or product source commit.",
            *[
                f"- Population `{p['population']}`: semantic `{p['semanticDigest']}`, artifact `{p['artifactDigest']}`."
                for p in source["populations"]
            ],
        ]
    else:
        identity_lines = [
            f"- Pinned matrix generated by benchmarks revision: `{b['matrixSourceReportRevision']}` (dirty: {str(b['matrixSourceReportDirty']).lower()})",
            f"- Corpus identity: {b['matrixFixtureCount']} fixtures, index digest `{b['matrixFixtureIndexDigest']}`, taxonomy digest `{b['matrixTaxonomyDigest']}`",
        ]
    out = [
        "# Detector and PII family support join",
        "",
        f"- Source revision (`git rev-parse HEAD`): `{report['sourceRevision']}`",
        *identity_lines,
        f"- {measured}; "
        + ("same as the source revision." if report["measuredProductIsSourceRevision"] else "NOT the source revision."),
        f"- `benchmarks/pin-source.json` benchmarkCommit: `{b['pinSourceBenchmarkCommit']}`; `benchmarks/pin-manifest.json` revision: `{b['pinManifestRevision']}` (redactSecretRevision `{b['pinManifestRedactSecretRevision']}`)",
        "",
        "## Counts",
        "",
        f"Shipped: {report['shipped']['credentialDetectors']} credential detectors emitting {report['shipped']['credentialFindingTypes']} finding types, and {report['shipped']['piiFamilies']} opt-in PII families.",
        "",
        f"Pinned matrix: {report['matrix']['providers']} providers, {report['matrix']['families']} families.",
        "",
        "| Status | Matrix families | Shipped credential detectors (weakest listed family) |",
        "| --- | ---: | ---: |",
    ]
    for status in STATUSES:
        out.append(
            f"| {status} | {report['matrix']['familiesByStatus'][status]} | {report['credentialDetectorsByWeakestStatus'][status]} |"
        )
    out.append(
        f"| shipped-but-unmeasured | n/a | {report['credentialDetectorsByWeakestStatus']['shipped-but-unmeasured']} |"
    )
    unmeasured = report["shippedButUnmeasuredCredentialDetectors"]
    out += [
        "",
        "Credential detectors with no matrix family: "
        + (", ".join(f"`{d}`" for d in unmeasured) if unmeasured else "none")
        + ".",
        "",
    ]
    out += [
        "## PII families",
        "",
        "| Family | In pinned matrix | Documented status (`docs/reference/detection.md`) |",
        "| --- | --- | --- |",
    ]
    for row in report["piiFamilies"]:
        out.append(
            f"| `{row['family']}` | {'yes' if row['inPinnedMatrix'] else 'no'} | {row['documentedStatus'] or 'none'} |"
        )
    out += ["", current_qualification_sentence(report.get("piiCurrentQualification"))]
    q = report["piiQualification"]
    out += [
        "",
        f"PII statuses were qualified at core `{q['coreRevision']}` ({q['release']}) with benchmarks revision "
        f"`{q['benchmarksRevision']}`. PII source files changed since: "
        + ", ".join(f"`{p}`" for p in q["codeChangedSinceQualification"])
        + ". Gate: `scripts/check-pii-family-status.py`.",
    ]
    out += ["", "## Matrix families with no shipped detector", "", "| Family | Status |", "| --- | --- |"]
    for row in report["matrix"]["familiesWithoutShippedDetector"]:
        out.append(f"| `{row['family']}` | {row['status']} |")
    out += [
        "",
        "## Matrix detector ids the inventory folds into another detector",
        "",
        "Each id is attributed to its owning detector above.",
        "",
    ]
    out += ["| Matrix detector id | Owning shipped detector |", "| --- | --- |"]
    for folded, owner in report["matrix"]["foldedDetectorIds"].items():
        out.append(f"| `{folded}` | `{owner}` |")
    unresolved = report["matrix"]["detectorIdsNotInInventory"]
    out += [
        "",
        "Matrix detector ids with no shipped owner: "
        + (", ".join(f"`{d}`" for d in unresolved) if unresolved else "none")
        + ".",
    ]
    out += [
        "",
        "## Per-detector join",
        "",
        "| Detector | Finding types | Weakest status | Matrix families |",
        "| --- | --- | --- | --- |",
    ]
    for row in report["detectors"]:
        types = ", ".join(f"`{t}`" for t in row["findingTypes"])
        families = ", ".join(f"`{f}` ({row['familyStatuses'][f]})" for f in row["families"]) or "none"
        out.append(f"| `{row['detector']}` | {types} | {row['weakestStatus']} | {families} |")
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--source-revision", help="override `git rev-parse HEAD`")
    args = parser.parse_args(argv)
    report = build(args.source_revision or git_head())
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
