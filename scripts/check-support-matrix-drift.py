#!/usr/bin/env python3
"""Gate a release candidate on support-matrix drift (issue #511, A10; part of #500).

`redact-secret-benchmarks` (#51) computes a drift record comparing a saved
baseline support matrix against a candidate's, but explicitly leaves the
release decision to this repository: "this repository emits and records the
drift; it does not decide the release." This script is that decision:

    python3 -B scripts/check-support-matrix-drift.py \\
        --baseline <(git show v0.1.0-beta.5:benchmarks/support-matrix.json) \\
        --candidate benchmarks/support-matrix.json \\
        --out support-matrix-drift.json

It ports `buildSupportMatrixDrift` (redact-secret-benchmarks'
`benchmarks/support/drift.ts`) into pure Python so the gate stays inside
this repository's own deterministic, offline boundary -- neither input ever
leaves the two already-committed/pinned JSON files this script is given,
and nothing here checks out or invokes the benchmarks repository (issue
#511 acceptance criterion 3).

Both inputs are validated against `benchmarks/support-matrix-schema.json`
first, the same structural second line of defense
`generate-support-matrix-docs.py`'s `validate_matrix` runs, so drift is
never computed from a malformed or hand-edited matrix -- and "a newly added
family must arrive with a status, never unclassified" (issue #511's scope)
is guaranteed by that same schema check rather than re-derived here. A
candidate whose `sourceReport.dirty` is `true` is rejected by default:
issue #508 established that candidate-derived and published-derived
evidence answer different questions, and an uncommitted benchmarks checkout
is not reproducible published-artifact evidence (acceptance criterion 4).
Pass `--allow-dirty-candidate` for a local dry run during RC prep.

Of the four kinds of drift:

- a **regression** (a family that carried `stable` in the baseline and does
  not in the candidate) fails this gate by default. Overriding it requires
  an explicit entry in `benchmarks/support-matrix-drift-acknowledgements.json`,
  fingerprinted on `family|baselineStatus|candidateStatus|reason` -- the
  same content-fingerprint disposition pattern `scripts/run-sast.py` uses
  for `sast/baseline.json` -- so a *new* reason for the same family's
  regression is never silently covered by an old acknowledgement of a
  different reason.
- an **improvement** (a family reaching `stable`) never blocks; its full
  evidence bundle is carried in the record for review, already backed by
  whatever the stable criteria (#503) required to earn it.
- a **newAndUnclassified** family never blocks either.
- **staleProviderProvenance** is a warning only, per the issue's own text. The
  compatibility key now covers drift in any evidence-provenance field, including
  evidence tier, basis, qualification profile, empirical evidence, and fixture
  profile, rather than silently checking `providerSource` alone.

Release authority is unchanged (acceptance criterion 5): a nonzero exit here
fails the qualification job and blocks publication in `release.yml`, but
nothing here tags, publishes, or releases anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "benchmarks" / "support-matrix.json"
SCHEMA_PATH = ROOT / "benchmarks" / "support-matrix-schema.json"
ACKNOWLEDGEMENTS_PATH = ROOT / "benchmarks" / "support-matrix-drift-acknowledgements.json"

EVIDENCE_FIELDS = (
    "evidenceTier",
    "evidenceBasis",
    "qualificationProfile",
    "providerSource",
    "corroboratingScanners",
    "twinCoverage",
    "unresolvedCriticalItems",
    "empiricalEvidence",
    "fixtureProfile",
    "detectors",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_matrix(label: str, matrix: dict, schema: dict) -> list[str]:
    """Structural checks independent of whatever produced `matrix`: the same
    role `generate-support-matrix-docs.py`'s `validate_matrix` plays for the
    docs projection, duplicated rather than imported -- every script in
    `scripts/` is a standalone gate."""
    errors: list[str] = []
    family_properties = schema["properties"]["families"]["items"]["properties"]
    vocabulary = family_properties["status"]["enum"]
    evidence_tiers = family_properties.get("evidenceTier", {}).get("enum", [])
    evidence_bases = family_properties.get("evidenceBasis", {}).get("enum", [])
    qualification_profiles = family_properties.get("qualificationProfile", {}).get("enum", [])
    families = matrix.get("families")
    if not isinstance(families, list):
        return [f"{label}: 'families' must be a list"]
    seen: set[str] = set()
    for entry in families:
        name = entry.get("family")
        if not name:
            errors.append(f"{label}: a family entry is missing 'family'")
            continue
        if name in seen:
            errors.append(f"{label}: duplicate family {name!r}")
        seen.add(name)
        status = entry.get("status")
        if status not in vocabulary:
            errors.append(f"{label}: {name}: status {status!r} is not in {vocabulary}")
        tier = entry.get("evidenceTier")
        basis = entry.get("evidenceBasis")
        profile = entry.get("qualificationProfile")
        current_contract = "stableDistribution" in matrix
        if current_contract or "evidenceBasis" in entry:
            if tier not in evidence_tiers:
                errors.append(f"{label}: {name}: evidence tier {tier!r} is not in {evidence_tiers}")
            if basis not in evidence_bases:
                errors.append(f"{label}: {name}: evidence basis {basis!r} is not in {evidence_bases}")
            if profile not in qualification_profiles:
                errors.append(
                    f"{label}: {name}: qualification profile {profile!r} is not in {qualification_profiles}"
                )
            if status == "stable" and profile is None:
                errors.append(f"{label}: {name}: stable carries no qualification profile")
            if status != "stable" and profile is not None:
                errors.append(f"{label}: {name}: {status!r} carries qualification profile {profile!r}")
            if profile == "documented" and (tier != "T1" or basis != "provider-documented"):
                errors.append(f"{label}: {name}: documented qualification is not T1 provider-documented")
            if profile == "empirical" and (tier != "T2" or basis != "empirically-observed"):
                errors.append(f"{label}: {name}: empirical qualification is not T2 empirically-observed")

    if "stableDistribution" in matrix:
        actual = {
            profile: sum(
                entry.get("status") == "stable" and entry.get("qualificationProfile") == profile
                for entry in families
            )
            for profile in ("documented", "empirical")
        }
        if matrix.get("stableDistribution") != actual:
            errors.append(
                f"{label}: stableDistribution {matrix.get('stableDistribution')} does not match {actual}"
            )
    return errors


def family_index(matrix: dict) -> dict[str, dict]:
    return {entry["family"]: entry for entry in matrix["families"]}


def regression_fingerprint(family: str, baseline_status: str, candidate_status: str, reason: str) -> str:
    return hashlib.sha256(f"{family}|{baseline_status}|{candidate_status}|{reason}".encode("utf-8")).hexdigest()[:16]


def build_drift(baseline: dict, candidate: dict) -> dict[str, list[dict]]:
    """Port of `buildSupportMatrixDrift`
    (`redact-secret-benchmarks`' `benchmarks/support/drift.ts`): walks the
    candidate's families only, so a family the candidate's own schema-valid
    matrix dropped entirely is out of scope, same as the TypeScript
    original.

    Raises `ValueError` when a family left `stable` with no `reason`
    recorded -- the same "fail loudly rather than default to a friendly
    status" property #509 already requires of the matrix generator itself.
    """
    baseline_by_family = family_index(baseline)
    regressions: list[dict] = []
    improvements: list[dict] = []
    new_and_unclassified: list[dict] = []
    stale_provider_provenance: list[dict] = []

    for entry in candidate["families"]:
        family = entry["family"]
        identity = {"provider": entry.get("provider"), "family": family, "familyName": entry["familyName"]}
        baseline_entry = baseline_by_family.get(family)
        if baseline_entry is None:
            new_and_unclassified.append({**identity, "status": entry["status"]})
            continue

        baseline_status = baseline_entry["status"]
        candidate_status = entry["status"]
        if baseline_status == "stable" and candidate_status != "stable":
            reason = entry.get("reason")
            if not reason:
                raise ValueError(f"{family} left stable with no reason recorded in the candidate matrix")
            regressions.append(
                {**identity, "baselineStatus": baseline_status, "candidateStatus": candidate_status, "reason": reason}
            )
        elif candidate_status == "stable" and baseline_status != "stable":
            improvements.append(
                {
                    **identity,
                    "baselineStatus": baseline_status,
                    "candidateStatus": "stable",
                    "evidence": {field: entry.get(field) for field in EVIDENCE_FIELDS},
                }
            )
        elif any(baseline_entry.get(field) != entry.get(field) for field in EVIDENCE_FIELDS):
            stale_provider_provenance.append(
                {
                    **identity,
                    "baselineStatus": baseline_status,
                    "candidateStatus": candidate_status,
                    "baselineProviderSource": baseline_entry.get("providerSource"),
                    "candidateProviderSource": entry.get("providerSource"),
                    "baselineEvidence": {field: baseline_entry.get(field) for field in EVIDENCE_FIELDS},
                    "candidateEvidence": {field: entry.get(field) for field in EVIDENCE_FIELDS},
                }
            )

    return {
        "regressions": regressions,
        "improvements": improvements,
        "newAndUnclassified": new_and_unclassified,
        "staleProviderProvenance": stale_provider_provenance,
    }


def load_acknowledgements(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def check_regressions(regressions: list[dict], acknowledgements: dict) -> list[str]:
    """Enforce issue #511 acceptance criterion 2. Returns a human-readable
    problem per unacknowledged or rationale-less regression -- empty when
    the run may pass."""
    problems: list[str] = []
    for regression in regressions:
        fingerprint = regression_fingerprint(
            regression["family"], regression["baselineStatus"], regression["candidateStatus"], regression["reason"]
        )
        entry = acknowledgements.get(fingerprint)
        location = (
            f"{regression['family']}: {regression['baselineStatus']} -> {regression['candidateStatus']} "
            f"({regression['reason']})"
        )
        if entry is None:
            problems.append(
                f"UNACKNOWLEDGED regression {fingerprint} ({location}): add it to "
                f"{ACKNOWLEDGEMENTS_PATH.relative_to(ROOT)}"
            )
        elif not entry.get("rationale"):
            problems.append(f"regression {fingerprint} ({location}) is acknowledged with no rationale recorded")
    return problems


def build_record(*, baseline: dict, candidate: dict, drift: dict[str, list[dict]]) -> dict:
    def source_report(matrix: dict) -> dict:
        report = matrix.get("sourceReport", {})
        return {"generatedAt": report.get("generatedAt"), "runId": report.get("runId"), "revision": report.get("revision")}

    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "taxonomySchemaVersion": candidate.get("taxonomySchemaVersion"),
        "familyCount": candidate.get("familyCount"),
        "baseline": source_report(baseline),
        "candidate": source_report(candidate),
        "summary": {key: len(drift[key]) for key in drift},
        **drift,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--baseline", required=True, type=Path, help="a previously saved support-matrix.json")
    parser.add_argument("--candidate", type=Path, default=CANDIDATE_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--acknowledgements", type=Path, default=ACKNOWLEDGEMENTS_PATH)
    parser.add_argument("--out", type=Path, default=None, help="write the full drift record as JSON")
    parser.add_argument(
        "--allow-dirty-candidate",
        action="store_true",
        help="skip the sourceReport.dirty rejection, for a local RC dry run",
    )
    args = parser.parse_args(argv)

    schema = load_json(args.schema)
    try:
        baseline = load_json(args.baseline)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR could not read --baseline {args.baseline}: {error}", file=sys.stderr)
        return 1
    try:
        candidate = load_json(args.candidate)
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR could not read --candidate {args.candidate}: {error}", file=sys.stderr)
        return 1

    errors = validate_matrix("baseline", baseline, schema) + validate_matrix("candidate", candidate, schema)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        print(f"\n{len(errors)} error(s) validating the support matrices", file=sys.stderr)
        return 1

    if candidate.get("sourceReport", {}).get("dirty") and not args.allow_dirty_candidate:
        print(
            "ERROR candidate matrix sourceReport.dirty is true: this is not reproducible "
            "published-artifact evidence (issue #508); pass --allow-dirty-candidate for a local dry run",
            file=sys.stderr,
        )
        return 1

    try:
        drift = build_drift(baseline, candidate)
    except ValueError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1

    record = build_record(baseline=baseline, candidate=candidate, drift=drift)

    # Written before `problems` is evaluated, the same as
    # `release-manifest.py`'s digest check: a run that fails this gate still
    # leaves a durable record of what it found.
    if args.out is not None:
        args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for entry in drift["staleProviderProvenance"]:
        print(
            f"WARNING stale evidence provenance for {entry['family']}: baseline and candidate "
            "evidence metadata disagree under an unchanged status",
            file=sys.stderr,
        )

    acknowledgements = load_acknowledgements(args.acknowledgements)
    problems = check_regressions(drift["regressions"], acknowledgements)
    if problems:
        for problem in problems:
            print(f"ERROR {problem}", file=sys.stderr)
        print(f"\n{len(problems)} unacknowledged support-matrix regression(s)", file=sys.stderr)
        return 1

    print(
        f"support-matrix drift: {len(drift['regressions'])} regression(s) (all acknowledged), "
        f"{len(drift['improvements'])} improvement(s), {len(drift['newAndUnclassified'])} new family/families, "
        f"{len(drift['staleProviderProvenance'])} stale provenance warning(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
