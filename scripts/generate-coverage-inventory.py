#!/usr/bin/env python3
"""Generate the deterministic detector/finding-type/policy/consumer baseline.

Issue #101 (tracking-key ``dacd-f1-t1``) asks for one inventory row per
built-in detector and emitted finding type, each classified as
``supported``, ``intentionally-unsupported``, ``not-applicable``, or
``unresolved``, without treating a raw fixture count as sufficient coverage
evidence.

This script joins three inputs:

1. ``docs/coverage/detector-inventory.json`` -- the hand-authored declared
   baseline (detector, finding type, default-policy class, and accepted
   schemes), reconciled against the real registry and ``DefaultPolicy`` by
   ``crates/secret-scan-core/src/detectors/mod.rs::tests::built_in_inventory_matches_the_declared_baseline``.
2. ``conformance/fixtures/synchronous-corpus.json`` -- the canonical corpus,
   for evidence dimensions (fixture ``kind``, ``support``, and host
   ``contexts``) per detector and, where declared, per scheme.
3. The declared runtime consumers -- the test files that actually exercise
   the corpus, verified to exist on disk.

A row's state is derived, never asserted: ``supported`` requires at least
one ``kind: "positive"``, ``support: "supported"`` fixture whose expectations
name the row's finding type (or scheme); ``intentionally-unsupported``
requires no such positive fixture but at least one fixture explicitly
declaring ``support: "intentionally-unsupported"``; anything else is
``unresolved``, which is the honest default for a reachable type with no
evidence -- not an error. ``not-applicable`` marks the scheme dimension for a
finding type that has no accepted-scheme concept at all.

The script's own exit code reflects only structural drift -- a declared
detector absent from the corpus, a corpus detector absent from the
declaration, or a declared consumer path that no longer exists -- never
substantive coverage gaps. Reporting an ``unresolved`` row is success: that is
the baseline doing its job. Making coverage drift a CI failure is a separate,
later concern (issue #104).

Output is deterministic: sorted keys, no timestamps, no fixture ``input`` or
matched values -- only fixture ids, detector ids, finding types, schemes, and
free-text ``note`` fields the corpus authors already wrote as safe metadata.

    python3 -B scripts/generate-coverage-inventory.py --out docs/coverage/inventory-report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
CORPUS_PATH = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"

ROW_STATES = ("supported", "intentionally-unsupported", "not-applicable", "unresolved")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fixtures_for_detector(fixtures: list[dict], detector: str) -> list[dict]:
    return [fixture for fixture in fixtures if fixture.get("detector") == detector]


def _mentions(fixture: dict, needle: str) -> bool:
    haystack = f"{fixture.get('id', '')} {fixture.get('note', '')}".lower()
    return needle.lower() in haystack


def _has_expected_type(fixture: dict, type_name: str) -> bool:
    return any(expectation.get("type") == type_name for expectation in (fixture.get("expected") or []))


def row_state(
    detector_fixtures: list[dict],
    type_name: str,
    *,
    scheme: str | None = None,
    ambiguous_keyword: str | None = None,
) -> tuple[str, list[str]]:
    """The state and supporting fixture ids for one type or scheme row.

    A detector's ``intentionally-unsupported`` fixtures carry no ``expected``
    list, so a type row cannot check them against ``expected[].type`` the way
    a positive row can. For a detector declaring more than one finding type
    (only ``generic-token`` today), that fixture-to-type link is instead
    approximated with ``ambiguous_keyword`` -- the type's own leading word
    (``contextual`` for ``contextual_secret``, ``authorization`` for
    ``authorization_credential``) -- so one type's justified gap cannot
    silently paper over another's unjustified one.
    """

    def matches(fixture: dict, keyword: str | None) -> bool:
        return keyword is None or _mentions(fixture, keyword)

    positive_supported = sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("kind") == "positive"
        and fixture.get("support") == "supported"
        and _has_expected_type(fixture, type_name)
        and matches(fixture, scheme)
    )
    if positive_supported:
        return "supported", positive_supported

    intentionally_unsupported = sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("support") == "intentionally-unsupported"
        and matches(fixture, scheme)
        and matches(fixture, ambiguous_keyword)
    )
    if intentionally_unsupported:
        return "intentionally-unsupported", intentionally_unsupported

    return "unresolved", []


def evidence_dimensions(detector_fixtures: list[dict]) -> dict:
    return {
        "fixtureCount": len(detector_fixtures),
        "kindsWithSupportedEvidence": sorted(
            {fixture["kind"] for fixture in detector_fixtures if fixture.get("support") == "supported"}
        ),
        "supportStatesPresent": sorted({fixture["support"] for fixture in detector_fixtures if "support" in fixture}),
        "hostContextsExercised": sorted(
            {context for fixture in detector_fixtures for context in fixture.get("contexts", [])}
        ),
    }


def build_report(manifest: dict, corpus: dict, root: Path) -> dict:
    fixtures = corpus["fixtures"]
    declared_detectors = sorted({entry["detector"] for entry in manifest["types"]})
    corpus_detectors = sorted({fixture["detector"] for fixture in fixtures if fixture.get("detector") != "unassigned"})
    types_per_detector: dict[str, int] = {}
    for entry in manifest["types"]:
        types_per_detector[entry["detector"]] = types_per_detector.get(entry["detector"], 0) + 1

    rows = []
    for entry in manifest["types"]:
        detector = entry["detector"]
        type_name = entry["type"]
        detector_fixtures = fixtures_for_detector(fixtures, detector)
        ambiguous_keyword = type_name.split("_")[0] if types_per_detector[detector] > 1 else None
        state, evidence_ids = row_state(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)

        schemes = entry.get("schemes")
        if schemes:
            scheme_rows: list[dict] | str = [
                {
                    "scheme": scheme,
                    **dict(
                        zip(
                            ("state", "evidenceFixtureIds"),
                            row_state(
                                detector_fixtures,
                                type_name,
                                scheme=scheme,
                                ambiguous_keyword=ambiguous_keyword,
                            ),
                        )
                    ),
                }
                for scheme in schemes
            ]
        else:
            scheme_rows = "not-applicable"

        rows.append(
            {
                "type": type_name,
                "detector": detector,
                "policyClass": entry["policyClass"],
                "state": state,
                "evidenceFixtureIds": evidence_ids,
                "evidence": evidence_dimensions(detector_fixtures),
                "schemeRows": scheme_rows,
            }
        )

    consumers = [
        {
            "path": consumer["path"],
            "role": consumer["role"],
            "exists": (root / consumer["path"]).is_file(),
        }
        for consumer in manifest["consumers"]
    ]

    summary = {state: sum(1 for row in rows if row["state"] == state) for state in ROW_STATES}

    return {
        "rowStates": list(ROW_STATES),
        "rows": rows,
        "reconciliation": {
            "declaredDetectorsMissingFromCorpus": sorted(set(declared_detectors) - set(corpus_detectors)),
            "corpusDetectorsMissingFromDeclaration": sorted(set(corpus_detectors) - set(declared_detectors)),
        },
        "consumers": consumers,
        "summary": summary,
    }


def structural_errors(report: dict) -> list[str]:
    """Drift a reviewer must fix before this baseline can be trusted.

    Deliberately excludes ``unresolved`` rows: those are honest, reportable
    coverage gaps (see the module docstring), not a malformed join.
    """
    errors = []
    for name in ("declaredDetectorsMissingFromCorpus", "corpusDetectorsMissingFromDeclaration"):
        for detector in report["reconciliation"][name]:
            errors.append(f"{name}: {detector}")
    for consumer in report["consumers"]:
        if not consumer["exists"]:
            errors.append(f"declared consumer no longer exists: {consumer['path']}")
    for row in report["rows"]:
        if row["state"] not in ROW_STATES:
            errors.append(f"{row['type']}: invalid row state {row['state']!r}")
        if row["schemeRows"] != "not-applicable":
            for scheme_row in row["schemeRows"]:
                if scheme_row["state"] not in ROW_STATES:
                    errors.append(f"{row['type']}/{scheme_row['scheme']}: invalid row state {scheme_row['state']!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    manifest = load_json(args.manifest)
    corpus = load_json(args.corpus)
    report = build_report(manifest, corpus, args.root)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    errors = structural_errors(report)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"\n{len(errors)} structural error(s); the baseline is out of sync", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
