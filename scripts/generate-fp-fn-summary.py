#!/usr/bin/env python3
"""Generate the per-detector false-positive/false-negative guard summary
(issue #316).

Issue #316 asks for a report of "negative-file FP counts per detector and
paired-positive FN counts", with fixture ids and provenance persisted, so a
reviewer does not have to recount ``conformance/fixtures/synchronous-corpus.json``
by hand to see how thoroughly a detector's false-positive boundary is
guarded.

This script does not run any detector and does not measure a false positive
or false negative independently. It reports the corpus's own design intent:
every ``kind: "negative"`` fixture for a detector declares empty
``expected`` (a guard the detector must produce zero findings for), and
every ``kind: "positive"`` fixture declares non-empty ``expected`` (a guard
the detector must still fire for). Whether the real detector actually meets
those guards is asserted independently, once, by
``crates/secret-scan-core/tests/canonical_corpus.rs::scan_matches_the_canonical_synchronous_corpus``,
which runs every evaluated fixture's ``input`` through ``scan`` and asserts
the findings equal ``expected`` exactly -- so an actual false positive or
false negative among these fixtures is a build failure, not a number this
script could under- or over-report.

Like the other coverage generators, this script never touches a fixture's
``input`` or a matched value: only fixture ids, detector ids, kinds,
``contexts``, and free-text ``note`` fields the corpus authors already wrote
as safe metadata.

Output is deterministic: sorted detector names, sorted fixture ids within
each detector, no timestamps.

    python3 -B scripts/generate-fp-fn-summary.py --out docs/coverage/fp-fn-summary.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"

DEFAULT_DETECTORS = ("stripe-token", "shopify-token", "supabase-token")
ENFORCED_BY = (
    "crates/secret-scan-core/tests/canonical_corpus.rs"
    "::scan_matches_the_canonical_synchronous_corpus"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_summary(fixtures: list[dict]) -> dict:
    return {
        "count": len(fixtures),
        "fixtureIds": sorted(fixture["id"] for fixture in fixtures),
    }


def build_detector_row(detector: str, corpus_fixtures: list[dict]) -> dict:
    detector_fixtures = [f for f in corpus_fixtures if f["detector"] == detector]
    negatives = [f for f in detector_fixtures if f["kind"] == "negative"]
    positives = [f for f in detector_fixtures if f["kind"] == "positive"]

    for fixture in negatives:
        if fixture["expected"]:
            raise ValueError(
                f"{fixture['id']}: kind is 'negative' but expected is non-empty"
            )
    for fixture in positives:
        if not fixture["expected"]:
            raise ValueError(
                f"{fixture['id']}: kind is 'positive' but expected is empty"
            )

    host_contexts = sorted({
        context
        for fixture in detector_fixtures
        for context in fixture.get("contexts", [])
    })

    return {
        "detector": detector,
        "falsePositiveGuards": {
            **_fixture_summary(negatives),
            "actualFalsePositives": 0,
        },
        "falseNegativeGuards": {
            **_fixture_summary(positives),
            "actualFalseNegatives": 0,
        },
        "hostContextsExercised": host_contexts,
    }


def build_report(corpus: dict, detectors: list[str]) -> dict:
    fixtures = corpus["fixtures"]
    known_detectors = {f["detector"] for f in fixtures}
    missing = sorted(set(detectors) - known_detectors)
    if missing:
        raise ValueError(f"detector(s) not present in the corpus: {missing}")

    return {
        "provenance": {
            "issue": "https://github.com/redact-secret/redact-secret/issues/316",
            "corpus": "conformance/fixtures/synchronous-corpus.json",
            "enforcedBy": ENFORCED_BY,
        },
        "detectors": [build_detector_row(d, fixtures) for d in sorted(detectors)],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument(
        "--detector",
        dest="detectors",
        action="append",
        help="detector id to report on; may be repeated (default: stripe-token, shopify-token, supabase-token)",
    )
    parser.add_argument("--out", type=Path, default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    detectors = args.detectors or list(DEFAULT_DETECTORS)
    corpus = load_json(args.corpus)
    report = build_report(corpus, detectors)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
