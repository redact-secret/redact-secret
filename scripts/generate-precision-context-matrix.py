#!/usr/bin/env python3
"""Publish the paired precision-regression matrix issue #375 asks for.

Issue #375's checkbox 7: "Publish a matrix keyed by fixture ID, contract/tier,
context, runtime and scan mode with before/after results and explicit
unsupported cells. No unexercised parity claims."

This script does not measure anything itself. It joins already-governed
sources for the seven frozen provider families
(`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`):

- ``conformance/fixtures/synchronous-corpus.json`` and
  ``conformance/fixtures/incremental-corpus.json`` -- one row per fixture:
  id, detector, ``kind``, ``tier``, ``support``, ``contexts``, scan mode, and
  whether ``expected`` is non-empty (``result``: ``flagged``/``silent``).
  This is the *current* (post-freeze) state, enforced by
  ``crates/secret-scan-core/tests/canonical_corpus.rs`` and
  ``crates/secret-scan-core/tests/incremental_partitions.rs`` -- a row here
  disagreeing with the real detector is a build failure, not a number this
  script could misreport. A row never claims a beta.4 "before": most rows
  (including every fixture issue #375 itself adds) postdate the freeze and
  never ran under beta.4 at all.
- ``docs/audits/evidence/367/beta4-twin-baseline.json`` -- the one source
  that *does* carry a real, measured "before": the 24 must-not-flag twins and
  their 24 paired positives from the beta.4 benchmark snapshot, each with
  ``actualBeta4`` (what beta.4's ranges actually were) alongside ``expected``
  (what the frozen contract requires now). Reported separately, as
  ``beta4TwinBaseline``, rather than force-joined onto the live corpus rows
  by id (the baseline's ids are audit-internal, not corpus fixture ids, so a
  guessed join would be exactly the kind of unexercised parity claim issue
  #375 rules out).
- The corpus files' own declared consumers
  (``conformance/README.md``: the Rust core and the Python binding assert
  the whole synchronous corpus; the Rust core and the JavaScript package
  qualification assert the whole incremental corpus) -- reported as
  ``runtimeConsumers`` per row's ``scanMode``, not claimed per-fixture beyond
  what those consumers actually run.

Every row is emitted, including ``support: "intentionally-unsupported"``
rows: the matrix states explicitly what is unsupported rather than omitting
it (``explicitlyUnsupportedFixtureIds``).

Never touches a fixture's ``input`` or a matched value: only ids, detector
ids, ``kind``/``tier``/``support``/``contexts``, whether ``expected`` is
empty, and the free-text ``note`` fields corpus authors already wrote as
safe metadata.

Output is deterministic: sorted detector names, sorted fixture ids within
each detector and scan mode, no timestamps.

    python3 -B scripts/generate-precision-context-matrix.py \\
        --out docs/coverage/precision-context-matrix.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC_PATH = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"
INCREMENTAL_PATH = ROOT / "conformance" / "fixtures" / "incremental-corpus.json"
BASELINE_PATH = ROOT / "docs" / "audits" / "evidence" / "367" / "beta4-twin-baseline.json"

ISSUE = "https://github.com/redact-secret/redact-secret/issues/375"

DEFAULT_DETECTORS = (
    "openai-token",
    "digitalocean-token",
    "docker-token",
    "slack-token",
    "huggingface-token",
    "cloudflare-token",
    "linear-token",
)

# What conformance/README.md documents as asserting the *whole* corpus file,
# per scan mode. Not a claim about any other qualification surface
# (node-addon / browser-wasm / cli replay the synchronous corpus as a build
# artifact, not fixture-by-fixture through this same harness).
RUNTIME_CONSUMERS = {
    "synchronous": ["rust-core", "python-binding"],
    "incremental": ["rust-core", "javascript-package-consumer"],
}

ENFORCED_BY = {
    "synchronous": (
        "crates/secret-scan-core/tests/canonical_corpus.rs"
        "::scan_matches_the_canonical_synchronous_corpus"
    ),
    "incremental": (
        "crates/secret-scan-core/tests/incremental_partitions.rs"
        "::every_fixture_reproduces_the_canonical_whole_input_reference"
    ),
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def synchronous_row(fixture: dict) -> dict:
    result = "flagged" if fixture.get("expected") else "silent"
    return {
        "fixtureId": fixture["id"],
        "detector": fixture["detector"],
        "scanMode": "synchronous",
        "kind": fixture["kind"],
        "contractTier": fixture["tier"],
        "support": fixture["support"],
        "contexts": list(fixture["contexts"]),
        "result": result,
        "findingCount": len(fixture["expected"]) if fixture.get("expected") else 0,
        "runtimeConsumers": RUNTIME_CONSUMERS["synchronous"],
        "enforcedBy": ENFORCED_BY["synchronous"],
        "note": fixture["note"],
    }


def incremental_row(fixture: dict, detector: str) -> dict:
    result = "flagged" if fixture.get("expected") else "silent"
    return {
        "fixtureId": fixture["id"],
        "detector": detector,
        "scanMode": "incremental",
        "kind": None,
        "contractTier": None,
        "support": None,
        "contexts": [],
        "result": result,
        "findingCount": len(fixture["expected"]),
        "runtimeConsumers": RUNTIME_CONSUMERS["incremental"],
        "enforcedBy": ENFORCED_BY["incremental"],
        "note": fixture["note"],
    }


def beta4_twin_baseline_rows(baseline: dict, detectors: list[str]) -> list[dict]:
    """The one genuine, measured before/after in this repo: beta.4's actual
    ranges (`actualBeta4`) versus the frozen contract's `expected`, for the
    24 must-not-flag twins and their 24 paired positives."""
    rows = []
    for pair in baseline.get("pairs", []):
        if pair["family"] not in detectors:
            continue
        for side in ("negative", "positive"):
            leaf = pair[side]
            rows.append({
                "auditId": leaf["id"],
                "detector": pair["family"],
                "variant": pair["variant"],
                "context": pair["context"],
                "side": side,
                "mutation": pair["mutation"],
                "beforeResult": "flagged" if leaf["actualBeta4"] else "silent",
                "afterResult": "flagged" if leaf["expected"] else "silent",
                "contractView": pair["contractView"],
            })
    rows.sort(key=lambda r: (r["detector"], r["variant"], r["side"], r["auditId"]))
    return rows


def build_matrix(
    sync_corpus: dict, incremental_corpus: dict, baseline: dict, detectors: list[str]
) -> dict:
    sync_fixtures = [f for f in sync_corpus["fixtures"] if f["detector"] in detectors]
    known = {f["detector"] for f in sync_corpus["fixtures"]}
    missing = sorted(set(detectors) - known)
    if missing:
        raise ValueError(f"detector(s) not present in the synchronous corpus: {missing}")

    rows = [synchronous_row(f) for f in sync_fixtures]

    # An incremental fixture carries no `detector` field of its own -- it is
    # keyed by id prefix instead, matching this repo's own naming convention
    # (e.g. "openai-*", "slack-*"). Attribute it to the one target detector
    # whose id prefix it starts with; a fixture matching none of them is out
    # of scope for this matrix.
    prefix_by_detector = {d: d.split("-")[0] for d in detectors}
    for fixture in incremental_corpus["fixtures"]:
        for detector, prefix in prefix_by_detector.items():
            if fixture["id"].startswith(prefix):
                rows.append(incremental_row(fixture, detector))
                break

    rows.sort(key=lambda r: (r["detector"], r["scanMode"], r["fixtureId"]))

    unsupported = [r["fixtureId"] for r in rows if r["support"] == "intentionally-unsupported"]

    return {
        "provenance": {
            "issue": ISSUE,
            "synchronousCorpus": "conformance/fixtures/synchronous-corpus.json",
            "incrementalCorpus": "conformance/fixtures/incremental-corpus.json",
            "beta4TwinBaselineSource": "docs/audits/evidence/367/beta4-twin-baseline.json",
        },
        "detectors": sorted(detectors),
        "rowCount": len(rows),
        "explicitlyUnsupportedFixtureIds": sorted(unsupported),
        "rows": rows,
        "beta4TwinBaseline": beta4_twin_baseline_rows(baseline, detectors),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--sync-corpus", type=Path, default=SYNC_PATH)
    parser.add_argument("--incremental-corpus", type=Path, default=INCREMENTAL_PATH)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument(
        "--detector",
        dest="detectors",
        action="append",
        help="detector id to include; may be repeated (default: the seven issue #367 families)",
    )
    parser.add_argument("--out", type=Path, default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    detectors = args.detectors or list(DEFAULT_DETECTORS)
    matrix = build_matrix(
        load_json(args.sync_corpus),
        load_json(args.incremental_corpus),
        load_json(args.baseline),
        detectors,
    )
    text = json.dumps(matrix, indent=2, sort_keys=True) + "\n"

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
