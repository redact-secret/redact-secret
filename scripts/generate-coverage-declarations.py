#!/usr/bin/env python3
"""Generate the canonical coverage-declaration corpus (issue #103, tracking-key
``dacd-f1-t3``).

``docs/coverage/evidence-requirements.md`` (issue #102) defines five behavior
classes, nine evidence dimensions, a requirement matrix, and four bounded
exception codes -- a model stated in prose over vocabulary the corpus and
``docs/coverage/detector-inventory.json`` already carry. This script encodes
that model as data: one ``CanonicalCoverageDeclaration`` row per declared
finding type, the cross-cutting ``incremental`` surface, and each declared
runtime consumer, every dimension resolved to ``supported``,
``not-applicable``, or ``pending`` -- never asserted, always derived from real
corpus evidence (a fixture's ``kind``, ``support``, ``tier``, and ``contexts``)
or a bounded exception citing another row's evidence.

The output validates against ``conformance/schema.ts``'s
``validateCanonicalCoverageDeclarations``, which rejects an unknown detector
or type, a row missing a dimension its behavior class requires, a stale
evidence id, a contradictory state/exception pairing, and an exception whose
reference does not resolve. Running this script twice over the same inputs
produces byte-identical output (sorted keys, no timestamps); that determinism
is how the existing canonical fixture files "migrate" into this schema
without hand-authored duplication that could drift from them.

Output carries no fixture ``input`` and no matched value -- only fixture ids,
detector ids, finding types, consumer paths, and the free-text ``note``
fields the corpus and baseline already carry as safe metadata.

    python3 -B scripts/generate-coverage-declarations.py --out docs/coverage/coverage-declarations.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs" / "coverage" / "detector-inventory.json"
CORPUS_PATH = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"
INCREMENTAL_CORPUS_PATH = ROOT / "conformance" / "fixtures" / "incremental-corpus.json"
LIFECYCLE_CORPUS_PATH = ROOT / "conformance" / "fixtures" / "incremental-lifecycle-corpus.json"
UNICODE_CORPUS_PATH = ROOT / "conformance" / "fixtures" / "unicode-conversion-corpus.json"
ERROR_CODES_PATH = ROOT / "conformance" / "fixtures" / "error-codes.json"

_INVENTORY_SPEC = importlib.util.spec_from_file_location(
    "generate_coverage_inventory",
    Path(__file__).resolve().parent / "generate-coverage-inventory.py",
)
assert _INVENTORY_SPEC and _INVENTORY_SPEC.loader
INVENTORY = importlib.util.module_from_spec(_INVENTORY_SPEC)
sys.modules[_INVENTORY_SPEC.name] = INVENTORY
_INVENTORY_SPEC.loader.exec_module(INVENTORY)

# evidence-requirements.md §1: the fixed partition of the 22 declared types
# into behavior classes. Every type not listed here is "provider" (16 of 22).
STRUCTURAL_TYPES = {
    "private_key",
    "jwt",
    "bearer_token",
    "connection_string_password",
    "otpauth_secret",
}
CONTEXTUAL_TYPES = {"contextual_secret", "authorization_credential"}

# evidence-requirements.md §3: the 22 CanonicalHostContext values partitioned
# into five representative lexical classes.
REPRESENTATIVE_CLASSES = {
    "structured-data-kv": {"dotenv", "json", "yaml", "toml"},
    "shell-invocation": {
        "shell",
        "powershell",
        "docker-compose",
        "github-actions",
        "terraform",
        "kubernetes",
    },
    "source-code": {"javascript", "typescript", "python"},
    "wire-and-log": {"http", "curl", "log", "terminal", "stack-trace"},
    "prose-and-markup": {"chat", "markdown", "xml", "plain-text"},
}

KIND_BY_DIMENSION = {
    "positive": "positive",
    "overlap": "overlap",
    "adversarial": "adversarial",
}
# evidence-requirements.md §2 states no support-state qualifier for the
# "boundary" dimension -- an intentionally-unsupported fixture at the edge of
# a detector's own grammar (a rejected mutation, a below-minimum length) is
# itself the evidence, not a gap. The corpus bears this out: every declared
# type's `kind: "boundary"` fixtures are `support: "intentionally-unsupported"`
# (the accepted form lives in the `positive` fixtures instead).
BOUNDARY_SUPPORT_STATES = {"supported", "intentionally-unsupported"}
MALFORMED_SUPPORT_STATES = {"supported", "intentionally-unsupported"}

INCREMENTAL_CONSUMER_PATHS = {
    "crates/secret-scan-core/tests/incremental_partitions.rs",
    "bindings/python/tests/test_incremental.py",
}
ADVERSARIAL_OWNER_PATH = "crates/secret-scan-core/tests/adversarial_bounds.rs"


def slug(text_value: str) -> str:
    """A CASE_ID_PATTERN-safe kebab-case slug (schema.ts's
    ``CASE_ID_PATTERN``): the repo's own type/detector identifiers are
    snake_case, so a newly-named backlog id built from one must not
    carry the underscore through."""
    return text_value.replace("_", "-")


def behavior_class_for(type_name: str) -> str:
    if type_name in STRUCTURAL_TYPES:
        return "structural"
    if type_name in CONTEXTUAL_TYPES:
        return "contextual"
    return "provider"


def _type_matches(fixture: dict, type_name: str, ambiguous_keyword: str | None) -> bool:
    if fixture.get("expected"):
        return INVENTORY._has_expected_type(fixture, type_name)
    return ambiguous_keyword is None or INVENTORY._mentions(fixture, ambiguous_keyword)


def kind_evidence(
    detector_fixtures: list[dict],
    type_name: str,
    kind: str,
    *,
    ambiguous_keyword: str | None,
    support_states: set[str] = frozenset({"supported"}),
) -> list[str]:
    return sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("kind") == kind
        and fixture.get("support") in support_states
        and _type_matches(fixture, type_name, ambiguous_keyword)
    )


def boundary_evidence(detector_fixtures: list[dict], type_name: str, *, ambiguous_keyword: str | None) -> list[str]:
    return kind_evidence(
        detector_fixtures,
        type_name,
        "boundary",
        ambiguous_keyword=ambiguous_keyword,
        support_states=BOUNDARY_SUPPORT_STATES,
    )


def malformed_evidence(detector_fixtures: list[dict], type_name: str, *, ambiguous_keyword: str | None) -> list[str]:
    return sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("tier") == "malformed"
        and fixture.get("support") in MALFORMED_SUPPORT_STATES
        and _type_matches(fixture, type_name, ambiguous_keyword)
    )


def near_miss_negative_evidence(
    detector_fixtures: list[dict], type_name: str, *, ambiguous_keyword: str | None
) -> list[str]:
    direct = kind_evidence(detector_fixtures, type_name, "negative", ambiguous_keyword=ambiguous_keyword)
    if direct:
        return direct
    return sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("support") == "intentionally-unsupported"
        and (ambiguous_keyword is None or INVENTORY._mentions(fixture, ambiguous_keyword))
    )


def own_contexts(detector_fixtures: list[dict], type_name: str, *, ambiguous_keyword: str | None) -> set[str]:
    contexts: set[str] = set()
    for fixture in detector_fixtures:
        if fixture.get("support") != "supported":
            continue
        if not _type_matches(fixture, type_name, ambiguous_keyword):
            continue
        contexts.update(fixture.get("contexts", []))
    return contexts


def representative_buckets(contexts: set[str]) -> set[str]:
    return {name for name, values in REPRESENTATIVE_CLASSES.items() if contexts & values}


def host_context_fixture_ids(
    detector_fixtures: list[dict], type_name: str, *, ambiguous_keyword: str | None
) -> list[str]:
    return sorted(
        fixture["id"]
        for fixture in detector_fixtures
        if fixture.get("support") == "supported"
        and _type_matches(fixture, type_name, ambiguous_keyword)
        and fixture.get("contexts")
    )


def supported(evidence_fixture_ids: list[str], *, class_level: bool = False) -> dict:
    row = {"state": "supported", "evidenceFixtureIds": evidence_fixture_ids}
    if class_level:
        row["classLevel"] = True
    return row


def supported_via(code: str, *, class_level: bool = False, **fields: str) -> dict:
    row = {
        "state": "supported",
        "evidenceFixtureIds": [],
        "exception": {"code": code, **fields},
    }
    if class_level:
        row["classLevel"] = True
    return row


def not_applicable() -> dict:
    return {
        "state": "not-applicable",
        "evidenceFixtureIds": [],
        "exception": {"code": "no-concept"},
    }


def pending(backlog_id: str) -> dict:
    return {
        "state": "pending",
        "evidenceFixtureIds": [],
        "exception": {"code": "pending", "backlogId": backlog_id},
    }


def dim(name: str, resolution: dict) -> dict:
    return {"dimension": name, **resolution}


def build_type_row(
    entry: dict,
    fixtures: list[dict],
    *,
    ambiguous_keyword: str | None,
    unicode_ids: list[str],
    representative_owner: str | None,
) -> dict:
    type_name = entry["type"]
    detector = entry["detector"]
    detector_fixtures = INVENTORY.fixtures_for_detector(fixtures, detector)
    behavior_class = behavior_class_for(type_name)

    dimensions = []
    for dimension_name, kind in KIND_BY_DIMENSION.items():
        ids = kind_evidence(detector_fixtures, type_name, kind, ambiguous_keyword=ambiguous_keyword)
        dimensions.append(
            dim(dimension_name, supported(ids) if ids else pending(f"{slug(type_name)}-{dimension_name}"))
        )

    boundary_ids = boundary_evidence(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)
    dimensions.append(
        dim("boundary", supported(boundary_ids) if boundary_ids else pending(f"{slug(type_name)}-boundary"))
    )

    near_miss_ids = near_miss_negative_evidence(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)
    dimensions.append(
        dim(
            "near-miss-negative",
            supported(near_miss_ids) if near_miss_ids else pending(f"{slug(type_name)}-near-miss-negative"),
        )
    )

    malformed_ids = malformed_evidence(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)
    dimensions.append(
        dim("malformed", supported(malformed_ids) if malformed_ids else pending(f"{slug(type_name)}-malformed"))
    )

    contexts = own_contexts(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)
    buckets = representative_buckets(contexts)
    if behavior_class == "contextual":
        # §3: host-context is required at the type level for contextual rows.
        host_context = (
            supported(host_context_fixture_ids(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword))
            if len(buckets) == len(REPRESENTATIVE_CLASSES)
            else pending(f"{slug(type_name)}-host-context-breadth")
        )
    elif representative_owner is None:
        # No member of this class reaches all five representative lexical
        # classes on its own evidence -- a real, currently-unmet class-level
        # gap, not one this generator papers over with invented context
        # fixtures (evidence-requirements.md §5-6).
        host_context = pending(f"{behavior_class}-host-context-breadth")
    elif representative_owner == type_name:
        host_context = supported(
            host_context_fixture_ids(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword),
            class_level=True,
        )
    else:
        host_context = supported_via(
            "owned-elsewhere", ownedBy=f"{representative_owner}:host-context", class_level=True
        )
    dimensions.append(dim("host-context", host_context))

    # §4: range is "○" (class-level) for provider/structural/contextual --
    # astral-neighbor stress is a cross-cutting corpus property, evidenced
    # once by the shared Unicode conversion corpus rather than per type.
    dimensions.append(dim("range", supported(unicode_ids, class_level=True)))

    return {
        "type": type_name,
        "detector": detector,
        "behaviorClass": behavior_class,
        "dimensions": dimensions,
        "note": entry.get(
            "note",
            f"Coverage declaration for {type_name} ({detector}), derived from "
            "synchronous-corpus.json per evidence-requirements.md's requirement matrix.",
        ),
    }


#  evidence-requirements.md §5's own example limits `single-detector-family`
#  reuse to behavioral-robustness dimensions a shared detector demonstrates
#  regardless of which type triggered it (adversarial caps and malformed-input
#  survival). `positive`, `near-miss-negative`, `boundary`, `overlap`, and
#  `host-context` are type-identity claims -- including which type wins a
#  candidate conflict -- that a sibling's evidence cannot stand in for without
#  inventing a supported state the corpus does not back (see
#  `apply_known_exceptions` for how those instead resolve honestly).
SHAREABLE_DIMENSIONS = {"malformed", "adversarial"}


def resolve_shared_family(rows_by_type: dict[str, dict], type_names: list[str]) -> None:
    """For a detector shared by more than one declared type (only
    ``generic-token`` today), a shareable dimension with no evidence of its
    own but a sibling type's direct evidence resolves via
    ``single-detector-family`` rather than an invented ``pending`` gap
    (evidence-requirements.md §5)."""
    for type_name in type_names:
        row = rows_by_type[type_name]
        siblings = [other for other in type_names if other != type_name]
        for dimension in row["dimensions"]:
            if dimension["state"] != "pending" or dimension["dimension"] not in SHAREABLE_DIMENSIONS:
                continue
            for sibling_name in siblings:
                sibling_dim = next(
                    d for d in rows_by_type[sibling_name]["dimensions"] if d["dimension"] == dimension["dimension"]
                )
                if sibling_dim["state"] == "supported" and "exception" not in sibling_dim:
                    dimension["state"] = "supported"
                    dimension["evidenceFixtureIds"] = []
                    dimension["exception"] = {
                        "code": "single-detector-family",
                        "sharedWith": sibling_name,
                    }
                    break


def apply_known_exceptions(rows_by_type: dict[str, dict]) -> None:
    """``C/F-03`` in ``docs/audits/deferred-quality-backlog.md`` names exactly
    two dimensions of ``authorization_credential``'s gap: at least one
    supported positive fixture per accepted scheme, plus one boundary
    fixture pinning ``MIN_AUTHORIZATION_VALUE_LENGTH``. Issue #105 closed
    that pair (and, alongside it, the near-miss-negative dimension issue
    #105's own acceptance criteria bundled with boundary). Any dimension
    still pending after that -- currently ``host-context`` -- is a real,
    separately-unmet gap the requirement matrix names but ``C/F-03`` never
    claimed to cover, so it is left to fall through to its own generated
    backlog slug rather than borrowing a closed finding's name."""
    auth = rows_by_type.get("authorization_credential")
    if auth is not None:
        for dimension in auth["dimensions"]:
            if dimension["dimension"] in ("positive", "boundary", "near-miss-negative"):
                if dimension["state"] == "pending":
                    dimension["exception"]["backlogId"] = "C/F-03"


def build_incremental_row(
    incremental_fixtures: list[dict],
    lifecycle_fixtures: list[dict],
    unicode_ids: list[str],
    synchronous_fixtures: list[dict],
) -> dict:
    malformed_ids = sorted(
        fixture["id"]
        for fixture in lifecycle_fixtures
        if any(op.get("op") == "appendBytesHex" for op in fixture.get("operations", []))
    )
    incremental_ids = sorted(fixture["id"] for fixture in incremental_fixtures)
    synchronous_adversarial_ids = sorted(
        fixture["id"]
        for fixture in synchronous_fixtures
        if fixture.get("kind") == "adversarial" and fixture.get("support") == "supported"
    )
    return {
        "type": "incremental",
        "detector": "unassigned",
        "behaviorClass": "incremental",
        "dimensions": [
            dim("malformed", supported(malformed_ids)),
            dim("range", supported(unicode_ids)),
            dim("incremental", supported(incremental_ids)),
            dim("adversarial", supported(synchronous_adversarial_ids)),
        ],
        "note": (
            "Cross-cutting incremental/stream surface: partition invariance, "
            "malformed-UTF-8 survival, and resource caps, reused from the "
            "whole-input synchronous corpus per evidence-requirements.md §4."
        ),
    }


def build_binding_edge_rows(
    consumers: list[dict],
    error_codes: list[dict],
    unicode_ids: list[str],
    incremental_ids: list[str],
    synchronous_adversarial_ids: list[str],
) -> list[dict]:
    error_code_ids = sorted(code["code"] for code in error_codes)
    rows = []
    for consumer in consumers:
        path = consumer["path"]
        dimensions = [
            dim("malformed", supported(error_code_ids)),
            dim("range", supported(unicode_ids)),
        ]
        if path in INCREMENTAL_CONSUMER_PATHS:
            dimensions.append(dim("incremental", supported(incremental_ids)))
        else:
            dimensions.append(dim("incremental", not_applicable()))
        if path == ADVERSARIAL_OWNER_PATH:
            dimensions.append(dim("adversarial", supported(synchronous_adversarial_ids)))
        else:
            dimensions.append(
                dim("adversarial", supported_via("owned-elsewhere", ownedBy=f"{ADVERSARIAL_OWNER_PATH}:adversarial"))
            )
        rows.append(
            {
                "type": path,
                "detector": "unassigned",
                "behaviorClass": "binding-edge",
                "dimensions": dimensions,
                "note": consumer["role"],
            }
        )
    return rows


def build_declarations(
    manifest: dict,
    corpus: dict,
    incremental_corpus: dict,
    lifecycle_corpus: dict,
    unicode_corpus: dict,
    error_codes_doc: dict,
) -> dict:
    fixtures = corpus["fixtures"]
    unicode_ids = sorted(fixture["id"] for fixture in unicode_corpus["fixtures"])

    types_per_detector: dict[str, int] = {}
    for entry in manifest["types"]:
        types_per_detector[entry["detector"]] = types_per_detector.get(entry["detector"], 0) + 1

    rows_by_type: dict[str, dict] = {}
    shared_detector_types: dict[str, list[str]] = {}
    representative_owner_by_class: dict[str, str | None] = {"provider": None, "structural": None}

    # Pass 1: pick each class's representative (the member whose own context
    # breadth already covers all five lexical classes, §3) before building
    # rows, so every other member can point at it directly.
    for entry in manifest["types"]:
        type_name = entry["type"]
        behavior_class = behavior_class_for(type_name)
        if behavior_class not in representative_owner_by_class:
            continue
        detector_fixtures = INVENTORY.fixtures_for_detector(fixtures, entry["detector"])
        ambiguous_keyword = type_name.split("_")[0] if types_per_detector[entry["detector"]] > 1 else None
        contexts = own_contexts(detector_fixtures, type_name, ambiguous_keyword=ambiguous_keyword)
        if representative_owner_by_class[behavior_class] is None and len(representative_buckets(contexts)) == len(
            REPRESENTATIVE_CLASSES
        ):
            representative_owner_by_class[behavior_class] = type_name

    for entry in manifest["types"]:
        type_name = entry["type"]
        detector = entry["detector"]
        behavior_class = behavior_class_for(type_name)
        ambiguous_keyword = type_name.split("_")[0] if types_per_detector[detector] > 1 else None
        owner = representative_owner_by_class.get(behavior_class)
        row = build_type_row(
            entry,
            fixtures,
            ambiguous_keyword=ambiguous_keyword,
            unicode_ids=unicode_ids,
            representative_owner=owner,
        )
        rows_by_type[type_name] = row
        if types_per_detector[detector] > 1:
            shared_detector_types.setdefault(detector, []).append(type_name)

    for type_names in shared_detector_types.values():
        resolve_shared_family(rows_by_type, type_names)

    apply_known_exceptions(rows_by_type)

    incremental_ids = sorted(fixture["id"] for fixture in incremental_corpus["fixtures"])
    synchronous_adversarial_ids = sorted(
        fixture["id"]
        for fixture in fixtures
        if fixture.get("kind") == "adversarial" and fixture.get("support") == "supported"
    )

    declarations = [rows_by_type[entry["type"]] for entry in manifest["types"]]
    declarations.append(
        build_incremental_row(incremental_corpus["fixtures"], lifecycle_corpus["fixtures"], unicode_ids, fixtures)
    )
    declarations.extend(
        build_binding_edge_rows(
            manifest["consumers"],
            error_codes_doc["codes"],
            unicode_ids,
            incremental_ids,
            synchronous_adversarial_ids,
        )
    )

    return {"declarations": declarations}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--incremental-corpus", type=Path, default=INCREMENTAL_CORPUS_PATH)
    parser.add_argument("--lifecycle-corpus", type=Path, default=LIFECYCLE_CORPUS_PATH)
    parser.add_argument("--unicode-corpus", type=Path, default=UNICODE_CORPUS_PATH)
    parser.add_argument("--error-codes", type=Path, default=ERROR_CODES_PATH)
    parser.add_argument("--out", type=Path, default=None, help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    manifest = INVENTORY.load_json(args.manifest)
    corpus = INVENTORY.load_json(args.corpus)
    incremental_corpus = INVENTORY.load_json(args.incremental_corpus)
    lifecycle_corpus = INVENTORY.load_json(args.lifecycle_corpus)
    unicode_corpus = INVENTORY.load_json(args.unicode_corpus)
    error_codes_doc = INVENTORY.load_json(args.error_codes)

    report = build_declarations(manifest, corpus, incremental_corpus, lifecycle_corpus, unicode_corpus, error_codes_doc)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"

    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
