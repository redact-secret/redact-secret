"""Asserts the Python binding against the reference ruleset conformance
fixture (`conformance/fixtures/ruleset-reference.json`, issue #495,
`decision-define-declarative-detector-ruleset-contract`'s "Conformance"):
the same fixture `crates/secret-scan-core/tests/ruleset_conformance.rs`
asserts on the Rust core, now asserted on this binding too, not through a
per-binding smoke test.

Every ruleset text and scanned input in the fixture is synthetic; nothing
here reproduces a matched value.
"""

from __future__ import annotations

import pytest

import redact_secret

from .conftest import byte_offset_to_char_offset_reference, load_corpus


def _fixture() -> dict:
    return load_corpus("ruleset-reference.json")


def _too_many_detectors_ruleset(count: int) -> bytes:
    """The `TOO_MANY_DETECTORS` ruleset: `count` detector blocks, each
    otherwise shaped like the accepted fixture's `acme-alnum-token` case
    with a unique id (mirrors the Rust conformance consumer's generator)."""
    lines = ["ruleset-revision: 1"]
    for index in range(count):
        lines.extend(
            [
                f"detector: acme-token-{index}",
                "specificity: contextual",
                'prefix: "ACME_"',
                "alphabet: alnum-dash",
                "run: at-least 20",
                "validator: none",
            ]
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def test_the_accepted_ruleset_matches_every_declared_case() -> None:
    accepted = _fixture()["accepted"]
    ruleset = accepted["ruleset"].encode("utf-8")

    for case in accepted["cases"]:
        findings = redact_secret.scan(case["input"], ruleset=ruleset)
        if case.get("findingCount") == 0:
            assert findings == [], case["id"]
            continue

        assert len(findings) == 1, case["id"]
        finding = findings[0]
        assert finding.detector == case["detector"], case["id"]
        assert finding.type == case["type"], case["id"]
        assert finding.confidence == case["confidence"], case["id"]
        start = byte_offset_to_char_offset_reference(case["input"], case["start"])
        end = byte_offset_to_char_offset_reference(case["input"], case["end"])
        assert (finding.start, finding.end) == (start, end), case["id"]


def test_the_ordering_fixture_shows_the_built_in_winning_the_tie() -> None:
    ordering = _fixture()["ordering"]
    ruleset = ordering["ruleset"].encode("utf-8")
    text = ordering["input"]
    expected = ordering["expectedWinner"]

    findings = redact_secret.scan(text, ruleset=ruleset)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == expected["detector"]
    assert finding.type == expected["type"]
    assert finding.confidence == expected["confidence"]
    start = byte_offset_to_char_offset_reference(text, expected["start"])
    end = byte_offset_to_char_offset_reference(text, expected["end"])
    assert (finding.start, finding.end) == (start, end)


@pytest.mark.parametrize(
    "rejection",
    _fixture()["rejections"],
    ids=lambda rejection: rejection["class"],
)
def test_every_declared_rejection_class_is_reproduced(rejection: dict) -> None:
    if "oversizedBytes" in rejection:
        ruleset = b"x" * rejection["oversizedBytes"]
    elif "detectorCount" in rejection:
        ruleset = _too_many_detectors_ruleset(rejection["detectorCount"])
    else:
        ruleset = rejection["ruleset"].encode("utf-8")

    with pytest.raises(redact_secret.InvalidRulesetError) as excinfo:
        redact_secret.scan("irrelevant", ruleset=ruleset)
    assert excinfo.value.code == "INVALID_RULESET"
    assert rejection["class"] in str(excinfo.value)


def test_every_class_the_core_defines_is_covered_exactly_once() -> None:
    names = [rejection["class"] for rejection in _fixture()["rejections"]]
    all_classes = [
        "RULESET_TOO_LARGE",
        "UNKNOWN_REVISION",
        "UNKNOWN_FIELD",
        "UNSUPPORTED_CONSTRUCT",
        "UNKNOWN_ALPHABET",
        "UNKNOWN_VALIDATOR",
        "SPECIFICITY_NOT_CLAIMABLE",
        "MISSING_FIELD",
        "PREFIX_TOO_SHORT",
        "PREFIX_TOO_LONG",
        "RUN_LENGTH_OUT_OF_BOUNDS",
        "TOO_MANY_DETECTORS",
        "DUPLICATE_DETECTOR_ID",
        "RESERVED_DETECTOR_ID",
        "EMPTY_RULESET",
    ]
    assert sorted(names) == sorted(all_classes)
