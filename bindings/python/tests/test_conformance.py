"""Synchronous conformance and Unicode range tests.

Runs the full canonical corpus (`decision-govern-cross-language-
conformance`) through `redact_secret.scan`, converting each expectation's
canonical UTF-8 byte offsets to Python code point offsets with an
independent reference conversion (not the binding under test), and asserts
`scan`'s detector/type/confidence/span output matches exactly.

Every fixture input is synthetic or explicitly revoked
(`conformance/README.md`); none embeds a live credential.
"""

from __future__ import annotations

import pytest

import redact_secret

from .conftest import byte_offset_to_char_offset_reference, load_corpus


def _expected_tuples(text: str, expected: list[dict]) -> list[tuple]:
    tuples = []
    for item in expected:
        start = byte_offset_to_char_offset_reference(text, item["start"])
        end = byte_offset_to_char_offset_reference(text, item["end"])
        tuples.append((item["detector"], item["type"], item["confidence"], start, end))
    return tuples


def _actual_tuples(findings: list[redact_secret.Finding]) -> list[tuple]:
    return [(f.detector, f.type, f.confidence, f.start, f.end) for f in findings]


def _finding_tuples(findings: list[redact_secret.Finding]) -> list[tuple]:
    return [(f.id, f.type, f.detector, f.confidence, f.action, f.start, f.end) for f in findings]


def _assert_equal(actual: object, expected: object, fixture_id: str) -> None:
    """Compares outside an `assert` statement so pytest's assertion-rewriting
    import hook never expands a mismatch into a printed diff, which could
    otherwise surface a fixture input or a matched value in test output."""
    if actual != expected:
        raise AssertionError(fixture_id)


def _synchronous_fixtures() -> list[dict]:
    corpus = load_corpus("synchronous-corpus.json")
    assert corpus["offsetUnit"] == "utf8-byte"
    # "not-yet-evaluated" fixtures carry no `expected` value (`null`) and
    # document a future gap, not a current behavioral contract.
    return [f for f in corpus["fixtures"] if f["support"] != "not-yet-evaluated"]


def _canonical_fixtures() -> list[dict]:
    corpus = load_corpus("synchronous-corpus.json")
    assert corpus["offsetUnit"] == "utf8-byte"
    return [f for f in corpus["fixtures"] if f["tier"] == "canonical"]


@pytest.mark.parametrize(
    "fixture",
    _synchronous_fixtures(),
    ids=lambda fixture: fixture["id"],
)
def test_scan_matches_the_canonical_synchronous_corpus(fixture: dict) -> None:
    text = fixture["input"]
    findings = redact_secret.scan(text)
    assert _actual_tuples(findings) == _expected_tuples(text, fixture["expected"])


def test_synchronous_corpus_is_not_vacuous() -> None:
    """Guards against every fixture being skipped by accident, which would
    make the parametrized test above pass without checking anything."""
    fixtures = _synchronous_fixtures()
    assert len(fixtures) >= 100
    assert any(f["expected"] for f in fixtures)
    assert any(not f["expected"] for f in fixtures)


@pytest.mark.parametrize(
    "fixture",
    _synchronous_fixtures(),
    ids=lambda fixture: fixture["id"],
)
def test_scan_and_redact_agrees_with_scan_then_redact_over_the_synchronous_corpus(
    fixture: dict,
) -> None:
    """Mirrors the Rust core's
    `scan_and_redact_equals_scan_then_redact_over_the_canonical_corpus`
    (`crates/secret-scan-core/tests/public_api.rs`): `scan_and_redact`
    must produce exactly the text and findings that separate `scan` and
    `redact` calls produce, for every non-`not-yet-evaluated` synchronous
    fixture."""
    text = fixture["input"]
    findings = redact_secret.scan(text)
    redacted = redact_secret.redact(text, findings)

    combined = redact_secret.scan_and_redact(text)

    _assert_equal(combined.text, redacted, fixture["id"])
    _assert_equal(_finding_tuples(combined.findings), _finding_tuples(findings), fixture["id"])


@pytest.mark.parametrize(
    "fixture",
    _canonical_fixtures(),
    ids=lambda fixture: fixture["id"],
)
def test_scan_and_redact_matches_the_canonical_corpus_redacted_text(
    fixture: dict,
) -> None:
    """Mirrors the CLI's `redact_matches_the_canonical_corpus_redacted_text`
    (`crates/secret-scan-cli/tests/cli.rs`): a `canonical`-tier fixture
    declares exactly one high-signal expectation, and `DefaultPolicy`
    always redacts or blocks it, both of which replace the range with
    `<SECRET_1>` - so the expected text is computable from the fixture's
    own `expected[0]` range alone."""
    text = fixture["input"]
    expected = fixture["expected"][0]
    start = byte_offset_to_char_offset_reference(text, expected["start"])
    end = byte_offset_to_char_offset_reference(text, expected["end"])
    expected_text = f"{text[:start]}<SECRET_1>{text[end:]}"

    result = redact_secret.scan_and_redact(text)

    _assert_equal(result.text, expected_text, fixture["id"])


def test_canonical_corpus_is_not_vacuous() -> None:
    """Guards against the canonical tier being empty, which would make the
    parametrized test above pass without checking anything."""
    assert len(_canonical_fixtures()) > 0


def _unicode_fixtures() -> list[dict]:
    corpus = load_corpus("unicode-conversion-corpus.json")
    assert corpus["offsetUnit"] == "utf8-byte"
    return corpus["fixtures"]


@pytest.mark.parametrize(
    "fixture",
    _unicode_fixtures(),
    ids=lambda fixture: fixture["id"],
)
def test_unicode_astral_ranges_convert_to_exact_code_point_offsets(
    fixture: dict,
) -> None:
    """An astral (supplementary-plane) character positioned before, within,
    and after a finding must not perturb the selected code point span:
    every code point counts as one unit regardless of plane."""
    text = fixture["input"]
    expected = fixture["expected"][0]
    start = byte_offset_to_char_offset_reference(text, expected["start"])
    end = byte_offset_to_char_offset_reference(text, expected["end"])

    assert redact_secret._native.byte_offset_to_char_offset(text, expected["start"]) == start
    assert redact_secret._native.byte_offset_to_char_offset(text, expected["end"]) == end
