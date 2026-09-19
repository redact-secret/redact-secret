"""Partition invariance for the canonical incremental corpus, in Python.

Every fixture in `conformance/fixtures/incremental-corpus.json` is run
through a bounded session at every Python code point boundary of its input
- and, for the smaller fixtures, one code point at a time - and the
concatenated text, findings, ids, order, actions, absolute code point
ranges, and placeholder numbering are compared against the whole-input
`scan_and_redact` reference.

This is the Python consumer of the canonical contract required by
`decision-govern-cross-language-conformance`: fixture values are read from
the corpus, never copied into this file. Canonical UTF-8 byte offsets are
converted to Python code point offsets by an independent reference
conversion (`conftest.byte_offset_to_char_offset_reference`), not by the
binding under test. Every fixture input is synthetic or explicitly revoked.
"""

from __future__ import annotations

import pytest

import redact_secret

from .conftest import (
    byte_offset_to_char_offset_reference,
    code_point_partitions,
    generous_limits,
    load_corpus,
    run_session,
    single_code_point_partition,
)

# Running every fixture at every boundary one code point at a time is
# quadratic in the input length, so the finest partition is applied only to
# inputs short enough for it to stay cheap. Two-piece partitions still cover
# every boundary of every fixture.
SINGLE_CODE_POINT_MAX_LENGTH = 256


def _fixtures() -> list[dict]:
    corpus = load_corpus("incremental-corpus.json")
    assert corpus["offsetUnit"] == "utf8-byte"
    assert corpus["fixtureCount"] == len(corpus["fixtures"])
    return corpus["fixtures"]


FIXTURES = _fixtures()


def _summary(findings: list[redact_secret.Finding]) -> list[tuple]:
    return [
        (f.id, f.detector, f.type, f.confidence, f.action, f.obfuscation, f.start, f.end)
        for f in findings
    ]


def _canonical_summary(fixture: dict) -> list[tuple]:
    """The corpus's own expectation, converted to code point offsets, with
    the ids and actions the whole-input reference is required to assign."""
    text = fixture["input"]
    return [
        (
            f"finding-{index + 1}",
            expected["detector"],
            expected["type"],
            expected["confidence"],
            byte_offset_to_char_offset_reference(text, expected["start"]),
            byte_offset_to_char_offset_reference(text, expected["end"]),
        )
        for index, expected in enumerate(fixture["expected"])
    ]


def test_corpus_is_not_vacuous() -> None:
    """Guards against a corpus that silently stopped carrying findings,
    which would make every assertion below pass without checking anything."""
    assert len(FIXTURES) >= 10
    assert any(fixture["expected"] for fixture in FIXTURES)
    assert any("\n" in fixture["input"] for fixture in FIXTURES)


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda fixture: fixture["id"])
def test_whole_input_reference_matches_the_canonical_expectation(
    fixture: dict,
) -> None:
    """Anchors the reference the partition tests compare against to the
    corpus, so a drifting binding cannot agree with itself and pass."""
    result = redact_secret.scan_and_redact(fixture["input"])
    assert result.text == fixture["text"]
    assert [
        (f.id, f.detector, f.type, f.confidence, f.start, f.end)
        for f in result.findings
    ] == _canonical_summary(fixture)


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda fixture: fixture["id"])
def test_every_code_point_partition_reproduces_the_whole_input_result(
    fixture: dict,
) -> None:
    text = fixture["input"]
    reference = redact_secret.scan_and_redact(text)
    expected = _summary(reference.findings)

    for chunks in code_point_partitions(text):
        actual_text, actual_findings = run_session(chunks)
        boundary = len(chunks[0])
        assert actual_text == reference.text, f"text at boundary {boundary}"
        assert _summary(actual_findings) == expected, f"findings at boundary {boundary}"


@pytest.mark.parametrize(
    "fixture",
    [f for f in FIXTURES if len(f["input"]) <= SINGLE_CODE_POINT_MAX_LENGTH],
    ids=lambda fixture: fixture["id"],
)
def test_one_code_point_per_append_reproduces_the_whole_input_result(
    fixture: dict,
) -> None:
    text = fixture["input"]
    reference = redact_secret.scan_and_redact(text)

    actual_text, actual_findings = run_session(single_code_point_partition(text))
    assert actual_text == reference.text
    assert _summary(actual_findings) == _summary(reference.findings)


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda fixture: fixture["id"])
def test_offsets_are_absolute_into_the_joined_input_not_per_chunk(
    fixture: dict,
) -> None:
    """The point of absolute code point offsets: with one code point per
    `append`, a per-chunk offset could only ever be 0 or 1, so agreeing
    with the corpus here proves the offsets are session-absolute."""
    text = fixture["input"]
    _, findings = run_session(single_code_point_partition(text))

    assert [(f.start, f.end) for f in findings] == [
        (
            byte_offset_to_char_offset_reference(text, expected["start"]),
            byte_offset_to_char_offset_reference(text, expected["end"]),
        )
        for expected in fixture["expected"]
    ]


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda fixture: fixture["id"])
def test_placeholder_numbering_continues_across_calls(fixture: dict) -> None:
    """Placeholders are numbered across the whole session, not restarted per
    `append`, so a partitioned run produces the same `<SECRET_N>` sequence
    the whole-input run does."""
    text = fixture["input"]
    indices: list[int] = []

    def formatter(
        finding: redact_secret.Finding, context: redact_secret.PlaceholderContext
    ) -> str:
        indices.append(context.placeholder_index)
        return redact_secret.default_placeholder_formatter(finding, context)

    session = redact_secret.IncrementalSanitizer(generous_limits(), None, formatter)
    produced = ""
    for chunk in single_code_point_partition(text):
        produced += session.append(chunk).text
    produced += session.finalize().text

    assert produced == redact_secret.scan_and_redact(text).text
    assert indices == list(range(1, len(indices) + 1))
