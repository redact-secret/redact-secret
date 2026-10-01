"""Unicode boundaries for an incremental session.

A session reports absolute Unicode code point offsets, but the core it
wraps reports absolute UTF-8 byte offsets, and the conversion has to work
without the session ever retaining the input. The cases below put an astral
(supplementary-plane) character before, within, and after a finding - the
mandatory evidence `decision-govern-cross-language-conformance` requires of
every binding runner - and drive them through every Python-native partition
of the input.

Each character in these inputs occupies one Python code point, four UTF-8
bytes for the astral ones and one for the ASCII, so a binding that reported
byte offsets, or that lost count across a chunk boundary, cannot pass.
Every input is synthetic.
"""

from __future__ import annotations

import pytest
import redact_secret

from .conftest import (
    code_point_partitions,
    run_session,
    single_code_point_partition,
)

# A key-shaped astral character, matching the corpus's own choice.
ASTRAL = "\U0001f511"
SYNTHETIC_TOKEN = "AKIASYNTHETICEXAMPLE"

CASES = {
    "astral-before": f"{ASTRAL} {SYNTHETIC_TOKEN} after",
    "astral-within-the-surrounding-text": f"before {ASTRAL} {SYNTHETIC_TOKEN} after",
    "astral-after": f"{SYNTHETIC_TOKEN} {ASTRAL}",
    "astral-on-both-sides-of-a-line-break": (
        f"{ASTRAL} {SYNTHETIC_TOKEN}\n{ASTRAL} api_key=SYNTHETIC_REVOKED_SECOND_VALUE\n"
    ),
    "astral-runs-between-two-findings": (
        f"{ASTRAL * 4}{SYNTHETIC_TOKEN}{ASTRAL * 4}\nBearer SYNTHETIC_REVOKED_BEARER_VALUE\n"
    ),
}


def _utf8_length(text: str, code_point_offset: int) -> int:
    """What a binding that reported UTF-8 byte offsets would say instead."""
    return len(text[:code_point_offset].encode("utf-8"))


@pytest.mark.parametrize("text", CASES.values(), ids=list(CASES))
def test_every_case_carries_an_astral_character_and_a_finding(text: str) -> None:
    """A case with no astral character, or no finding, would make the
    assertions below pass without exercising anything."""
    assert ASTRAL in text
    assert redact_secret.scan(text)


def test_the_cases_include_offsets_that_diverge_from_utf8_bytes() -> None:
    """An astral character placed *after* a finding legitimately leaves the
    two units agreeing - that is the point of the "astral after" case - so
    divergence is required of the set, not of every member."""
    diverging = [
        text
        for text in CASES.values()
        for finding in redact_secret.scan(text)
        if finding.start != _utf8_length(text, finding.start) or finding.end != _utf8_length(text, finding.end)
    ]
    assert len(diverging) >= 3


@pytest.mark.parametrize("text", CASES.values(), ids=list(CASES))
def test_every_partition_reproduces_the_whole_input_result(text: str) -> None:
    reference = redact_secret.scan_and_redact(text)
    expected = [(f.id, f.type, f.action, f.start, f.end) for f in reference.findings]

    for chunks in code_point_partitions(text) + [single_code_point_partition(text)]:
        actual_text, findings = run_session(chunks)
        assert actual_text == reference.text, chunks[:1]
        assert [(f.id, f.type, f.action, f.start, f.end) for f in findings] == expected, chunks[:1]


@pytest.mark.parametrize("text", CASES.values(), ids=list(CASES))
def test_reported_offsets_index_the_joined_chunks(text: str) -> None:
    """The contract a Python caller depends on: the offsets slice the
    concatenation of the chunks they fed in, not any chunk on its own and
    not the UTF-8 encoding of either."""
    chunks = single_code_point_partition(text)
    _, findings = run_session(chunks)
    joined = "".join(chunks)

    reference = {(f.start, f.end) for f in redact_secret.scan(text)}
    assert {(f.start, f.end) for f in findings} == reference
    for finding in findings:
        assert 0 <= finding.start < finding.end <= len(joined)
        # Slicing at these offsets never splits a character: Python `str`
        # indexing is code point indexing, so this holds by construction and
        # would fail only if the offsets were byte or UTF-16 offsets.
        assert len(joined[finding.start : finding.end]) == finding.end - finding.start


@pytest.mark.parametrize("text", CASES.values(), ids=list(CASES))
def test_offsets_equal_pythons_own_index_of_the_matched_span(text: str) -> None:
    """The fully independent reference: `str.index` counts code points, and
    the binding under test plays no part in computing it."""
    _, findings = run_session(single_code_point_partition(text))
    matched = [f for f in findings if f.detector == "aws-access-key"]
    assert len(matched) == 1

    expected_start = text.index(SYNTHETIC_TOKEN)
    assert matched[0].start == expected_start
    assert matched[0].end == expected_start + len(SYNTHETIC_TOKEN)
