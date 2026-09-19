"""`WholeInputLimits`: the default whole-input bound, its opt-out, and
diagnostic identity (`decision-bound-whole-input-operations-by-default`).

Every input here is synthetic.
"""

from __future__ import annotations

import pytest

import redact_secret

SYNTHETIC_INPUT = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000"


def test_default_behavior_is_unaffected_for_ordinary_input() -> None:
    findings = redact_secret.scan(SYNTHETIC_INPUT)
    assert len(findings) == 1

    redacted = redact_secret.redact(SYNTHETIC_INPUT, findings)
    assert redacted == "API_KEY=<SECRET_1>"

    result = redact_secret.scan_and_redact(SYNTHETIC_INPUT)
    assert result.text == redacted


def test_scan_accepts_input_exactly_at_an_explicit_byte_bound() -> None:
    limits = redact_secret.WholeInputLimits(
        max_input_bytes=len(SYNTHETIC_INPUT), max_findings=10
    )
    findings = redact_secret.scan(SYNTHETIC_INPUT, limits=limits)
    assert len(findings) == 1


def test_scan_rejects_input_one_byte_over_an_explicit_byte_bound() -> None:
    limits = redact_secret.WholeInputLimits(
        max_input_bytes=len(SYNTHETIC_INPUT) - 1, max_findings=10
    )
    with pytest.raises(redact_secret.InputLimitExceededError) as excinfo:
        redact_secret.scan(SYNTHETIC_INPUT, limits=limits)
    assert excinfo.value.code == "INPUT_LIMIT_EXCEEDED"


def test_redact_and_scan_and_redact_also_honor_an_explicit_byte_bound() -> None:
    limits = redact_secret.WholeInputLimits(max_input_bytes=5, max_findings=50)

    with pytest.raises(redact_secret.InputLimitExceededError):
        redact_secret.redact("abcdef", [], limits=limits)

    with pytest.raises(redact_secret.InputLimitExceededError):
        redact_secret.scan_and_redact("abcdef", limits=limits)


def test_scan_rejects_a_finding_count_over_an_explicit_bound() -> None:
    # Two disjoint AWS-access-key-shaped candidates.
    text = "prefix AKIA{} middle AKIA{} suffix".format(
        "SYNTHETICEXAMPLE", "SYNTHETICEXAMPL2"
    )
    generous = redact_secret.WholeInputLimits(max_input_bytes=1024, max_findings=100)
    found = redact_secret.scan(text, limits=generous)
    assert len(found) == 2

    at_bound = redact_secret.WholeInputLimits(max_input_bytes=1024, max_findings=2)
    assert len(redact_secret.scan(text, limits=at_bound)) == 2

    one_under = redact_secret.WholeInputLimits(max_input_bytes=1024, max_findings=1)
    with pytest.raises(redact_secret.FindingLimitExceededError) as excinfo:
        redact_secret.scan(text, limits=one_under)
    assert excinfo.value.code == "FINDING_LIMIT_EXCEEDED"


def test_redact_independently_enforces_the_finding_bound() -> None:
    """`redact()` bounds `len(findings)` even when the findings did not come
    from a `scan()` call under the same limits — no `scan()` call under
    `strict` is involved here at all."""
    text = "prefix AKIA{} middle AKIA{} suffix".format(
        "SYNTHETICEXAMPLE", "SYNTHETICEXAMPL2"
    )
    generous = redact_secret.WholeInputLimits(max_input_bytes=1024, max_findings=100)
    findings = redact_secret.scan(text, limits=generous)
    assert len(findings) == 2

    strict = redact_secret.WholeInputLimits(max_input_bytes=1024, max_findings=1)
    with pytest.raises(redact_secret.FindingLimitExceededError):
        redact_secret.redact(text, findings, limits=strict)


def test_whole_input_limits_rejects_a_zero_input_bound() -> None:
    with pytest.raises(redact_secret.InvalidLimitsError) as excinfo:
        redact_secret.WholeInputLimits(max_input_bytes=0, max_findings=10)
    assert excinfo.value.code == "INVALID_LIMITS"


def test_whole_input_limits_rejects_a_zero_finding_bound() -> None:
    with pytest.raises(redact_secret.InvalidLimitsError):
        redact_secret.WholeInputLimits(max_input_bytes=10, max_findings=0)


def test_whole_input_limits_attributes_are_read_only() -> None:
    limits = redact_secret.WholeInputLimits(max_input_bytes=10, max_findings=10)
    with pytest.raises(AttributeError):
        limits.max_input_bytes = 20  # type: ignore[misc]


def test_the_fixed_codes_and_messages_are_stable() -> None:
    assert redact_secret.FindingLimitExceededError.code == "FINDING_LIMIT_EXCEEDED"
    assert redact_secret.InputLimitExceededError.code == "INPUT_LIMIT_EXCEEDED"
    assert redact_secret.InvalidLimitsError.code == "INVALID_LIMITS"
