"""`ruleset`: the declarative ruleset argument to `scan`/`scan_and_redact`
(issue #495, `decision-define-declarative-detector-ruleset-contract`).

Every input and ruleset here is synthetic.
"""

from __future__ import annotations

import pytest

import redact_secret

RULESET_FIXTURE = b"""ruleset-revision: 1
detector: acme-internal-token
specificity: contextual
prefix: "ACME_"
alphabet: alnum-dash
run: at-least 20
validator: none
"""


def _synthetic_value() -> str:
    return "a" * 20


def test_no_built_in_detector_claims_the_synthetic_prefix() -> None:
    text = f"ACME_{_synthetic_value()}"
    assert redact_secret.scan(text) == []


def test_ruleset_bytes_add_a_detection() -> None:
    text = f"ACME_{_synthetic_value()}"
    findings = redact_secret.scan(text, ruleset=RULESET_FIXTURE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == "acme-internal-token"
    assert finding.type == "acme-internal-token"
    # Every ruleset candidate carries `Confidence::Medium`, fixed regardless
    # of the ruleset's own content (issue #495's "Decisions this issue
    # settles" #1).
    assert finding.confidence == "medium"
    # `DefaultPolicy` redacts only `Confidence::High` or an always-redact
    # type, so a ruleset detection warns rather than redacts by default.
    assert finding.action == "warn"


def test_ruleset_str_is_equivalent_to_the_same_bytes() -> None:
    text = f"ACME_{_synthetic_value()}"
    from_bytes = redact_secret.scan(text, ruleset=RULESET_FIXTURE)
    from_str = redact_secret.scan(text, ruleset=RULESET_FIXTURE.decode("utf-8"))
    assert [f.detector for f in from_bytes] == [f.detector for f in from_str]


def test_ruleset_detector_registers_after_the_built_ins() -> None:
    """A ruleset detector at the same span, specificity, and confidence as
    a built-in never outranks it: `generic-token`'s own ambiguous-name
    contextual candidate for `AUTH_TOKEN=<value>` spans exactly `<value>`,
    and a ruleset prefix equal to the value's own first four bytes claims
    the identical range, specificity, and (fixed) confidence — the tie
    falls through to registration order, where the built-in wins
    (`decision-define-declarative-detector-ruleset-contract`, "Ordering
    and the specificity cap")."""
    value = "tok_a1B2c3D4e5F6g7H8i9"
    text = f"AUTH_TOKEN={value}\n"
    ruleset = b"""ruleset-revision: 1
detector: acme-tok-companion
specificity: contextual
prefix: "tok_"
alphabet: alnum
run: at-least 4
validator: none
"""
    findings = redact_secret.scan(text, ruleset=ruleset)
    assert len(findings) == 1
    assert findings[0].detector == "generic-token"


def test_scan_and_redact_threads_the_ruleset_through() -> None:
    text = f"ACME_{_synthetic_value()}"
    result = redact_secret.scan_and_redact(text, ruleset=RULESET_FIXTURE)
    assert len(result.findings) == 1
    assert result.findings[0].detector == "acme-internal-token"
    # Warn-only: the text passes through unchanged.
    assert result.text == text


def test_a_malformed_ruleset_raises_invalid_ruleset_error_with_the_fixed_class() -> None:
    malformed = RULESET_FIXTURE.replace(b"ruleset-revision: 1", b"ruleset-revision: 2")
    with pytest.raises(redact_secret.InvalidRulesetError) as excinfo:
        redact_secret.scan("irrelevant", ruleset=malformed)
    assert excinfo.value.code == "INVALID_RULESET"
    assert "UNKNOWN_REVISION" in str(excinfo.value)


def test_a_ruleset_rejection_carries_no_byte_from_the_rejected_ruleset() -> None:
    canary = b"S3CR3T_RULESET_CANARY_MARKER"
    malformed = RULESET_FIXTURE.replace(b"validator: none", b"validator: " + canary)
    with pytest.raises(redact_secret.InvalidRulesetError) as excinfo:
        redact_secret.scan("irrelevant", ruleset=malformed)
    assert canary.decode("ascii") not in str(excinfo.value)


def test_a_non_bytes_non_str_ruleset_raises_invalid_options_error() -> None:
    with pytest.raises(redact_secret.InvalidOptionsError) as excinfo:
        redact_secret.scan("irrelevant", ruleset=12345)  # type: ignore[arg-type]
    assert excinfo.value.code == "INVALID_OPTIONS"


def test_a_specificity_reserved_to_built_ins_is_rejected() -> None:
    for reserved in ("structural", "provider", "private-key"):
        malformed = RULESET_FIXTURE.replace(
            b"specificity: contextual", f"specificity: {reserved}".encode()
        )
        with pytest.raises(redact_secret.InvalidRulesetError) as excinfo:
            redact_secret.scan("irrelevant", ruleset=malformed)
        assert "SPECIFICITY_NOT_CLAIMABLE" in str(excinfo.value)
