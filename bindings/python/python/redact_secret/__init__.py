"""Deterministic secret detection and redaction, synchronously.

``redact_secret`` wraps the ``redact_secret._native`` PyO3 extension built from
the Rust core (``decision-define-runtime-bindings``). Every built-in
detector runs; there is no custom detector callback surface. Ranges on
every :class:`DetectedFinding` and :class:`Finding` are Unicode code point
offsets (``RANGE_UNIT``), matching Python's own ``str`` indexing and
slicing.

Typical usage::

    import redact_secret

    findings = redact_secret.scan(text)
    redacted = redact_secret.redact(text, findings)

    # or, to guarantee the findings and the redacted text agree:
    result = redact_secret.scan_and_redact(text)
    result.text, result.findings

``scan``, ``redact``, and ``scan_and_redact`` apply a default
:class:`WholeInputLimits` — 64 MiB of input, 50,000 accepted findings —
before doing any work, and fail with ``InputLimitExceededError`` or
``FindingLimitExceededError`` rather than truncating. Pass an explicit
``limits`` to raise or lower it::

    limits = redact_secret.WholeInputLimits(max_input_bytes=1_000_000, max_findings=1_000)
    findings = redact_secret.scan(text, limits=limits)

For input that arrives in pieces, :class:`IncrementalSanitizer` sanitizes a
bounded session chunk by chunk::

    limits = redact_secret.IncrementalLimits(
        max_input_bytes=1_000_000,
        max_buffered_bytes=16_512,
        max_token_bytes=8_192,
        max_multiline_bytes=16_384,
    )
    with redact_secret.IncrementalSanitizer(limits) as session:
        for chunk in chunks:
            print(session.append(chunk).text, end="")
        print(session.finalize().text, end="")

Its findings carry absolute code point offsets into the logical
whole-session input, so they index ``"".join(chunks)`` exactly as the
synchronous API's findings index the same joined string. Limits are
mandatory: a session declares its own bounds and there are no defaults.

To change what a few rules name and keep the default action for every other
finding, pass a declarative ``action_policy`` (a ``dict``, or its JSON document
as ``bytes``, ``bytearray`` or ``str``) instead of a ``policy`` callback; a
call or session takes one or the other, never both::

    result = redact_secret.scan_and_redact(
        text,
        action_policy={
            "actionPolicyRevision": 1,
            "base": "default",
            "rules": [{"id": "warn-jwt", "match": {"type": ["jwt"]}, "action": "warn"}],
        },
    )

A rejected document raises :class:`InvalidActionPolicyError`, whose
``error_class`` and ``rule_index`` attributes name the fixed rejection class and
the rule being read.

To see what a change would do before adopting it, :func:`compare_action_policies`
detects once and reports what 1 to 4 policies (the default, a declarative
document, or a legacy ``policy`` callback) would choose for the same finalized
findings. It is a preview, never enforcement (``mode == "preview"``,
``enforced is False``), it covers whole input only (there is no incremental
comparison), and it carries no input byte or matched value::

    comparison = redact_secret.compare_action_policies(
        text,
        [
            redact_secret.ComparedPolicy.default(),
            redact_secret.ComparedPolicy.action_policy(candidate_document),
        ],
    )
    for finding in comparison.findings:
        print(finding.type, [d.action for d in finding.decisions], finding.differs)

``policy`` and ``formatter`` callbacks only ever receive the safe metadata
types below, never the input or a matched value. A callback that raises, or
that returns something other than the documented protocol, never
propagates its own error: it becomes one of the fixed exceptions below.
"""

from __future__ import annotations

# Fixed, input-free, and actionable (issue #586): an extension module that is
# missing, built for another platform, or otherwise unloadable fails the
# import with this message alone. The loader's own error names host paths and
# ABI details, so it is suppressed rather than chained.
_NATIVE_UNAVAILABLE = (
    "redact-secret could not load its native extension: this platform or Python "
    "build has no supported wheel, or the installation is incomplete. Reinstall "
    "with `python -m pip install --only-binary=:all: redact-secret` on a supported "
    "platform; see https://github.com/redact-secret/redact-secret/blob/main/docs/python-packaging.md"
)

try:
    from redact_secret._native import (
        RANGE_UNIT,
        VERSION,
        ActionComparison,
        ActionCounts,
        ActionDecision,
        BufferLimitExceededError,
        ComparedFinding,
        ComparedPolicy,
        ComparedSide,
        CoreStatus,
        DetectedFinding,
        DetectionIdentity,
        DetectorFailureError,
        Finding,
        FindingLimitExceededError,
        IncrementalLimits,
        IncrementalPolicyContext,
        IncrementalResult,
        IncrementalSanitizer,
        InputLimitExceededError,
        InvalidActionPolicyError,
        InvalidCandidateError,
        InvalidDetectorError,
        InvalidFindingsError,
        InvalidInputError,
        InvalidLimitsError,
        InvalidOptionsError,
        InvalidPlaceholderError,
        InvalidPolicyActionError,
        InvalidRulesetError,
        InvalidStateError,
        MultilineLimitExceededError,
        PiiActivationConflictError,
        PiiSelectorInvalidError,
        PiiSelectorUnavailableError,
        PiiSelectorUnsupportedError,
        PlaceholderContext,
        PlaceholderFailureError,
        PolicyContext,
        PolicyFailureError,
        ScanResult,
        SecretScanError,
        TokenLimitExceededError,
        WholeInputLimits,
        compare_action_policies,
        default_incremental_policy,
        default_placeholder_formatter,
        default_policy,
        initialize,
        pii_activation,
        redact,
        scan,
        scan_and_redact,
        status,
        typed_placeholder_formatter,
    )
except ImportError:
    raise ImportError(_NATIVE_UNAVAILABLE) from None

__version__ = VERSION

__all__ = [
    "RANGE_UNIT",
    "VERSION",
    "ActionComparison",
    "ActionCounts",
    "ActionDecision",
    "BufferLimitExceededError",
    "ComparedFinding",
    "ComparedPolicy",
    "ComparedSide",
    "CoreStatus",
    "DetectedFinding",
    "DetectionIdentity",
    "DetectorFailureError",
    "Finding",
    "FindingLimitExceededError",
    "IncrementalLimits",
    "IncrementalPolicyContext",
    "IncrementalResult",
    "IncrementalSanitizer",
    "InputLimitExceededError",
    "InvalidActionPolicyError",
    "InvalidCandidateError",
    "InvalidDetectorError",
    "InvalidFindingsError",
    "InvalidInputError",
    "InvalidLimitsError",
    "InvalidOptionsError",
    "InvalidPlaceholderError",
    "InvalidPolicyActionError",
    "InvalidRulesetError",
    "InvalidStateError",
    "MultilineLimitExceededError",
    "PlaceholderContext",
    "PlaceholderFailureError",
    "PolicyContext",
    "PolicyFailureError",
    "PiiActivationConflictError",
    "PiiSelectorInvalidError",
    "PiiSelectorUnavailableError",
    "PiiSelectorUnsupportedError",
    "ScanResult",
    "SecretScanError",
    "TokenLimitExceededError",
    "WholeInputLimits",
    "compare_action_policies",
    "default_incremental_policy",
    "default_placeholder_formatter",
    "default_policy",
    "initialize",
    "pii_activation",
    "redact",
    "scan",
    "scan_and_redact",
    "status",
    "typed_placeholder_formatter",
]
