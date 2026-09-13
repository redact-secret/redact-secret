"""Incremental session lifecycle, limits, immutability, and callbacks.

Covers the half of the incremental contract that partition invariance
(`test_incremental_partitions.py`) does not: the mandatory limits, the
`accepting` -> `finalized`/`aborted`/`failed` lifecycle and the fixed
exception every operation outside it raises, the immutability of a result,
the safe-metadata contract the policy and formatter callbacks see, and the
requirement that `abort` and every failure discard retained plaintext.

The lifecycle cases are driven from the canonical
`conformance/fixtures/incremental-lifecycle-corpus.json`
(`decision-govern-cross-language-conformance`) wherever the corpus declares
one, so this suite cannot drift from the Rust core's own. Every input here
is synthetic or explicitly revoked.
"""

from __future__ import annotations

import gc

import pytest

import redact_secret

from .conftest import GENEROUS_LIMITS, generous_limits, load_corpus

# A synthetic value that is never a real credential, used as the marker a
# retention assertion looks for.
RETENTION_MARKER = "SYNTHETIC_REVOKED_RETENTION_MARKER"
OPEN_CONSTRUCT = f"api_key={RETENTION_MARKER}"

# The canonical corpus declares its limits in the temporary TypeScript
# oracle's UTF-16 code units. Every fixture input is ASCII, where one code
# unit is one UTF-8 byte, so the mapping below is exact rather than
# approximate; `test_lifecycle_fixture_inputs_are_ascii` enforces that.
LIMIT_NAMES = {
    "maxInputCodeUnits": "max_input_bytes",
    "maxBufferedCodeUnits": "max_buffered_bytes",
    "maxTokenCodeUnits": "max_token_bytes",
    "maxMultilineCodeUnits": "max_multiline_bytes",
}
DEFAULT_LIFECYCLE_LIMITS = {
    "max_input_bytes": 32_768,
    "max_buffered_bytes": 16_512,
    "max_token_bytes": 8_192,
    "max_multiline_bytes": 16_384,
}


# ---------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------


def test_limits_are_mandatory_and_keyword_only() -> None:
    with pytest.raises(TypeError):
        redact_secret.IncrementalLimits()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        redact_secret.IncrementalLimits(1_000_000, 16_512, 8_192, 16_384)  # type: ignore[misc]
    with pytest.raises(TypeError):
        redact_secret.IncrementalSanitizer()  # type: ignore[call-arg]


def test_limits_expose_what_they_were_given() -> None:
    limits = generous_limits()
    assert limits.max_input_bytes == GENEROUS_LIMITS["max_input_bytes"]
    assert limits.max_buffered_bytes == GENEROUS_LIMITS["max_buffered_bytes"]
    assert limits.max_token_bytes == GENEROUS_LIMITS["max_token_bytes"]
    assert limits.max_multiline_bytes == GENEROUS_LIMITS["max_multiline_bytes"]
    assert redact_secret.IncrementalSanitizer(limits).limits.max_input_bytes == (
        GENEROUS_LIMITS["max_input_bytes"]
    )


def test_limits_are_read_only() -> None:
    limits = generous_limits()
    with pytest.raises(AttributeError):
        limits.max_input_bytes = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "override",
    [
        {"max_input_bytes": 0},
        {"max_buffered_bytes": 0},
        {"max_token_bytes": 0},
        {"max_multiline_bytes": 0},
        # A construct limit above the total input limit.
        {"max_input_bytes": 1_024, "max_token_bytes": 2_048},
        {"max_input_bytes": 1_024, "max_multiline_bytes": 2_048},
        # A buffer that cannot hold the largest construct plus lookaround.
        {"max_buffered_bytes": 16_384},
    ],
)
def test_invalid_limits_raise_invalid_limits_error(override: dict) -> None:
    with pytest.raises(redact_secret.InvalidLimitsError) as excinfo:
        redact_secret.IncrementalLimits(**{**GENEROUS_LIMITS, **override})
    assert excinfo.value.code == "INVALID_LIMITS"


def test_buffer_limit_must_cover_the_documented_lookaround_window() -> None:
    """The documented relationship, asserted against the constant the module
    publishes rather than a number copied into this test."""
    construct = 8_192
    base = {
        "max_input_bytes": 1_000_000,
        "max_token_bytes": construct,
        "max_multiline_bytes": construct,
    }
    exact = redact_secret.IncrementalLimits.minimum_buffered_bytes(construct, construct)
    assert redact_secret.IncrementalLimits(max_buffered_bytes=exact, **base)
    with pytest.raises(redact_secret.InvalidLimitsError):
        redact_secret.IncrementalLimits(max_buffered_bytes=exact - 1, **base)


# ---------------------------------------------------------------------
# Lifecycle, from the canonical corpus
# ---------------------------------------------------------------------


def _lifecycle_fixtures() -> list[dict]:
    corpus = load_corpus("incremental-lifecycle-corpus.json")
    assert corpus["fixtureCount"] == len(corpus["fixtures"])
    # The `stream` surface is the byte-oriented adapter, which this binding
    # does not expose; its fixtures belong to whichever binding does.
    return [f for f in corpus["fixtures"] if f["surface"] == "incremental"]


LIFECYCLE_FIXTURES = _lifecycle_fixtures()


def test_lifecycle_fixture_inputs_are_ascii() -> None:
    """The corpus declares limits in UTF-16 code units; this binding's are
    UTF-8 bytes. The two agree only for ASCII, so the mapping the fixtures
    are run through is only valid while this holds."""
    assert LIFECYCLE_FIXTURES
    for fixture in LIFECYCLE_FIXTURES:
        for operation in fixture["operations"]:
            assert operation.get("chunk", "").isascii(), fixture["id"]


def _limits_for(fixture: dict) -> redact_secret.IncrementalLimits:
    declared = fixture.get("limits")
    if declared is None:
        return redact_secret.IncrementalLimits(**DEFAULT_LIFECYCLE_LIMITS)
    return redact_secret.IncrementalLimits(
        **{LIMIT_NAMES[key]: value for key, value in declared.items()}
    )


@pytest.mark.parametrize(
    "fixture", LIFECYCLE_FIXTURES, ids=lambda fixture: fixture["id"]
)
def test_lifecycle_matches_the_canonical_corpus(fixture: dict) -> None:
    session = redact_secret.IncrementalSanitizer(_limits_for(fixture))
    outcome = fixture["outcome"]
    text = ""
    finding_count = 0
    raised: redact_secret.SecretScanError | None = None

    for index, operation in enumerate(fixture["operations"]):
        try:
            if operation["op"] == "append":
                result = session.append(operation["chunk"])
            elif operation["op"] == "finalize":
                result = session.finalize()
            else:
                session.abort()
                continue
        except redact_secret.SecretScanError as error:
            # Only the last declared operation is allowed to fail.
            assert index == len(fixture["operations"]) - 1, fixture["id"]
            raised = error
            break
        text += result.text
        finding_count += len(result.findings)

    assert session.state == outcome["state"]
    assert text == outcome["text"]
    assert finding_count == outcome["findingCount"]
    if outcome["ok"]:
        assert raised is None
    else:
        assert raised is not None
        assert raised.code == outcome["code"]


def test_lifecycle_corpus_covers_both_outcomes() -> None:
    assert any(f["outcome"]["ok"] for f in LIFECYCLE_FIXTURES)
    assert any(not f["outcome"]["ok"] for f in LIFECYCLE_FIXTURES)


# ---------------------------------------------------------------------
# Lifecycle, beyond the corpus
# ---------------------------------------------------------------------


def test_a_new_session_is_accepting() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    assert session.state == "accepting"
    assert repr(session) == 'IncrementalSanitizer(state="accepting")'


@pytest.mark.parametrize("operation", ["append", "finalize", "abort"])
def test_every_operation_after_finalize_raises_invalid_state(operation: str) -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    session.finalize()
    assert session.state == "finalized"

    with pytest.raises(redact_secret.InvalidStateError) as excinfo:
        if operation == "append":
            session.append("x")
        elif operation == "finalize":
            session.finalize()
        else:
            session.abort()
    assert excinfo.value.code == "INVALID_STATE"
    assert session.state == "finalized"


@pytest.mark.parametrize("operation", ["append", "finalize", "abort"])
def test_every_operation_after_a_failure_raises_invalid_state(operation: str) -> None:
    limits = redact_secret.IncrementalLimits(
        max_input_bytes=64,
        max_buffered_bytes=192,
        max_token_bytes=32,
        max_multiline_bytes=64,
    )
    session = redact_secret.IncrementalSanitizer(limits)
    with pytest.raises(redact_secret.InputLimitExceededError):
        session.append("x" * 65)
    assert session.state == "failed"

    with pytest.raises(redact_secret.InvalidStateError):
        if operation == "append":
            session.append("x")
        elif operation == "finalize":
            session.finalize()
        else:
            session.abort()
    assert session.state == "failed"


@pytest.mark.parametrize("chunk", [42, b"bytes", "\ud800", "\udc00"])
def test_invalid_input_is_terminal(chunk) -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    retained = session.append("🔑SYNTHETIC_REVOKED_RETAINED_TEXT")
    assert retained.text == ""
    assert list(retained.findings) == []
    with pytest.raises(redact_secret.InvalidInputError) as excinfo:
        session.append(chunk)
    assert excinfo.value.code == "INVALID_INPUT"
    assert str(excinfo.value) == "Secret scan input must be a string."
    assert excinfo.value.__cause__ is None
    assert session.state == "failed"
    for operation in [
        lambda: session.append("x"),
        lambda: session.append(chunk),
        session.finalize,
        session.abort,
    ]:
        with pytest.raises(redact_secret.InvalidStateError) as later:
            operation()
        assert later.value.code == "INVALID_STATE"
        assert str(later.value) == "The incremental sanitizer is no longer accepting input."
        assert session.state == "failed"


def test_an_empty_session_finalizes_to_empty_output() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    result = session.finalize()
    assert result.text == ""
    assert list(result.findings) == []
    assert session.state == "finalized"


def test_the_context_manager_aborts_a_session_left_accepting() -> None:
    with redact_secret.IncrementalSanitizer(generous_limits()) as session:
        session.append(OPEN_CONSTRUCT)
    assert session.state == "aborted"


def test_the_context_manager_leaves_a_finalized_session_alone() -> None:
    with redact_secret.IncrementalSanitizer(generous_limits()) as session:
        session.finalize()
    assert session.state == "finalized"


def test_the_context_manager_does_not_swallow_an_exception() -> None:
    with pytest.raises(ValueError):
        with redact_secret.IncrementalSanitizer(generous_limits()) as session:
            session.append(OPEN_CONSTRUCT)
            raise ValueError("caller's own failure")
    assert session.state == "aborted"


# ---------------------------------------------------------------------
# Immutable results
# ---------------------------------------------------------------------


def test_results_are_read_only() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    result = session.append(f"{OPEN_CONSTRUCT}\n")
    with pytest.raises(AttributeError):
        result.text = "tampered"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.findings = []  # type: ignore[misc]


def test_mutating_the_findings_list_does_not_change_the_result() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    result = session.append(f"{OPEN_CONSTRUCT}\n")
    assert len(result.findings) == 1

    result.findings.clear()
    assert len(result.findings) == 1
    with pytest.raises(AttributeError):
        result.findings[0].action = "allow"  # type: ignore[misc]


def test_a_result_is_not_re_emitted_by_a_later_call() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    first = session.append(f"{OPEN_CONSTRUCT}\n")
    second = session.append("plain text\n")
    final = session.finalize()

    assert first.text == "api_key=<SECRET_1>\n"
    assert second.text == "plain text\n"
    assert final.text == ""
    assert len(second.findings) == 0
    assert len(final.findings) == 0


def test_finding_ids_are_stable_and_continue_across_calls() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    ids = []
    for _ in range(3):
        ids.extend(f.id for f in session.append(f"{OPEN_CONSTRUCT}\n").findings)
    ids.extend(f.id for f in session.finalize().findings)
    assert ids == ["finding-1", "finding-2", "finding-3"]


# ---------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------


def test_policy_receives_only_safe_metadata_with_absolute_offsets() -> None:
    seen: list[tuple] = []

    def policy(
        finding: redact_secret.DetectedFinding,
        context: redact_secret.IncrementalPolicyContext,
    ) -> str:
        seen.append((type(finding).__name__, type(context).__name__, finding.start, context.finding_index))
        assert not hasattr(finding, "value")
        assert not hasattr(finding, "text")
        assert not hasattr(context, "finding_count")
        return redact_secret.default_incremental_policy(finding, context)

    chunks = ["\U0001f511 ", f"{OPEN_CONSTRUCT}\n", f"{OPEN_CONSTRUCT}\n"]
    session = redact_secret.IncrementalSanitizer(generous_limits(), policy)
    for chunk in chunks:
        session.append(chunk)
    session.finalize()

    joined = "".join(chunks)
    expected_starts = [f.start for f in redact_secret.scan(joined)]
    assert [entry[0] for entry in seen] == ["DetectedFinding", "DetectedFinding"]
    assert [entry[1] for entry in seen] == [
        "IncrementalPolicyContext",
        "IncrementalPolicyContext",
    ]
    assert [entry[2] for entry in seen] == expected_starts
    assert [entry[3] for entry in seen] == [0, 1]


def test_default_incremental_policy_agrees_with_the_default_policy() -> None:
    actions: list[str] = []

    def policy(
        finding: redact_secret.DetectedFinding,
        context: redact_secret.IncrementalPolicyContext,
    ) -> str:
        actions.append(redact_secret.default_incremental_policy(finding, context))
        return actions[-1]

    text = f"{OPEN_CONSTRUCT}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    session = redact_secret.IncrementalSanitizer(generous_limits(), policy)
    session.append(text)
    session.finalize()

    assert actions == [f.action for f in redact_secret.scan(text)]


def test_a_policy_override_changes_the_emitted_text() -> None:
    def allow_everything(
        finding: redact_secret.DetectedFinding,
        context: redact_secret.IncrementalPolicyContext,
    ) -> str:
        return "allow"

    session = redact_secret.IncrementalSanitizer(generous_limits(), allow_everything)
    result = session.append(f"{OPEN_CONSTRUCT}\n")
    session.finalize()
    assert result.text == f"{OPEN_CONSTRUCT}\n"
    assert [f.action for f in result.findings] == ["allow"]


def test_formatter_receives_only_safe_metadata_with_absolute_offsets() -> None:
    seen: list[tuple] = []

    def formatter(
        finding: redact_secret.Finding, context: redact_secret.PlaceholderContext
    ) -> str:
        seen.append((type(finding).__name__, finding.start, context.placeholder_index))
        assert not hasattr(finding, "value")
        return redact_secret.typed_placeholder_formatter(finding, context)

    chunks = ["\U0001f511 ", f"{OPEN_CONSTRUCT}\n", f"{OPEN_CONSTRUCT}\n"]
    session = redact_secret.IncrementalSanitizer(generous_limits(), None, formatter)
    text = "".join(session.append(chunk).text for chunk in chunks)
    text += session.finalize().text

    joined = "".join(chunks)
    assert text == redact_secret.scan_and_redact(
        joined, formatter=redact_secret.typed_placeholder_formatter
    ).text
    assert [entry[0] for entry in seen] == ["Finding", "Finding"]
    assert [entry[1] for entry in seen] == [f.start for f in redact_secret.scan(joined)]
    assert [entry[2] for entry in seen] == [1, 2]


@pytest.mark.parametrize(
    ("policy", "expected", "code"),
    [
        pytest.param(
            lambda finding, context: (_ for _ in ()).throw(
                ValueError(f"leak: {RETENTION_MARKER}")
            ),
            "PolicyFailureError",
            "POLICY_FAILURE",
            id="raises",
        ),
        pytest.param(
            lambda finding, context: 1,
            "InvalidPolicyActionError",
            "INVALID_POLICY_ACTION",
            id="non-string",
        ),
        pytest.param(
            lambda finding, context: "delete",
            "InvalidPolicyActionError",
            "INVALID_POLICY_ACTION",
            id="unrecognized",
        ),
    ],
)
def test_a_failing_policy_fails_the_session_without_leaking(
    policy, expected: str, code: str
) -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits(), policy)
    with pytest.raises(getattr(redact_secret, expected)) as excinfo:
        session.append(f"{OPEN_CONSTRUCT}\n")

    assert excinfo.value.code == code
    assert RETENTION_MARKER not in str(excinfo.value)
    assert "leak" not in str(excinfo.value)
    assert session.state == "failed"


@pytest.mark.parametrize(
    ("formatter", "expected", "code"),
    [
        pytest.param(
            lambda finding, context: (_ for _ in ()).throw(
                ValueError(f"leak: {RETENTION_MARKER}")
            ),
            "PlaceholderFailureError",
            "PLACEHOLDER_FAILURE",
            id="raises",
        ),
        pytest.param(
            lambda finding, context: 1,
            "PlaceholderFailureError",
            "PLACEHOLDER_FAILURE",
            id="non-string",
        ),
        pytest.param(
            lambda finding, context: "",
            "InvalidPlaceholderError",
            "INVALID_PLACEHOLDER",
            id="empty",
        ),
        pytest.param(
            lambda finding, context: RETENTION_MARKER,
            "InvalidPlaceholderError",
            "INVALID_PLACEHOLDER",
            id="reproduces-the-matched-value",
        ),
    ],
)
def test_a_failing_formatter_fails_the_session_without_leaking(
    formatter, expected: str, code: str
) -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits(), None, formatter)
    with pytest.raises(getattr(redact_secret, expected)) as excinfo:
        session.append(f"{OPEN_CONSTRUCT}\n")

    assert excinfo.value.code == code
    assert RETENTION_MARKER not in str(excinfo.value)
    assert session.state == "failed"


# ---------------------------------------------------------------------
# Retention: abort and every failure discard plaintext
# ---------------------------------------------------------------------


def _live_marker_strings() -> int:
    """Counts the Python `str` objects that carry the retention marker and
    are not one of this module's own constants, so a session that handed
    retained plaintext back to Python would be visible here."""
    gc.collect()
    return sum(
        1
        for obj in gc.get_objects()
        if isinstance(obj, str)
        and RETENTION_MARKER in obj
        and obj not in (RETENTION_MARKER, OPEN_CONSTRUCT)
    )


def test_abort_leaves_no_marker_bearing_text_reachable() -> None:
    baseline = _live_marker_strings()
    session = redact_secret.IncrementalSanitizer(generous_limits())
    session.append(OPEN_CONSTRUCT)  # no newline: the construct stays open
    session.abort()

    assert session.state == "aborted"
    assert _live_marker_strings() == baseline


def test_a_failure_leaves_no_marker_bearing_text_reachable() -> None:
    baseline = _live_marker_strings()
    exact = len(OPEN_CONSTRUCT)
    limits = redact_secret.IncrementalLimits(
        max_input_bytes=exact,
        max_buffered_bytes=redact_secret.IncrementalLimits.minimum_buffered_bytes(
            exact, exact
        ),
        max_token_bytes=exact,
        max_multiline_bytes=exact,
    )
    session = redact_secret.IncrementalSanitizer(limits)
    session.append(OPEN_CONSTRUCT)  # accepted, retained, still open
    with pytest.raises(redact_secret.InputLimitExceededError):
        session.append("x")

    assert session.state == "failed"
    assert _live_marker_strings() == baseline


def test_an_aborted_session_emits_nothing_it_had_retained() -> None:
    """The stronger half of the retention contract: what was held open is
    not merely unreachable, it is never emitted."""
    session = redact_secret.IncrementalSanitizer(generous_limits())
    emitted = session.append(OPEN_CONSTRUCT).text
    session.abort()
    assert emitted == ""


def test_a_repr_never_carries_retained_text() -> None:
    session = redact_secret.IncrementalSanitizer(generous_limits())
    session.append(OPEN_CONSTRUCT)
    assert RETENTION_MARKER not in repr(session)
    assert repr(session) == 'IncrementalSanitizer(state="accepting")'
