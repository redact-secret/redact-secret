"""Asserts the Python binding against the shared action policy conformance
fixture (`conformance/fixtures/action-policy-v1.json`, issue #1219,
`decision-define-the-versioned-declarative-action-policy-and-default-overlay`):
the same fixture `crates/secret-scan-core/tests/action_policy_conformance.rs`
asserts on the Rust core.

The Rust core runs the fixture for semantics. This binding runs it for
plumbing, through the public API: every rejection with its exact class and
rule index, every accepted edge document, the five end-to-end cases (whole
input, every accepted input form, and incremental sessions under several
partitions), and the host obligations that belong to Python. The fixture's
`evaluations` table needs a finding built without scanning, which Python cannot
do; `bindings/python/src/lib.rs` runs it as a unit test over the same
evaluator this package calls.

`base` in the fixture is a sentinel. It is resolved here by what the same input
yields with no policy at all, and cross-checked against `default_policy`, never
by a copy of the default table.

Every document, finding and input here is synthetic.
"""

from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import pytest
import redact_secret

from .conftest import byte_offset_to_char_offset_reference, load_corpus

GITHUB_INPUT = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000"
ALLOW_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "allow-github", "match": {"type": ["github_token"]}, "action": "allow"}],
}
BLOCK_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "block-github", "match": {"type": ["github_token"]}, "action": "block"}],
}
EMPTY_RULES = {"actionPolicyRevision": 1, "base": "default", "rules": []}


def _fixture() -> dict[str, Any]:
    return load_corpus("action-policy-v1.json")


def _compact(document: Any) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _named_policy(fixture: dict[str, Any], policy_id: str) -> dict[str, Any]:
    return next(policy for policy in fixture["policies"] if policy["id"] == policy_id)


def _document_bytes(entry: dict[str, Any]) -> bytes:
    """The bytes a host hands the core for a fixture entry: raw text, a compact
    serialization of a JSON document, or one synthesized at a bound."""
    if "documentText" in entry:
        return entry["documentText"].encode("utf-8")
    if "document" in entry:
        return _compact(entry["document"])
    synthesis = entry["synthesis"]
    kind = synthesis["kind"]
    if kind == "padded":
        base = synthesis["base"].encode("utf-8")
        assert len(base) <= synthesis["totalBytes"]
        return base + b" " * (synthesis["totalBytes"] - len(base))
    if kind == "rule-count":
        rules = ",".join(
            f'{{"id":"r{index}","match":{{"type":["jwt"]}},"action":"warn"}}' for index in range(synthesis["count"])
        )
        return f'{{"actionPolicyRevision":1,"base":"default","rules":[{rules}]}}'.encode()
    assert kind == "set-size"
    members = ",".join(f'"t{index}"' for index in range(synthesis["count"]))
    return (
        '{"actionPolicyRevision":1,"base":"default","rules":'
        f'[{{"id":"r","match":{{"type":[{members}]}},"action":"warn"}}]}}'
    ).encode()


def _policy_document(fixture: dict[str, Any], reference: Any) -> Any:
    return _named_policy(fixture, reference)["document"] if isinstance(reference, str) else reference


def _spans_to_text(text: str, spans: list[tuple[int, int, str]]) -> str:
    """The expected sanitized text: `redact` and `block` spans become numbered
    placeholders; `warn` and `allow` spans are untouched and take no number."""
    out = []
    cursor = 0
    number = 0
    for start, end, action in spans:
        if action in ("redact", "block"):
            number += 1
            out.append(text[cursor:start])
            out.append(f"<SECRET_{number}>")
            cursor = end
    out.append(text[cursor:])
    return "".join(out)


# ---------------------------------------------------------------------
# The fixture agrees with the package's own constants
# ---------------------------------------------------------------------


def test_the_fixture_error_code_and_message_match_the_exception() -> None:
    fixture = _fixture()
    assert redact_secret.InvalidActionPolicyError.code == fixture["errorCode"] == "INVALID_ACTION_POLICY"
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy=b"{")
    assert str(excinfo.value) == fixture["errorMessage"]
    assert issubclass(redact_secret.InvalidActionPolicyError, redact_secret.SecretScanError)
    assert "InvalidActionPolicyError" in redact_secret.__all__


def test_the_exception_defaults_and_instances_are_content_free() -> None:
    assert redact_secret.InvalidActionPolicyError.error_class is None
    assert redact_secret.InvalidActionPolicyError.rule_index is None
    secret = "ghp_SYNTHETICREVOKED00000000000000000000"
    document = f'{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"{secret}"}}]}}'
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan(GITHUB_INPUT, action_policy=document)
    error = excinfo.value
    assert error.error_class == "INVALID_IDENTIFIER"
    assert error.rule_index == 0
    assert secret not in str(error) + repr(error) + error.error_class
    assert error.args == ("The supplied action policy is invalid.",)
    for clone in (copy.copy(error), pickle.loads(pickle.dumps(error))):
        assert clone.error_class == "INVALID_IDENTIFIER"
        assert clone.rule_index == 0
        assert clone.code == "INVALID_ACTION_POLICY"


# ---------------------------------------------------------------------
# Rejections and accepted documents
# ---------------------------------------------------------------------


def test_every_rejection_reports_its_exact_class_and_rule_index() -> None:
    fixture = _fixture()
    first = fixture["rejections"]
    additional = fixture["additionalRejections"]
    assert len(first) == 17
    assert len(additional) == 41
    # One first rejection per class.
    assert len({case["class"] for case in first}) == 17

    for case in first + additional:
        document = _document_bytes(case)
        # The same bytes through every call and session entry point, in every
        # accepted byte-oriented form.
        forms: list[Any] = [document, bytearray(document)]
        try:
            forms.append(document.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        for form in forms:
            for call in (
                lambda value: redact_secret.scan(GITHUB_INPUT, action_policy=value),
                lambda value: redact_secret.scan_and_redact(GITHUB_INPUT, action_policy=value),
                lambda value: redact_secret.IncrementalSanitizer(_limits(), action_policy=value),
            ):
                with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
                    call(form)
                error = excinfo.value
                assert error.code == fixture["errorCode"], case["id"]
                assert str(error) == fixture["errorMessage"], case["id"]
                assert error.error_class == case["class"], case["id"]
                assert error.rule_index == case["ruleIndex"], case["id"]


def test_a_rejected_document_through_a_dict_reports_the_same_class_and_index() -> None:
    # The fixture writes its rejections as text; a dict is exercised on a
    # handful of bad shapes built here, one per kind of violation.
    dicts = {
        "UNKNOWN_FIELD": ({"actionPolicyRevision": 1, "base": "default", "rules": [], "extra": 1}, None),
        "MISSING_FIELD": ({"base": "default", "rules": []}, None),
        "UNKNOWN_REVISION": ({"actionPolicyRevision": 2, "base": "default", "rules": []}, None),
        "WRONG_TYPE": ({"actionPolicyRevision": 1, "base": "default", "rules": {}}, None),
        "INVALID_ACTION": (
            {
                "actionPolicyRevision": 1,
                "base": "default",
                "rules": [{"id": "r", "match": {"type": ["jwt"]}, "action": "mask"}],
            },
            0,
        ),
        "EMPTY_MATCH": (
            {"actionPolicyRevision": 1, "base": "default", "rules": [{"id": "r", "match": {}, "action": "warn"}]},
            0,
        ),
    }
    for expected_class, (document, expected_index) in dicts.items():
        with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
            redact_secret.scan("", action_policy=document)
        assert excinfo.value.error_class == expected_class
        assert excinfo.value.rule_index == expected_index


def test_every_named_policy_and_accepted_document_loads_in_every_form() -> None:
    fixture = _fixture()
    accepted = fixture["acceptedDocuments"]
    assert len(accepted) == 7
    at_limit = next(document for document in accepted if document["id"] == "document-at-byte-limit")
    assert len(_document_bytes(at_limit)) == fixture["limits"]["maxDocumentBytes"]

    for entry in fixture["policies"] + accepted:
        document = _document_bytes(entry)
        for form in (document, bytearray(document), document.decode("utf-8")):
            assert redact_secret.scan(GITHUB_INPUT, action_policy=form) is not None, entry["id"]
        # Construction validates once and accepts the same document.
        redact_secret.IncrementalSanitizer(_limits(), action_policy=document).abort()
        if "document" in entry:
            assert redact_secret.scan(GITHUB_INPUT, action_policy=entry["document"]) is not None, entry["id"]


def test_the_byte_bound_is_checked_exactly() -> None:
    padded = b'{"actionPolicyRevision":1,"base":"default","rules":[]}'
    assert redact_secret.scan("", action_policy=padded + b" " * (65536 - len(padded))) == []
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy=padded + b" " * (65537 - len(padded)))
    assert excinfo.value.error_class == "ACTION_POLICY_TOO_LARGE"
    assert excinfo.value.rule_index is None


# ---------------------------------------------------------------------
# Accepted input forms and their failures
# ---------------------------------------------------------------------


def test_dict_str_bytes_and_bytearray_give_the_same_result() -> None:
    document = _compact(ALLOW_GITHUB)
    results = [
        redact_secret.scan_and_redact(GITHUB_INPUT, action_policy=form)
        for form in (ALLOW_GITHUB, document.decode("utf-8"), document, bytearray(document))
    ]
    for result in results:
        assert result.text == GITHUB_INPUT
        assert [finding.action for finding in result.findings] == ["allow"]


def test_a_dict_that_the_standard_encoder_cannot_serialize_is_malformed_document() -> None:
    circular: dict[str, Any] = {"actionPolicyRevision": 1, "base": "default"}
    circular["rules"] = circular
    unserializable: list[Any] = [
        {"actionPolicyRevision": 1, "base": "default", "rules": {"a"}},
        {"actionPolicyRevision": 1, "base": "default", "rules": b"bytes"},
        {"actionPolicyRevision": 1, "base": "default", "rules": [object()]},
        {("a", "tuple"): 1},
        circular,
    ]
    for value in unserializable:
        for call in (
            lambda v: redact_secret.scan("", action_policy=v),
            lambda v: redact_secret.IncrementalSanitizer(_limits(), action_policy=v),
        ):
            with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
                call(value)
            assert excinfo.value.error_class == "MALFORMED_DOCUMENT"
            assert excinfo.value.rule_index is None


def test_a_str_that_is_not_utf_8_encodable_is_malformed_document() -> None:
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy='{"actionPolicyRevision":1,"base":"default","rules":[]}\ud800')
    assert excinfo.value.error_class == "MALFORMED_DOCUMENT"
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy=b"\xff\xfe")
    assert excinfo.value.error_class == "MALFORMED_DOCUMENT"


def test_a_dict_serializes_to_the_compact_encoding_in_insertion_order() -> None:
    # The revision must be the first member: a dict that lists it later is the
    # core's MISSING_FIELD, so insertion order is the document's member order.
    reordered = {"base": "default", "actionPolicyRevision": 1, "rules": []}
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy=reordered)
    assert excinfo.value.error_class == "MISSING_FIELD"
    # A non-ASCII string is `\uXXXX`-escaped by the standard encoder and so is
    # rejected as an escape, the same class a raw non-ASCII byte gets.
    non_ascii = {"actionPolicyRevision": 1, "base": "default", "rules": [{"id": "café"}]}
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        redact_secret.scan("", action_policy=non_ascii)
    assert excinfo.value.error_class == "MALFORMED_DOCUMENT"


@pytest.mark.parametrize("value", [1, 1.5, True, [], ["a"], (), memoryview(b"{}"), object(), frozenset()])
def test_any_other_type_is_invalid_options_never_ignored(value: object) -> None:
    for call in (
        lambda: redact_secret.scan(GITHUB_INPUT, action_policy=value),  # type: ignore[arg-type]
        lambda: redact_secret.scan_and_redact(GITHUB_INPUT, action_policy=value),  # type: ignore[arg-type]
        lambda: redact_secret.IncrementalSanitizer(_limits(), action_policy=value),  # type: ignore[arg-type]
    ):
        with pytest.raises(redact_secret.InvalidOptionsError) as excinfo:
            call()
        assert excinfo.value.code == "INVALID_OPTIONS"


def test_none_is_no_overlay_and_matches_a_call_without_the_option() -> None:
    plain = redact_secret.scan_and_redact(GITHUB_INPUT)
    none = redact_secret.scan_and_redact(GITHUB_INPUT, action_policy=None)
    assert (none.text, [f.action for f in none.findings]) == (plain.text, [f.action for f in plain.findings])


def test_the_option_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        redact_secret.scan(GITHUB_INPUT, None, None, None, ALLOW_GITHUB)  # type: ignore[misc]
    with pytest.raises(TypeError):
        redact_secret.scan_and_redact(GITHUB_INPUT, None, None, None, None, ALLOW_GITHUB)  # type: ignore[misc]
    with pytest.raises(TypeError):
        redact_secret.IncrementalSanitizer(_limits(), None, None, ALLOW_GITHUB)  # type: ignore[misc]


def test_input_type_is_still_checked_first() -> None:
    with pytest.raises(redact_secret.InvalidInputError):
        redact_secret.scan(b"bytes", action_policy="{")  # type: ignore[arg-type]


# ---------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------


def _limits() -> redact_secret.IncrementalLimits:
    return redact_secret.IncrementalLimits(
        max_input_bytes=1 << 20,
        max_buffered_bytes=redact_secret.IncrementalLimits.minimum_buffered_bytes(1 << 16, 1 << 16),
        max_token_bytes=1 << 16,
        max_multiline_bytes=1 << 16,
    )


def _incremental(policy: Any, partition: list[str]) -> tuple[str, list[redact_secret.Finding]]:
    session = redact_secret.IncrementalSanitizer(_limits(), action_policy=policy)
    out = ""
    found: list[redact_secret.Finding] = []
    for chunk in partition:
        result = session.append(chunk)
        out += result.text
        found.extend(result.findings)
    result = session.finalize()
    out += result.text
    found.extend(result.findings)
    return out, found


def test_every_end_to_end_case_matches_whole_input_and_incremental() -> None:
    fixture = _fixture()
    end_to_end = fixture["endToEnd"]
    cases = end_to_end["cases"]
    assert len(cases) == 5

    for case in cases:
        case_id = case["id"]
        text = case["input"]
        document = _policy_document(fixture, case["policy"])
        compact = _compact(document)
        ruleset = end_to_end["ruleset"].encode("utf-8") if case.get("useRuleset") else None

        # `base` resolves to what the same input yields with no policy at all.
        unpoliced = redact_secret.scan(text, ruleset=ruleset)
        expected = case["expectedFindings"]
        assert len(unpoliced) == len(expected), case_id

        spans: list[tuple[int, int, str]] = []
        for index, want in enumerate(expected):
            want_action = unpoliced[index].action if want["expectedAction"] == "base" else want["expectedAction"]
            start = byte_offset_to_char_offset_reference(text, want["start"])
            end = byte_offset_to_char_offset_reference(text, want["end"])
            spans.append((start, end, want_action))

        # Every accepted input form agrees.
        for form in (document, compact, compact.decode("utf-8"), bytearray(compact)):
            findings = redact_secret.scan(text, ruleset=ruleset, action_policy=form)
            assert len(findings) == len(expected), case_id
            for finding, want, (start, end, want_action) in zip(findings, expected, spans, strict=True):
                assert (finding.type, finding.detector) == (want["type"], want["detector"]), case_id
                assert (finding.confidence, finding.obfuscation) == (want["confidence"], want["obfuscation"]), case_id
                assert (finding.start, finding.end) == (start, end), case_id
                assert finding.action == want_action, case_id

            result = redact_secret.scan_and_redact(text, ruleset=ruleset, action_policy=form)
            assert result.text == _spans_to_text(text, spans), case_id
            assert [finding.action for finding in result.findings] == [action for _, _, action in spans], case_id

        # A document with no rules changes nothing about a no-policy result.
        plain = redact_secret.scan_and_redact(text, ruleset=ruleset)
        empty = redact_secret.scan_and_redact(text, ruleset=ruleset, action_policy=EMPTY_RULES)
        assert empty.text == plain.text, case_id
        assert [(f.type, f.action, f.start, f.end) for f in empty.findings] == [
            (f.type, f.action, f.start, f.end) for f in plain.findings
        ], case_id

        if not case.get("alsoIncremental"):
            assert ruleset is not None, case_id
            continue

        partitions: list[list[str]] = [[text], list(text)]
        partitions.extend([text[:cut], text[cut:]] for cut in range(0, len(text) + 1, 5))
        if text.isascii():
            partitions.append([text[index : index + 7] for index in range(0, len(text), 7)])
        for partition in partitions:
            for form in (document, compact):
                out, found = _incremental(form, partition)
                assert out == _spans_to_text(text, spans), (case_id, partition)
                assert len(found) == len(expected), (case_id, partition)
                for got, (start, end, want_action) in zip(found, spans, strict=True):
                    assert (got.start, got.end, got.action) == (start, end, want_action), (case_id, partition)


def test_the_base_matches_default_policy_for_every_end_to_end_finding() -> None:
    """The empty document is the declarative default: it agrees with the
    package's public `default_policy` on every finding the fixture scans."""
    fixture = _fixture()
    for case in fixture["endToEnd"]["cases"]:
        ruleset = fixture["endToEnd"]["ruleset"].encode("utf-8") if case.get("useRuleset") else None
        seen: list[str] = []

        def callback(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
            action = redact_secret.default_policy(finding, context)
            seen.append(action)
            return action

        via_callback = redact_secret.scan(case["input"], policy=callback, ruleset=ruleset)
        via_empty = redact_secret.scan(case["input"], ruleset=ruleset, action_policy=EMPTY_RULES)
        assert [f.action for f in via_callback] == [f.action for f in via_empty] == seen, case["id"]


def test_the_default_action_rule_keeps_the_base_and_an_unnamed_type_falls_to_it() -> None:
    document = {
        "actionPolicyRevision": 1,
        "base": "default",
        "rules": [
            {"id": "keep-default-github", "match": {"type": ["github_token"]}, "action": "default"},
            {"id": "allow-high", "match": {"confidence": ["high"]}, "action": "allow"},
        ],
    }
    default = redact_secret.scan(GITHUB_INPUT)[0].action
    assert redact_secret.scan(GITHUB_INPUT, action_policy=document)[0].action == default
    # A name no built-in emits loads, never matches, and leaves the base.
    typo = {
        "actionPolicyRevision": 1,
        "base": "default",
        "rules": [{"id": "typo", "match": {"type": ["github-token"]}, "action": "allow"}],
    }
    assert redact_secret.scan(GITHUB_INPUT, action_policy=typo)[0].action == default


def test_the_python_guide_example_runs_as_written() -> None:
    """The example in `docs/guides/python.md#declarative-action-policy`."""
    result = redact_secret.scan_and_redact(
        "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE",
        formatter=redact_secret.typed_placeholder_formatter,
        action_policy={
            "actionPolicyRevision": 1,
            "base": "default",
            "rules": [{"id": "warn-contextual", "match": {"type": ["contextual_secret"]}, "action": "warn"}],
        },
    )
    assert result.text == "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE"
    assert [finding.action for finding in result.findings] == ["warn"]


def test_public_findings_gain_no_field() -> None:
    finding = redact_secret.scan(GITHUB_INPUT, action_policy=ALLOW_GITHUB)[0]
    public = {name for name in dir(finding) if not name.startswith("_")}
    assert public == {"id", "type", "detector", "confidence", "action", "obfuscation", "start", "end"}


# ---------------------------------------------------------------------
# Host obligations
# ---------------------------------------------------------------------


def test_the_host_obligation_ids_are_the_ones_this_suite_covers() -> None:
    ids = {obligation["id"] for obligation in _fixture()["hostObligations"]}
    assert ids == {
        "legacy-callback-replaces-the-default",
        "legacy-callback-throws",
        "legacy-callback-invalid-action",
        "callback-and-action-policy-together",
        "invalid-document-fails-before-scanning",
        "session-binds-policy-at-construction",
        "no-process-global-policy-slot",
    }
    codes = {obligation["id"]: obligation["expectedCode"] for obligation in _fixture()["hostObligations"]}
    assert codes["legacy-callback-throws"] == redact_secret.PolicyFailureError.code
    assert codes["legacy-callback-invalid-action"] == redact_secret.InvalidPolicyActionError.code
    assert codes["callback-and-action-policy-together"] == redact_secret.InvalidOptionsError.code
    assert codes["invalid-document-fails-before-scanning"] == redact_secret.InvalidActionPolicyError.code


def test_legacy_callback_replaces_the_default() -> None:
    def allow_all(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        return "allow"

    assert redact_secret.scan(GITHUB_INPUT, policy=allow_all)[0].action == "allow"
    result = redact_secret.scan_and_redact(GITHUB_INPUT, policy=allow_all)
    assert result.text == GITHUB_INPUT
    session = redact_secret.IncrementalSanitizer(_limits(), lambda finding, context: "block")
    out = session.append(GITHUB_INPUT).text + session.finalize().text
    assert out == "API_KEY=<SECRET_1>"


def test_legacy_callback_throws_and_invalid_action_keep_their_existing_codes() -> None:
    def throws(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        raise RuntimeError(GITHUB_INPUT)

    def invalid(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        return "mask"

    with pytest.raises(redact_secret.PolicyFailureError) as excinfo:
        redact_secret.scan(GITHUB_INPUT, policy=throws)
    assert excinfo.value.code == "POLICY_FAILURE"
    with pytest.raises(redact_secret.InvalidPolicyActionError) as excinfo:
        redact_secret.scan(GITHUB_INPUT, policy=invalid)
    assert excinfo.value.code == "INVALID_POLICY_ACTION"
    with pytest.raises(redact_secret.InvalidPolicyActionError):
        redact_secret.scan_and_redact(GITHUB_INPUT, policy=invalid)
    session = redact_secret.IncrementalSanitizer(_limits(), invalid)
    with pytest.raises(redact_secret.InvalidPolicyActionError):
        session.append(GITHUB_INPUT)
        session.finalize()
    session = redact_secret.IncrementalSanitizer(_limits(), throws)
    with pytest.raises(redact_secret.PolicyFailureError):
        session.append(GITHUB_INPUT)
        session.finalize()


def test_a_callback_and_an_action_policy_together_are_invalid_options_before_any_scan() -> None:
    calls: list[str] = []

    def callback(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        calls.append(finding.id)
        return "redact"

    def incremental_callback(
        finding: redact_secret.DetectedFinding, context: redact_secret.IncrementalPolicyContext
    ) -> str:
        calls.append(finding.id)
        return "redact"

    for document in (ALLOW_GITHUB, _compact(ALLOW_GITHUB), b"{", "not a document", 5):
        with pytest.raises(redact_secret.InvalidOptionsError) as excinfo:
            redact_secret.scan(GITHUB_INPUT, policy=callback, action_policy=document)  # type: ignore[arg-type]
        assert excinfo.value.code == "INVALID_OPTIONS"
        with pytest.raises(redact_secret.InvalidOptionsError):
            redact_secret.scan_and_redact(GITHUB_INPUT, policy=callback, action_policy=document)  # type: ignore[arg-type]
        with pytest.raises(redact_secret.InvalidOptionsError):
            redact_secret.IncrementalSanitizer(_limits(), incremental_callback, action_policy=document)  # type: ignore[arg-type]
        with pytest.raises(redact_secret.InvalidOptionsError):
            redact_secret.IncrementalSanitizer(_limits(), policy=incremental_callback, action_policy=document)  # type: ignore[arg-type]
    assert calls == []


def test_an_invalid_document_fails_before_scanning_and_never_falls_back() -> None:
    calls: list[str] = []

    def formatter(finding: redact_secret.Finding, context: redact_secret.PlaceholderContext) -> str:
        calls.append(finding.id)
        return "<X>"

    with pytest.raises(redact_secret.InvalidActionPolicyError):
        redact_secret.scan_and_redact(GITHUB_INPUT, formatter=formatter, action_policy=b"{")
    # Input limits are not consulted first: the document is read, and rejected,
    # before the (here impossible) input bound.
    tiny = redact_secret.WholeInputLimits(max_input_bytes=1, max_findings=1)
    with pytest.raises(redact_secret.InvalidActionPolicyError):
        redact_secret.scan(GITHUB_INPUT, limits=tiny, action_policy=b"{")
    assert calls == []


def test_a_session_binds_its_policy_at_construction() -> None:
    mutable = copy.deepcopy(BLOCK_GITHUB)
    session = redact_secret.IncrementalSanitizer(_limits(), action_policy=mutable)
    # Later mutation of the native object, and later policies, change nothing.
    mutable["rules"][0]["action"] = "allow"
    other = redact_secret.IncrementalSanitizer(_limits(), action_policy=ALLOW_GITHUB)
    out = session.append(GITHUB_INPUT).text + session.finalize().text
    assert out == "API_KEY=<SECRET_1>"
    assert other.append(GITHUB_INPUT).text + other.finalize().text == GITHUB_INPUT

    # A whole-input call serializes at the call, so mutating afterwards is moot
    # and nothing is retained between calls.
    first = redact_secret.scan(GITHUB_INPUT, action_policy=mutable)[0].action
    mutable["rules"][0]["action"] = "block"
    second = redact_secret.scan(GITHUB_INPUT, action_policy=mutable)[0].action
    assert (first, second) == ("allow", "block")


def test_there_is_no_process_global_policy_slot() -> None:
    for swap in (False, True):
        first, second = (ALLOW_GITHUB, BLOCK_GITHUB) if swap else (BLOCK_GITHUB, ALLOW_GITHUB)
        one = redact_secret.IncrementalSanitizer(_limits(), action_policy=first)
        two = redact_secret.IncrementalSanitizer(_limits(), action_policy=second)
        # Interleave a whole-input call that compiles a third document and a
        # rejected document between the two sessions.
        assert redact_secret.scan(GITHUB_INPUT, action_policy=EMPTY_RULES)[0].action == "redact"
        with pytest.raises(redact_secret.InvalidActionPolicyError):
            redact_secret.scan(GITHUB_INPUT, action_policy=b"{")
        a = one.append(GITHUB_INPUT).text + one.finalize().text
        b = two.append(GITHUB_INPUT).text + two.finalize().text
        want_first, want_second = ("allow", "block") if swap else ("block", "allow")
        rendered = {"allow": GITHUB_INPUT, "block": "API_KEY=<SECRET_1>"}
        assert (a, b) == (rendered[want_first], rendered[want_second])
        assert [f.action for f in redact_secret.scan(GITHUB_INPUT, action_policy=first)] == [want_first]
        assert [f.action for f in redact_secret.scan(GITHUB_INPUT, action_policy=second)] == [want_second]


def test_a_policy_never_resurrects_an_overlap_loser() -> None:
    """The fixture's overlap case, with the winner allowed: the loser stays
    unreported and the text is unchanged (the end-to-end test asserts the
    same through every input form; this pins the finding count)."""
    case = next(c for c in _fixture()["endToEnd"]["cases"] if c["id"] == "overlap-loser-is-never-an-input")
    result = redact_secret.scan_and_redact(case["input"], action_policy=case["policy"])
    assert result.text == case["input"]
    assert [(f.type, f.action) for f in result.findings] == [("bearer_token", "allow")]
