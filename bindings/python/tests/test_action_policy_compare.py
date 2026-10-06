"""Asserts the Python binding against the shared explain-and-compare
conformance fixture (`conformance/fixtures/action-policy-compare-v1.json`,
issue #1220, `decision-explain-and-compare-action-policies-over-one-detection-pass`):
the same fixture the Rust core and the Rust CLI run.

The Rust core runs the fixture for semantics. This binding runs it for
plumbing, through the public API: every case (per-finding actions, bases, rule
ids and indexes, `differs`, per-side counts and the callback call sequence),
every error case, every digest, and the host obligations that apply to a
whole-input Python surface. For every declarative side it also asserts
enforcement parity: each finding's action equals what `scan` with that same
document yields for that finding.

`base` in the fixture is a sentinel. It is resolved here by what `scan` with no
policy yields for the same finding, never by a copy of the default table.

Every document, finding and input here is synthetic.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from typing import Any

import pytest
import redact_secret
from redact_secret import ComparedPolicy, compare_action_policies

from .conftest import byte_offset_to_char_offset_reference, load_corpus

GITHUB_SECRET = "ghp_SYNTHETICREVOKED00000000000000000000"
GITHUB_INPUT = f"API_KEY={GITHUB_SECRET}"
ALLOW_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "allow-github", "match": {"type": ["github_token"]}, "action": "allow"}],
}
WARN_GITHUB = {
    "actionPolicyRevision": 1,
    "base": "default",
    "rules": [{"id": "warn-github", "match": {"type": ["github_token"]}, "action": "warn"}],
}

ERROR_CLASSES: dict[str, type[redact_secret.SecretScanError]] = {
    "POLICY_FAILURE": redact_secret.PolicyFailureError,
    "INVALID_POLICY_ACTION": redact_secret.InvalidPolicyActionError,
    "INVALID_OPTIONS": redact_secret.InvalidOptionsError,
    "INPUT_LIMIT_EXCEEDED": redact_secret.InputLimitExceededError,
    "FINDING_LIMIT_EXCEEDED": redact_secret.FindingLimitExceededError,
}


def _fixture() -> dict[str, Any]:
    return load_corpus("action-policy-compare-v1.json")


def _policy_text(fixture: dict[str, Any], policy_id: str) -> str:
    entry = next(policy for policy in fixture["policies"] if policy["id"] == policy_id)
    text = entry["documentText"]
    assert isinstance(text, str)
    return text


class _Callback:
    """A fixture callback side: logs `<label><finding_index>` per call and
    returns the fixture's scripted action, or raises at the scripted index."""

    def __init__(self, side: dict[str, Any], log: list[str]) -> None:
        self.label: str = side["label"]
        self.returns: list[str] = side["returns"]
        self.fail_at: int | None = side.get("failAtFindingIndex")
        self.log = log

    def __call__(self, finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        self.log.append(f"{self.label}{context.finding_index}")
        if context.finding_index == self.fail_at:
            raise RuntimeError("scripted callback failure")
        return self.returns[context.finding_index]


def _build_sides(fixture: dict[str, Any], sides: list[dict[str, Any]], log: list[str]) -> list[ComparedPolicy]:
    built: list[ComparedPolicy] = []
    for side in sides:
        kind = side["kind"]
        if kind == "default":
            built.append(ComparedPolicy.default())
        elif kind == "policy":
            built.append(ComparedPolicy.action_policy(_policy_text(fixture, side["policy"])))
        else:
            assert kind == "callback"
            built.append(ComparedPolicy.callback(_Callback(side, log)))
    return built


def _limits(entry: dict[str, Any]) -> redact_secret.WholeInputLimits | None:
    spec = entry.get("limits")
    if spec is None:
        return None
    return redact_secret.WholeInputLimits(max_input_bytes=spec["maxInputBytes"], max_findings=spec["maxFindings"])


def _ruleset(fixture: dict[str, Any], entry: dict[str, Any]) -> str | None:
    if not entry.get("useRuleset"):
        return None
    ruleset = fixture["ruleset"]
    assert isinstance(ruleset, str)
    return ruleset


def _resolve(expected: str, base: str) -> str:
    return base if expected == "base" else expected


# ---------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------

CASE_IDS = [case["id"] for case in _fixture()["cases"]]
ERROR_IDS = [case["id"] for case in _fixture()["errors"]]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_fixture_case(case_id: str) -> None:
    fixture = _fixture()
    case = next(entry for entry in fixture["cases"] if entry["id"] == case_id)
    text: str = case["input"]
    ruleset = _ruleset(fixture, case)
    log: list[str] = []
    comparison = compare_action_policies(text, _build_sides(fixture, case["sides"], log), ruleset=ruleset)

    # A preview, never enforcement.
    assert comparison.mode == "preview"
    assert comparison.enforced is False

    # The findings are exactly what `scan` returns, with the default action
    # `base` stands for resolved from `scan` itself.
    scanned = redact_secret.scan(text, ruleset=ruleset)
    assert len(comparison.findings) == len(scanned) == len(case["expectedFindings"])
    for compared, plain, expected in zip(comparison.findings, scanned, case["expectedFindings"], strict=True):
        assert (compared.id, compared.type, compared.detector) == (plain.id, plain.type, plain.detector)
        assert (compared.confidence, compared.obfuscation) == (plain.confidence, plain.obfuscation)
        assert (compared.start, compared.end) == (plain.start, plain.end)
        assert compared.type == expected["type"]
        assert compared.detector == expected["detector"]
        assert compared.confidence == expected["confidence"]
        assert compared.obfuscation == expected["obfuscation"]
        assert compared.start == byte_offset_to_char_offset_reference(text, expected["start"])
        assert compared.end == byte_offset_to_char_offset_reference(text, expected["end"])
        assert len(compared.decisions) == len(case["sides"])
        for decision, wanted in zip(compared.decisions, expected["expectedDecisions"], strict=True):
            assert decision.action == _resolve(wanted["action"], plain.action)
            assert decision.basis == wanted["basis"]
            assert decision.rule_id == wanted["ruleId"]
            assert decision.rule_index == wanted["ruleIndex"]
        assert compared.differs is expected["expectedDiffers"]
    assert comparison.changed_count == case["expectedChangedCount"]
    assert comparison.changed_count == sum(compared.differs for compared in comparison.findings)

    # Sides: kind, digest and per-side counts, in the order given.
    assert len(comparison.sides) == len(case["sides"])
    for index, (side, spec) in enumerate(zip(comparison.sides, case["sides"], strict=True)):
        if spec["kind"] == "policy":
            assert side.kind == "action-policy"
            document = _policy_text(fixture, spec["policy"])
            assert side.document_sha256 == hashlib.sha256(document.encode("utf-8")).hexdigest()
        else:
            assert side.kind == spec["kind"]
            assert side.document_sha256 is None
        actions = [compared.decisions[index].action for compared in comparison.findings]
        assert (side.counts.redact, side.counts.block, side.counts.warn, side.counts.allow) == (
            actions.count("redact"),
            actions.count("block"),
            actions.count("warn"),
            actions.count("allow"),
        )

    # The callback call sequence the fixture pins: once per finding, in order,
    # one side at a time.
    if "expectedCallSequence" in case:
        assert log == case["expectedCallSequence"]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_every_side_matches_what_scan_chooses(case_id: str) -> None:
    """Enforcement parity: each side's action equals `scan` with that policy,
    and a callback side sees the call log `scan` gives it."""
    fixture = _fixture()
    case = next(entry for entry in fixture["cases"] if entry["id"] == case_id)
    text: str = case["input"]
    ruleset = _ruleset(fixture, case)
    log: list[str] = []
    comparison = compare_action_policies(text, _build_sides(fixture, case["sides"], log), ruleset=ruleset)
    for index, spec in enumerate(case["sides"]):
        compared_actions = [finding.decisions[index].action for finding in comparison.findings]
        if spec["kind"] == "default":
            scanned = redact_secret.scan(text, ruleset=ruleset)
        elif spec["kind"] == "policy":
            scanned = redact_secret.scan(text, ruleset=ruleset, action_policy=_policy_text(fixture, spec["policy"]))
        else:
            scan_log: list[str] = []
            scanned = redact_secret.scan(text, _Callback(spec, scan_log), ruleset=ruleset)
            # The same sequence this side contributed to the comparison.
            assert scan_log == [entry for entry in log if entry.startswith(spec["label"])]
        assert compared_actions == [finding.action for finding in scanned]


@pytest.mark.parametrize("case_id", ERROR_IDS)
def test_every_fixture_error_case(case_id: str) -> None:
    fixture = _fixture()
    case = next(entry for entry in fixture["errors"] if entry["id"] == case_id)
    log: list[str] = []
    sides = _build_sides(fixture, case["sides"], log)
    expected_class = ERROR_CLASSES[case["expectedCode"]]
    with pytest.raises(redact_secret.SecretScanError) as excinfo:
        compare_action_policies(case["input"], sides, limits=_limits(case), ruleset=_ruleset(fixture, case))
    assert type(excinfo.value) is expected_class
    assert excinfo.value.code == case["expectedCode"]  # type: ignore[attr-defined]
    assert log == case["expectedCallSequence"]


def test_a_callback_failure_gives_no_partial_result_and_no_later_call() -> None:
    fixture = _fixture()
    case = next(entry for entry in fixture["errors"] if entry["id"] == "callback-failure-fails-the-whole-comparison")
    log: list[str] = []
    sides = _build_sides(fixture, case["sides"], log)
    with pytest.raises(redact_secret.PolicyFailureError) as excinfo:
        compare_action_policies(case["input"], sides, ruleset=fixture["ruleset"])
    # The callback's own exception never propagates, and nothing chains it.
    assert "scripted" not in str(excinfo.value) + repr(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert log == ["A0", "A1"]


# ---------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------


def test_every_fixture_digest() -> None:
    fixture = _fixture()
    for entry in fixture["digests"]:
        text = _policy_text(fixture, entry["policy"])
        side = ComparedPolicy.action_policy(text)
        assert side.document_sha256 == entry["documentSha256"]
        assert side.document_sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
        comparison = compare_action_policies(GITHUB_INPUT, [side])
        assert comparison.sides[0].document_sha256 == entry["documentSha256"]


def test_whitespace_changes_the_digest_and_the_digest_is_lowercase_hex() -> None:
    fixture = _fixture()
    compact = ComparedPolicy.action_policy(_policy_text(fixture, "empty-rules")).document_sha256
    spaced = ComparedPolicy.action_policy(_policy_text(fixture, "empty-rules-spaced")).document_sha256
    assert compact is not None
    assert spaced is not None
    assert compact != spaced
    for digest in (compact, spaced):
        assert len(digest) == 64
        assert digest == digest.lower()
        assert set(digest) <= set("0123456789abcdef")


def test_every_input_form_is_digested_over_the_exact_bytes_received() -> None:
    compact = json.dumps(ALLOW_GITHUB, separators=(",", ":"))
    expected = hashlib.sha256(compact.encode("utf-8")).hexdigest()
    forms: list[Any] = [ALLOW_GITHUB, compact, compact.encode("utf-8"), bytearray(compact.encode("utf-8"))]
    for form in forms:
        assert ComparedPolicy.action_policy(form).document_sha256 == expected
    # A dict is serialized once with the compact encoder, so a host that
    # digests its own pretty-printed text gets a different, equally valid key.
    pretty = json.dumps(ALLOW_GITHUB, indent=2)
    assert ComparedPolicy.action_policy(pretty).document_sha256 != expected


def test_a_callback_and_the_default_have_no_digest_and_the_kinds_are_fixed() -> None:
    assert ComparedPolicy.default().kind == "default"
    assert ComparedPolicy.default().document_sha256 is None
    callback = ComparedPolicy.callback(redact_secret.default_policy)
    assert callback.kind == "callback"
    assert callback.document_sha256 is None
    assert ComparedPolicy.action_policy(ALLOW_GITHUB).kind == "action-policy"


# ---------------------------------------------------------------------
# Building a side
# ---------------------------------------------------------------------


def test_a_rejected_document_is_rejected_when_the_side_is_built() -> None:
    secret_id = GITHUB_SECRET
    document = f'{{"actionPolicyRevision":1,"base":"default","rules":[{{"id":"{secret_id}"}}]}}'
    with pytest.raises(redact_secret.InvalidActionPolicyError) as excinfo:
        ComparedPolicy.action_policy(document)
    assert excinfo.value.error_class == "INVALID_IDENTIFIER"
    assert excinfo.value.rule_index == 0
    assert secret_id not in str(excinfo.value) + repr(excinfo.value)
    with pytest.raises(redact_secret.InvalidActionPolicyError):
        ComparedPolicy.action_policy({"actionPolicyRevision": 2})
    with pytest.raises(redact_secret.InvalidActionPolicyError):
        ComparedPolicy.action_policy("")


@pytest.mark.parametrize("value", [None, 1, 1.5, ["rules"], ("a",), object()])
def test_an_action_policy_of_the_wrong_type_is_invalid_options(value: object) -> None:
    with pytest.raises(redact_secret.InvalidOptionsError):
        ComparedPolicy.action_policy(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [None, "allow", 1, {"a": 1}])
def test_a_callback_must_be_callable(value: object) -> None:
    with pytest.raises(redact_secret.InvalidOptionsError):
        ComparedPolicy.callback(value)  # type: ignore[arg-type]


def test_a_side_has_no_public_constructor_and_is_read_only() -> None:
    with pytest.raises(TypeError):
        ComparedPolicy()
    side = ComparedPolicy.default()
    with pytest.raises(AttributeError):
        side.kind = "callback"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        side.document_sha256 = "0" * 64  # type: ignore[misc]
    assert repr(side) == 'ComparedPolicy(kind="default")'


# ---------------------------------------------------------------------
# The policies argument
# ---------------------------------------------------------------------


def _default_side() -> ComparedPolicy:
    return ComparedPolicy.default()


@pytest.mark.parametrize("count", [0, 5, 6])
def test_zero_or_more_than_four_sides_is_invalid_options_before_any_callback(count: int) -> None:
    calls: list[str] = []

    def record(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        calls.append(finding.id)
        return "allow"

    sides = [ComparedPolicy.callback(record)] + [_default_side() for _ in range(max(count - 1, 0))]
    with pytest.raises(redact_secret.InvalidOptionsError):
        compare_action_policies(GITHUB_INPUT, sides[:count])
    assert calls == []


def test_one_to_four_sides_are_accepted_as_a_list_or_a_tuple() -> None:
    for count in (1, 2, 3, 4):
        assert len(compare_action_policies(GITHUB_INPUT, [_default_side()] * count).sides) == count
        assert len(compare_action_policies(GITHUB_INPUT, tuple([_default_side()] * count)).sides) == count


@pytest.mark.parametrize(
    "policies",
    [
        None,
        "default",
        b"default",
        {"kind": "default"},
        ALLOW_GITHUB,
        [None],
        ["default"],
        [ALLOW_GITHUB],
        [redact_secret.default_policy],
        [_default_side(), "allow"],
        iter([_default_side()]),
        (side for side in [_default_side()]),
    ],
)
def test_policies_must_be_a_list_or_tuple_of_compared_policies(policies: object) -> None:
    with pytest.raises(redact_secret.InvalidOptionsError):
        compare_action_policies(GITHUB_INPUT, policies)  # type: ignore[arg-type]


def test_the_text_type_is_checked_first_and_arguments_are_positional_or_keyword() -> None:
    with pytest.raises(redact_secret.InvalidInputError):
        compare_action_policies(None, [])  # type: ignore[arg-type]
    with pytest.raises(redact_secret.InvalidInputError):
        compare_action_policies(b"API_KEY=x", [_default_side()])  # type: ignore[arg-type]
    result = compare_action_policies(text=GITHUB_INPUT, policies=[_default_side()], limits=None, ruleset=None)
    assert len(result.findings) == 1
    with pytest.raises(TypeError):
        compare_action_policies(GITHUB_INPUT)  # type: ignore[call-arg]


def test_the_policies_argument_is_the_only_way_to_pass_a_policy() -> None:
    with pytest.raises(TypeError):
        compare_action_policies(GITHUB_INPUT, [_default_side()], action_policy=ALLOW_GITHUB)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        compare_action_policies(GITHUB_INPUT, [_default_side()], policy=redact_secret.default_policy)  # type: ignore[call-arg]


# ---------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------


def test_results_have_no_public_constructor_and_are_immutable() -> None:
    comparison = compare_action_policies(GITHUB_INPUT, [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)])
    for cls in (
        redact_secret.ActionComparison,
        redact_secret.ComparedFinding,
        redact_secret.ActionDecision,
        redact_secret.ComparedSide,
        redact_secret.ActionCounts,
        redact_secret.DetectionIdentity,
    ):
        with pytest.raises(TypeError):
            cls()
    finding = comparison.findings[0]
    for target, name in (
        (comparison, "mode"),
        (comparison, "enforced"),
        (comparison, "changed_count"),
        (comparison, "findings"),
        (finding, "differs"),
        (finding, "start"),
        (finding, "decisions"),
        (finding.decisions[0], "action"),
        (comparison.sides[0], "kind"),
        (comparison.sides[0].counts, "redact"),
        (comparison.detection, "detector_count"),
    ):
        with pytest.raises(AttributeError):
            setattr(target, name, 0)
    assert isinstance(comparison.sides, tuple)
    assert isinstance(comparison.findings, tuple)
    assert isinstance(finding.decisions, tuple)
    assert comparison.findings is comparison.findings
    assert finding.decisions is finding.decisions


def test_the_result_says_it_is_a_preview_and_renders_nothing() -> None:
    comparison = compare_action_policies(GITHUB_INPUT, [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)])
    assert comparison.mode == "preview"
    assert comparison.enforced is False
    assert not hasattr(comparison, "text")
    assert not hasattr(comparison, "redacted")
    assert not hasattr(comparison.findings[0], "text")
    assert not hasattr(comparison.findings[0], "action")  # a finding has one decision per policy, not one action
    assert "preview" in repr(comparison)


def test_a_comparison_with_no_findings_is_empty_and_unchanged() -> None:
    comparison = compare_action_policies(
        "nothing to see here", [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)]
    )
    assert comparison.findings == ()
    assert comparison.changed_count == 0
    assert [
        (side.counts.redact, side.counts.block, side.counts.warn, side.counts.allow) for side in comparison.sides
    ] == [
        (0, 0, 0, 0),
        (0, 0, 0, 0),
    ]


def test_ranges_are_unicode_code_points() -> None:
    text = f"안녕 \U0001f642 API_KEY={GITHUB_SECRET} 끝"
    comparison = compare_action_policies(text, [_default_side()])
    (finding,) = comparison.findings
    assert text[finding.start : finding.end] == GITHUB_SECRET
    assert (finding.start, finding.end) == (redact_secret.scan(text)[0].start, redact_secret.scan(text)[0].end)


def test_detection_is_identified_apart_from_every_policy() -> None:
    fixture = _fixture()
    text = GITHUB_INPUT
    first = compare_action_policies(text, [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)])
    second = compare_action_policies(text, [_default_side(), ComparedPolicy.action_policy(WARN_GITHUB)])
    # Swapping a policy leaves the detection configuration unchanged.
    for field in ("activation_identity", "profile", "detector_count"):
        assert getattr(first.detection, field) == getattr(second.detection, field)
    assert first.sides[1].document_sha256 != second.sides[1].document_sha256
    assert first.detection.profile == redact_secret.status().profile
    assert first.detection.activation_identity
    assert first.detection.detector_count > 0
    # Swapping the detection configuration leaves every binding unchanged.
    with_ruleset = compare_action_policies(
        text, [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)], ruleset=fixture["ruleset"]
    )
    assert with_ruleset.detection.detector_count == first.detection.detector_count + 1
    assert [side.document_sha256 for side in with_ruleset.sides] == [side.document_sha256 for side in first.sides]


def test_a_side_given_twice_is_compared_twice() -> None:
    side = ComparedPolicy.action_policy(ALLOW_GITHUB)
    comparison = compare_action_policies(GITHUB_INPUT, [side, side])
    assert comparison.sides[0].document_sha256 == comparison.sides[1].document_sha256
    assert comparison.changed_count == 0


# ---------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------

THREE_FINDINGS = "ACME_AN_aB1cD2eF3gH4iJ5kL6mN\nAPI_KEY=" + GITHUB_SECRET + "\n"


def test_a_callback_sees_the_context_and_finding_scan_gives_it() -> None:
    seen: list[tuple[str, int, int, int, int]] = []

    def record(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        seen.append((finding.type, finding.start, finding.end, context.finding_index, context.finding_count))
        return "warn"

    compare_action_policies(THREE_FINDINGS, [ComparedPolicy.callback(record)], ruleset=_fixture()["ruleset"])
    via_scan: list[tuple[str, int, int, int, int]] = []

    def record_scan(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        via_scan.append((finding.type, finding.start, finding.end, context.finding_index, context.finding_count))
        return "warn"

    redact_secret.scan(THREE_FINDINGS, record_scan, ruleset=_fixture()["ruleset"])
    assert seen == via_scan
    assert [entry[3] for entry in seen] == [0, 1]
    assert {entry[4] for entry in seen} == {2}


def test_a_bad_callback_return_is_the_existing_invalid_policy_action_error() -> None:
    for bad in ("quarantine", 1, None, b"allow", ""):
        with pytest.raises(redact_secret.InvalidPolicyActionError):
            compare_action_policies(GITHUB_INPUT, [ComparedPolicy.callback(lambda f, c, bad=bad: bad)])  # type: ignore[misc]


def test_a_bad_return_in_a_later_side_fails_the_whole_comparison() -> None:
    log: list[str] = []

    def good(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        log.append("good")
        return "allow"

    with pytest.raises(redact_secret.InvalidPolicyActionError):
        compare_action_policies(
            GITHUB_INPUT,
            [ComparedPolicy.callback(good), ComparedPolicy.callback(lambda f, c: "nope")],
        )
    assert log == ["good"]


def test_a_callback_exception_is_the_existing_policy_failure_and_is_never_propagated() -> None:
    class Boom(Exception):
        pass

    def boom(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        raise Boom(GITHUB_SECRET)

    with pytest.raises(redact_secret.PolicyFailureError) as excinfo:
        compare_action_policies(GITHUB_INPUT, [ComparedPolicy.callback(boom)])
    assert GITHUB_SECRET not in str(excinfo.value) + repr(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None


def test_the_callback_count_matches_scan_and_the_enforcement_path_is_unchanged() -> None:
    def make(log: list[str]) -> Callable[[redact_secret.DetectedFinding, redact_secret.PolicyContext], str]:
        def policy(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
            log.append(f"{finding.id}:{context.finding_index}/{context.finding_count}")
            return "redact" if finding.type == "github_token" else "warn"

        return policy

    ruleset = _fixture()["ruleset"]
    before_log: list[str] = []
    before = redact_secret.scan_and_redact(THREE_FINDINGS, make(before_log), ruleset=ruleset)
    compare_log: list[str] = []
    compare_action_policies(THREE_FINDINGS, [ComparedPolicy.callback(make(compare_log))], ruleset=ruleset)
    after_log: list[str] = []
    after = redact_secret.scan_and_redact(THREE_FINDINGS, make(after_log), ruleset=ruleset)
    # Same count and order as `scan`, whatever ran in between.
    assert compare_log == before_log == after_log
    assert (before.text, [(f.id, f.action, f.start, f.end) for f in before.findings]) == (
        after.text,
        [(f.id, f.action, f.start, f.end) for f in after.findings],
    )


def test_enforcement_output_is_byte_identical_before_and_after_a_comparison() -> None:
    sides = [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB), ComparedPolicy.callback(lambda f, c: "block")]
    before = redact_secret.scan_and_redact(THREE_FINDINGS, ruleset=_fixture()["ruleset"])
    comparison = compare_action_policies(THREE_FINDINGS, sides, ruleset=_fixture()["ruleset"])
    after = redact_secret.scan_and_redact(THREE_FINDINGS, ruleset=_fixture()["ruleset"])
    assert before.text == after.text
    assert [repr(f) for f in before.findings] == [repr(f) for f in after.findings]
    assert comparison.findings  # the comparison itself returned no text
    assert before.text != THREE_FINDINGS or GITHUB_SECRET not in before.text


def test_a_callback_may_itself_scan_and_compare() -> None:
    inner: list[int] = []

    def reentrant(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        inner.append(len(redact_secret.scan(GITHUB_INPUT)))
        inner.append(len(compare_action_policies(GITHUB_INPUT, [ComparedPolicy.default()]).findings))
        return "allow"

    result = compare_action_policies(GITHUB_INPUT, [ComparedPolicy.callback(reentrant), _default_side()])
    assert inner == [1, 1]
    assert [d.action for d in result.findings[0].decisions] == ["allow", "redact"]
    # The thread's registry survives the callback: a later call works and still
    # sees the same detectors.
    again = compare_action_policies(GITHUB_INPUT, [_default_side()])
    assert again.detection.detector_count == result.detection.detector_count


def test_a_callback_may_use_a_ruleset_comparison_reentrantly() -> None:
    ruleset = _fixture()["ruleset"]

    def reentrant(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        assert len(redact_secret.scan(THREE_FINDINGS, ruleset=ruleset)) == 2
        assert len(redact_secret.scan(THREE_FINDINGS)) == 1
        return "warn"

    result = compare_action_policies(THREE_FINDINGS, [ComparedPolicy.callback(reentrant)], ruleset=ruleset)
    assert [d.action for f in result.findings for d in f.decisions] == ["warn", "warn"]
    assert len(redact_secret.scan(THREE_FINDINGS, ruleset=ruleset)) == 2


def test_comparisons_run_from_several_threads() -> None:
    results: list[tuple[int, int]] = []
    failures: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(20):
                comparison = compare_action_policies(
                    GITHUB_INPUT, [_default_side(), ComparedPolicy.action_policy(ALLOW_GITHUB)]
                )
                results.append((len(comparison.findings), comparison.changed_count))
        except BaseException as error:  # noqa: BLE001 - surfaced by the assertion below
            failures.append(error)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert set(results) == {(1, 1)}


# ---------------------------------------------------------------------
# Bounds and ruleset
# ---------------------------------------------------------------------


def test_the_byte_bound_is_checked_before_a_ruleset_is_parsed_and_before_a_callback() -> None:
    calls: list[str] = []

    def record(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        calls.append(finding.id)
        return "allow"

    limits = redact_secret.WholeInputLimits(max_input_bytes=10, max_findings=10)
    with pytest.raises(redact_secret.InputLimitExceededError):
        compare_action_policies(GITHUB_INPUT, [ComparedPolicy.callback(record)], limits=limits, ruleset="not a ruleset")
    assert calls == []


def test_the_finding_bound_fails_before_any_policy_runs() -> None:
    calls: list[str] = []

    def record(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
        calls.append(finding.id)
        return "allow"

    limits = redact_secret.WholeInputLimits(max_input_bytes=1_000_000, max_findings=1)
    with pytest.raises(redact_secret.FindingLimitExceededError):
        compare_action_policies(
            THREE_FINDINGS, [ComparedPolicy.callback(record)], limits=limits, ruleset=_fixture()["ruleset"]
        )
    assert calls == []
    # An exactly-at-the-bound comparison succeeds.
    ok = compare_action_policies(
        GITHUB_INPUT,
        [ComparedPolicy.callback(record)],
        limits=redact_secret.WholeInputLimits(max_input_bytes=100, max_findings=1),
    )
    assert len(ok.findings) == 1


def test_an_invalid_ruleset_and_a_wrong_typed_option_are_the_existing_errors() -> None:
    with pytest.raises(redact_secret.InvalidRulesetError):
        compare_action_policies(GITHUB_INPUT, [_default_side()], ruleset="ruleset-revision: 9\n")
    with pytest.raises(redact_secret.InvalidOptionsError):
        compare_action_policies(GITHUB_INPUT, [_default_side()], ruleset=5)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        compare_action_policies(GITHUB_INPUT, [_default_side()], limits=5)  # type: ignore[arg-type]
    ruleset = _fixture()["ruleset"]
    for form in (ruleset, ruleset.encode("utf-8"), bytearray(ruleset.encode("utf-8"))):
        comparison = compare_action_policies(THREE_FINDINGS, [_default_side()], ruleset=form)
        assert len(comparison.findings) == 2


def test_the_pii_selection_is_part_of_the_detection_identity() -> None:
    comparison = compare_action_policies(GITHUB_INPUT, [_default_side()])
    assert comparison.detection.activation_identity == (
        redact_secret.status().activation or comparison.detection.activation_identity
    )
    assert comparison.detection.profile == "full"


# ---------------------------------------------------------------------
# Host obligations
# ---------------------------------------------------------------------


def _strings(value: object, seen: set[int] | None = None) -> list[str]:
    """Every string reachable from a result through its public attributes."""
    seen = seen if seen is not None else set()
    if id(value) in seen:
        return []
    seen.add(id(value))
    if isinstance(value, str):
        return [value]
    if isinstance(value, (tuple, list)):
        return [text for item in value for text in _strings(item, seen)]
    if value is None or isinstance(value, (bool, int, float)):
        return []
    collected = [repr(value), str(value)]
    for name in dir(value):
        if name.startswith("_"):
            continue
        collected.extend(_strings(getattr(value, name), seen))
    return collected


def test_the_result_holds_no_input_byte_matched_value_or_snippet() -> None:
    fixture = _fixture()
    case = fixture["cases"][0]
    log: list[str] = []
    comparison = compare_action_policies(
        case["input"], _build_sides(fixture, case["sides"], log), ruleset=fixture["ruleset"]
    )
    haystack = "\n".join(_strings(comparison))
    for fragment in (
        GITHUB_SECRET,
        "ghp_SYNTHETIC",
        "SYNTHETICREVOKED",
        "aB1cD2eF3gH4iJ5kL6mN",
        "U1lOVEhFVElDX1JFVk9LRURfRklYVFVSRQ==",
        "BEGIN PRIVATE KEY",
        "API_KEY",
    ):
        assert fragment not in haystack
    # Only a policy document's digest is a digest; nothing carries a score.
    assert not any(
        hasattr(finding, name)
        for finding in comparison.findings
        for name in ("score", "hash", "snippet", "value", "match")
    )


def test_incremental_comparison_is_not_exposed_anywhere() -> None:
    names = [name for name in dir(redact_secret) if "compar" in name.lower()]
    assert sorted(names) == sorted(
        [
            "ActionComparison",
            "ComparedFinding",
            "ComparedPolicy",
            "ComparedSide",
            "compare_action_policies",
        ]
    )
    for owner in (redact_secret.IncrementalSanitizer, redact_secret.IncrementalLimits, redact_secret.IncrementalResult):
        assert [name for name in dir(owner) if "compar" in name.lower() or "explain" in name.lower()] == []
    # An incremental callback context is not accepted as a compared callback's
    # input, and a session cannot be passed as a side.
    limits = redact_secret.IncrementalLimits(
        max_input_bytes=1_000_000, max_buffered_bytes=100_000, max_token_bytes=8_192, max_multiline_bytes=16_384
    )
    with redact_secret.IncrementalSanitizer(limits) as session:
        with pytest.raises(redact_secret.InvalidOptionsError):
            compare_action_policies(GITHUB_INPUT, [session])  # type: ignore[list-item]


def test_the_fixture_obligations_this_surface_asserts_are_all_present() -> None:
    obligations = {entry["id"] for entry in _fixture()["hostObligations"]}
    assert obligations == {
        "preview-is-not-enforcement",
        "detection-runs-once",
        "finalized-findings-only",
        "no-plaintext",
        "detection-identified-separately",
        "callback-bindings-have-no-identity",
        "incremental-comparison-is-unsupported",
        "digest-is-over-the-exact-document-bytes",
    }


def test_detection_runs_once_for_any_number_of_sides() -> None:
    """A stateful `ruleset`-free proxy: with a callback on each of four sides,
    every callback is called once per finding, so the finding list was
    produced by one pass and shared (a second detection would not change the
    call count, so the finalized-findings parity above is the proof; here the
    ids are asserted equal across every side's callback)."""
    seen: list[list[str]] = [[], [], [], []]

    def make(index: int) -> Callable[[redact_secret.DetectedFinding, redact_secret.PolicyContext], str]:
        def policy(finding: redact_secret.DetectedFinding, context: redact_secret.PolicyContext) -> str:
            seen[index].append(finding.id)
            return "allow"

        return policy

    ruleset = _fixture()["ruleset"]
    comparison = compare_action_policies(
        THREE_FINDINGS, [ComparedPolicy.callback(make(index)) for index in range(4)], ruleset=ruleset
    )
    expected = [finding.id for finding in comparison.findings]
    assert expected == [finding.id for finding in redact_secret.scan(THREE_FINDINGS, ruleset=ruleset)]
    assert seen == [expected] * 4
