"""Framework-neutral AI-context boundary contract, Python twin (issue #610).

Replays ``conformance/fixtures/ai-context-boundary.json`` through a minimal
Python reference model of ``docs/reference/ai-context-boundary.md``, built
from documented ``redact_secret`` API only (``scan_and_redact``,
``IncrementalSanitizer``, ``WholeInputLimits``, ``IncrementalLimits``, and the
``code`` attribute of ``SecretScanError``). The JavaScript twin is
``conformance/ai-context-boundary.mjs``; both must reach the same outcome for
every shared case. ``scripts/qualify-python-wheel.py --conformance`` runs this
file against the installed wheel, so it qualifies the publish-shaped
artifact, not the source tree.

The model is test code, not a package export: the installable adapter lives
in ``redact-secret-adapters``. Assertion failures name a case ID and a field
only, never an input, a value, or a matched secret.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest

import redact_secret

from .conftest import load_corpus

FIXTURE = load_corpus("ai-context-boundary.json")

SAFE_FINDING_FIELDS = ("id", "type", "detector", "confidence", "action", "obfuscation", "start", "end")
BLOCK_REASONS = ("policy", "limit_exceeded", "unsupported_value", "lifecycle", "core_error")
LIMIT_CODES = {
    "INPUT_LIMIT_EXCEEDED",
    "FINDING_LIMIT_EXCEEDED",
    "BUFFER_LIMIT_EXCEEDED",
    "TOKEN_LIMIT_EXCEEDED",
    "MULTILINE_LIMIT_EXCEEDED",
}

ABORTED = {"outcome": "aborted"}


def _blocked(reason: str, code: str | None = None) -> dict:
    return {"outcome": "blocked", "reason": reason} if code is None else {
        "outcome": "blocked",
        "reason": reason,
        "code": code,
    }


def _failure_from(error: BaseException) -> dict:
    """Maps any exception to a fixed failure. Never reads ``str(error)``."""
    code = getattr(error, "code", None) if isinstance(error, redact_secret.SecretScanError) else None
    if not isinstance(code, str):
        code = None
    if code in LIMIT_CODES:
        return _blocked("limit_exceeded", code)
    if code == "INVALID_STATE":
        return _blocked("lifecycle", code)
    return _blocked("core_error", code)


def _safe_finding(finding: Any) -> dict:
    return {name: getattr(finding, name) for name in SAFE_FINDING_FIELDS}


@dataclass
class Signal:
    aborted: bool = False


@dataclass
class Boundary:
    whole_limits: Any
    incremental_limits: Any
    traversal: dict
    policy: Callable | None
    on_finding: Callable[[dict, dict], None] | None = None

    def _emit(self, findings: list[dict], boundary: str) -> None:
        if self.on_finding is None:
            return
        for finding in findings:
            try:
                self.on_finding(dict(finding), {"boundary": boundary})
            except Exception:  # noqa: BLE001 -- telemetry never changes the outcome
                pass

    def _scan(self, text: Any) -> tuple[dict | None, str, list[dict]]:
        if not isinstance(text, str):
            return _blocked("unsupported_value"), "", []
        try:
            result = redact_secret.scan_and_redact(text, policy=self.policy, limits=self.whole_limits)
        except Exception as error:  # noqa: BLE001 -- mapped to a fixed failure
            return _failure_from(error), "", []
        return None, result.text, [_safe_finding(finding) for finding in result.findings]

    def sanitize_text(self, text: Any, boundary: str, signal: Signal) -> dict:
        if signal.aborted:
            return ABORTED
        failure, value, findings = self._scan(text)
        if failure is not None:
            return failure
        self._emit(findings, boundary)
        if any(finding["action"] == "block" for finding in findings):
            return _blocked("policy")
        if signal.aborted:
            return ABORTED
        return {"outcome": "ok", "value": value, "findings": findings}

    def sanitize_value(self, value: Any, boundary: str, signal: Signal) -> dict:
        if signal.aborted:
            return ABORTED
        findings: list[dict] = []
        state = {"nodes": 0}
        seen: set[int] = set()

        def walk(node: Any, depth: int) -> tuple[dict | None, Any]:
            state["nodes"] += 1
            if state["nodes"] > self.traversal["maxNodes"]:
                return _blocked("limit_exceeded"), None
            if isinstance(node, str):
                failure, text, leaf = self._scan(node)
                if failure is not None:
                    return failure, None
                self._emit(leaf, boundary)
                findings.extend(leaf)
                if any(finding["action"] == "block" for finding in leaf):
                    return _blocked("policy"), None
                return None, text
            if node is None or isinstance(node, bool) or (
                isinstance(node, (int, float)) and node == node and node not in (float("inf"), float("-inf"))
            ):
                return None, node
            if type(node) not in (list, dict):
                return _blocked("unsupported_value"), None
            if id(node) in seen:
                return _blocked("unsupported_value"), None
            if depth + 1 > self.traversal["maxDepth"]:
                return _blocked("limit_exceeded"), None
            seen.add(id(node))
            try:
                if isinstance(node, list):
                    out_list = []
                    for item in node:
                        failure, child = walk(item, depth + 1)
                        if failure is not None:
                            return failure, None
                        out_list.append(child)
                    return None, out_list
                out: dict = {}
                for key, item in node.items():
                    failure, _, key_findings = self._scan(key)
                    if failure is not None:
                        return failure, None
                    self._emit(key_findings, boundary)
                    if any(finding["action"] in ("block", "redact") for finding in key_findings):
                        return _blocked("policy"), None
                    failure, child = walk(item, depth + 1)
                    if failure is not None:
                        return failure, None
                    out[key] = child
                return None, out
            finally:
                seen.discard(id(node))

        failure, walked = walk(value, 0)
        if failure is not None:
            return failure
        if signal.aborted:
            return ABORTED
        return {"outcome": "ok", "value": walked, "findings": findings}

    def build_context(self, parts: list[dict], signal: Signal) -> dict:
        if signal.aborted:
            return ABORTED
        messages = []
        findings: list[dict] = []
        for part in parts:
            if "text" in part:
                outcome = self.sanitize_text(part["text"], part["boundary"], signal)
            else:
                outcome = self.sanitize_value(part["value"], part["boundary"], signal)
            if outcome["outcome"] != "ok":
                return outcome
            findings.extend(outcome["findings"])
            messages.append({"role": part["role"], "content": outcome["value"]})
        if signal.aborted:
            return ABORTED
        return {"outcome": "ok", "value": messages, "findings": findings}

    def open_stream(self, boundary: str, signal: Signal) -> "Stream":
        return Stream(self, boundary, signal)


@dataclass
class Stream:
    owner: Boundary
    boundary: str
    signal: Signal
    session: Any = None
    terminal: dict | None = None
    finalized: bool = False
    staged: str = ""
    findings: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.signal.aborted:
            self._fail(ABORTED)
            return
        try:
            self.session = redact_secret.IncrementalSanitizer(
                self.owner.incremental_limits, policy=self.owner.policy
            )
        except Exception as error:  # noqa: BLE001
            self._fail(_failure_from(error))

    def _fail(self, outcome: dict) -> None:
        if self.terminal is None:
            self.terminal = outcome
        self.staged = ""
        self.findings = []
        if self.session is not None:
            try:
                self.session.abort()
            except Exception:  # noqa: BLE001 -- cleanup on a failed session
                pass

    def _record(self, result: Any) -> None:
        safe = [_safe_finding(finding) for finding in result.findings]
        self.owner._emit(safe, self.boundary)
        self.findings.extend(safe)
        self.staged += result.text
        if any(finding["action"] == "block" for finding in safe):
            self._fail(_blocked("policy"))

    def append(self, chunk: Any) -> None:
        if self.finalized or self.terminal is not None:
            return
        if self.signal.aborted:
            self._fail(ABORTED)
            return
        if not isinstance(chunk, str):
            self._fail(_blocked("unsupported_value"))
            return
        try:
            self._record(self.session.append(chunk))
        except Exception as error:  # noqa: BLE001
            self._fail(_failure_from(error))

    def finalize(self) -> dict:
        if self.finalized:
            return _blocked("lifecycle")
        self.finalized = True
        if self.terminal is None and self.signal.aborted:
            self._fail(ABORTED)
        if self.terminal is None:
            try:
                self._record(self.session.finalize())
            except Exception as error:  # noqa: BLE001
                self._fail(_failure_from(error))
        if self.terminal is not None:
            return self.terminal
        outcome = {"outcome": "ok", "value": self.staged, "findings": self.findings}
        self.staged = ""
        self.findings = []
        return outcome

    def abort(self) -> None:
        if not self.finalized:
            self._fail(ABORTED)


# ---------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------


def _block_all(finding: Any, context: Any) -> str:
    return "block"


def _throwing(finding: Any, context: Any) -> str:
    raise RuntimeError("synthetic policy failure")


POLICIES: dict[str, Callable | None] = {"default": None, "block-all": _block_all, "throwing": _throwing}


def _materialize(value: Any) -> str:
    if isinstance(value, str):
        return value
    return value["repeat"] * value["count"]


class _NonPlain:
    """Stands in for any non-JSON host object (JavaScript uses a Date)."""


def _materialize_value(value: Any) -> Any:
    if isinstance(value, dict) and isinstance(value.get("construct"), str):
        construct = value["construct"]
        if construct == "array-of-strings":
            return [value["item"]] * value["count"]
        if construct == "non-plain-object":
            return {"when": _NonPlain()}
        if construct == "cycle":
            node: dict = {"label": "ordinary text"}
            node["self"] = node
            return node
        raise AssertionError("unsupported construct")
    return value


def _boundary(case: dict, events: list) -> Boundary:
    limits = FIXTURE["limits"]
    incremental = limits["incremental"]
    throwing = case.get("telemetry") == "throwing"

    def on_finding(finding: dict, context: dict) -> None:
        events.append({"finding": finding, "context": context})
        if throwing:
            raise RuntimeError("synthetic telemetry failure")

    return Boundary(
        whole_limits=redact_secret.WholeInputLimits(
            max_input_bytes=limits["wholeInput"]["maxInputBytes"],
            max_findings=limits["wholeInput"]["maxFindings"],
        ),
        incremental_limits=redact_secret.IncrementalLimits(
            max_input_bytes=incremental["maxInputBytes"],
            max_buffered_bytes=incremental["maxBufferedBytes"],
            max_token_bytes=incremental["maxTokenBytes"],
            max_multiline_bytes=incremental["maxMultilineBytes"],
        ),
        traversal=limits["traversal"],
        policy=POLICIES[case.get("policy", "default")],
        on_finding=on_finding,
    )


def _check(condition: bool, case_id: str, what: str) -> None:
    """Fails outside an ``assert`` so pytest never prints an input or value."""
    if not condition:
        raise AssertionError(f"{case_id}: {what}")


def _check_no_leak(case: dict, outcome: dict, events: list) -> None:
    metadata = json.dumps({k: v for k, v in outcome.items() if k != "value"}) + json.dumps(events)
    value = json.dumps(outcome.get("value")) if outcome["outcome"] == "ok" else ""
    for secret in case.get("secrets", []):
        _check(secret not in metadata, case["id"], "a secret reached outcome metadata or telemetry")
        if not case.get("valueMayContainSecrets"):
            _check(secret not in value, case["id"], "a secret reached the safe value")
    for event in events:
        _check(sorted(event["finding"]) == sorted(SAFE_FINDING_FIELDS), case["id"], "telemetry finding fields")
        _check(list(event["context"]) == ["boundary"], case["id"], "telemetry context fields")
    if outcome["outcome"] != "ok":
        _check("value" not in outcome and "findings" not in outcome, case["id"], "non-ok outcome carries data")
    if outcome["outcome"] == "blocked":
        _check(outcome["reason"] in BLOCK_REASONS, case["id"], "unknown block reason")


def _python_cases() -> list[dict]:
    return [
        case
        for case in FIXTURE["cases"]
        if "python" in case.get("runtimes", ["python"]) and case.get("phase", "initialized") == "initialized"
    ]


def test_fixture_declares_the_runner_field_set() -> None:
    assert FIXTURE["schemaVersion"] == 1
    assert tuple(FIXTURE["safeFindingFields"]) == SAFE_FINDING_FIELDS
    assert tuple(FIXTURE["blockReasons"]) == BLOCK_REASONS
    # Every JavaScript-only case must say why by being uninitialized-phase or
    # a lone-surrogate host check; nothing else may silently skip Python.
    skipped = {case["id"] for case in FIXTURE["cases"] if case not in _python_cases()}
    assert skipped == {
        "text-before-initialization-fails-closed",
        "text-unpaired-surrogate-fails-closed",
        "stream-before-initialization-fails-closed",
    }


@pytest.mark.parametrize("case", _python_cases(), ids=lambda case: case["id"])
def test_ai_context_boundary_case(case: dict) -> None:
    events: list = []
    boundary = _boundary(case, events)
    signal = Signal(aborted=case.get("signal") == "aborted-before")
    operation = case["operation"]

    if operation == "stream":
        stream = boundary.open_stream(case["boundary"], signal)
        outcomes = []
        for step in case["steps"]:
            if step["op"] == "append":
                stream.append(_materialize(step["chunk"]))
            elif step["op"] == "abort":
                stream.abort()
            elif step["op"] == "signal":
                signal.aborted = True
            elif step["op"] == "finalize":
                outcomes.append(stream.finalize())
            else:
                raise AssertionError(f"{case['id']}: unknown step")
        _check(outcomes == case["expected"], case["id"], "stream outcomes")
        for outcome in outcomes:
            _check_no_leak(case, outcome, events)
        return

    if operation == "sanitizeText":
        outcome = boundary.sanitize_text(_materialize(case["input"]), case["boundary"], signal)
    elif operation == "sanitizeValue":
        outcome = boundary.sanitize_value(_materialize_value(case["value"]), case["boundary"], signal)
    elif operation == "buildContext":
        outcome = boundary.build_context(case["parts"], signal)
    else:
        raise AssertionError(f"{case['id']}: unknown operation")
    _check(outcome == case["expected"], case["id"], "outcome")
    _check_no_leak(case, outcome, events)

    if operation == "sanitizeText" and case.get("incrementalEquivalence", True) and "signal" not in case:
        text = _materialize(case["input"])
        step = 1 if len(text) <= 256 else -(-len(text) // 64)
        partitions = [[text[:index], text[index:]] for index in range(0, len(text) + 1) if index % step == 0 or index == len(text)]
        if len(text) <= 256:
            partitions.append(list(text))
        for chunks in partitions:
            stream = _boundary(case, events).open_stream(case["boundary"], Signal())
            for chunk in chunks:
                stream.append(chunk)
            streamed = stream.finalize()
            _check(streamed == case["expected"], case["id"], "incremental outcome diverges from whole-input")
            _check_no_leak(case, streamed, events)
