"""The side-effect-free, input-free `status()` query (issue #1172)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
import redact_secret

OFF = "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"
PII = (
    "credentials=full;selectors=pii:global;"
    "families=pii:global:email,pii:global:iban,pii:global:network-address,"
    "pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2"
)


def _child(source: str) -> object:
    completed = subprocess.run(
        [sys.executable, "-c", source],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_status_is_exported_and_typed() -> None:
    assert "status" in redact_secret.__all__
    assert "CoreStatus" in redact_secret.__all__
    assert isinstance(redact_secret.status(), redact_secret.CoreStatus)


def test_status_takes_no_input() -> None:
    with pytest.raises(TypeError):
        redact_secret.status("x")  # type: ignore[call-arg]


def test_status_does_not_initialize_or_lock_the_selection() -> None:
    child = """
import json, redact_secret
before = redact_secret.status()
again = redact_secret.status()
redact_secret.initialize(pii=["pii"])
after = redact_secret.status()
print(json.dumps({
    "before": [before.initialized, before.profile, before.activation],
    "again": [again.initialized, again.activation],
    "after": [after.initialized, after.profile, after.activation],
    "identity": redact_secret.pii_activation(),
}))
"""
    actual = _child(child)
    assert isinstance(actual, dict)
    assert actual["before"] == [False, "full", None]
    assert actual["again"] == [False, None]
    # Querying never fixed the selection, so a later initialize still applied.
    assert actual["after"] == [True, "full", PII]
    assert actual["identity"] == PII


def test_status_reports_the_activation_and_leaves_conflicts_unchanged() -> None:
    child = """
import json, redact_secret
redact_secret.initialize()
status = redact_secret.status()
try:
    redact_secret.initialize(pii=["pii"])
    conflict = None
except redact_secret.PiiActivationConflictError as error:
    conflict = type(error).__name__
final = redact_secret.status()
print(json.dumps({
    "status": [status.initialized, status.activation],
    "conflict": conflict,
    "final": [final.initialized, final.activation],
}))
"""
    actual = _child(child)
    assert isinstance(actual, dict)
    assert actual["status"] == [True, OFF]
    assert actual["conflict"] == "PiiActivationConflictError"
    assert actual["final"] == [True, OFF]


def test_status_is_read_only_and_exposes_only_fixed_fields() -> None:
    status = redact_secret.status()
    with pytest.raises(AttributeError):
        status.initialized = True  # type: ignore[misc]
    public = {name for name in dir(status) if not name.startswith("_")}
    assert public == {"initialized", "profile", "activation"}
    assert status.profile == "full"
    text = repr(status)
    assert text.startswith("CoreStatus(initialized=")
