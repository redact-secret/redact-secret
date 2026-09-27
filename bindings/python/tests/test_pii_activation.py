"""Shared PII activation/error conformance for the installed Python binding."""

from __future__ import annotations

import redact_secret

from .conftest import load_corpus


def test_pii_runtime_fixture() -> None:
    fixture = load_corpus("pii-runtime-v1.json")
    first = fixture["activationCases"][1]
    redact_secret.initialize(pii=first["selectors"])
    assert redact_secret.pii_activation() == first["expected"]

    for case in fixture["errorCases"]:
        try:
            redact_secret.initialize(pii=case["selectors"])
        except redact_secret.SecretScanError as error:
            assert error.code == case["code"]
            assert str(error) == case["message"]
        else:
            raise AssertionError(case["id"])


def test_different_selection_conflicts_without_echoing_input() -> None:
    marker = "SYNTHETIC_SELECTOR_MARKER"
    try:
        redact_secret.initialize(pii=())
    except redact_secret.PiiActivationConflictError as error:
        assert error.code == "PII_ACTIVATION_CONFLICT"
        assert str(error) == "PII activation is already initialized differently."
        assert marker not in str(error)
    else:
        raise AssertionError("expected an activation conflict")
