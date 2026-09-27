"""Shared PII activation/error conformance for the installed Python binding."""

from __future__ import annotations

import json
import subprocess
import sys

import redact_secret

from .conftest import (
    byte_offset_to_char_offset_reference,
    code_point_partitions,
    load_corpus,
    run_session,
)


def _observable(finding: object) -> dict[str, object]:
    return {
        "detector": finding.detector,
        "type": finding.type,
        "confidence": finding.confidence,
        "action": finding.action,
        "start": finding.start,
        "end": finding.end,
    }


def test_pii_runtime_fixture() -> None:
    fixture = load_corpus("pii-runtime-v1.json")
    first = fixture["activationCases"][1]
    redact_secret.initialize(pii=first["selectors"])
    assert redact_secret.pii_activation() == first["expected"]

    for family_fixture in ("pii-email-v1.json", "pii-iban-v1.json"):
        family = load_corpus(family_fixture)
        for case in family["cases"]:
            input_text = case["input"]
            expected = []
            for finding in case["expected"]:
                converted = dict(finding)
                converted["start"] = byte_offset_to_char_offset_reference(
                    input_text, finding["start"]
                )
                converted["end"] = byte_offset_to_char_offset_reference(
                    input_text, finding["end"]
                )
                expected.append(converted)
            assert [_observable(finding) for finding in redact_secret.scan(input_text)] == expected

            whole = redact_secret.scan_and_redact(input_text)
            for partition, chunks in enumerate(code_point_partitions(input_text)):
                text, findings = run_session(chunks)
                assert text == whole.text, (case["id"], partition)
                assert [_observable(finding) for finding in findings] == expected, (
                    case["id"],
                    partition,
                )

    for case in fixture["errorCases"]:
        try:
            redact_secret.initialize(pii=case["selectors"])
        except redact_secret.SecretScanError as error:
            assert error.code == case["code"]
            assert str(error) == case["message"]
        else:
            raise AssertionError(case["id"])

    network_fixture = load_corpus("pii-network-address-v1.json")
    for case in network_fixture["cases"]:
        findings = [
            finding
            for finding in redact_secret.scan(case["input"])
            if finding.type == "pii_global_network_address"
        ]
        assert len(findings) == len(case["expected"]), case["id"]
        for finding, expected in zip(findings, case["expected"], strict=True):
            byte_start = len(case["input"][: finding.start].encode())
            byte_end = len(case["input"][: finding.end].encode())
            assert (byte_start, byte_end) == (expected["start"], expected["end"])
            assert finding.detector == "pii-domain"
            assert finding.action == "redact"

    payment_fixture = load_corpus("pii-payment-card-v1.json")
    for case in payment_fixture["cases"]:
        input_text = case["input"]
        expected = []
        for finding in case["expected"]:
            converted = dict(finding)
            converted["start"] = byte_offset_to_char_offset_reference(
                input_text, finding["start"]
            )
            converted["end"] = byte_offset_to_char_offset_reference(
                input_text, finding["end"]
            )
            expected.append(converted)
        assert [_observable(finding) for finding in redact_secret.scan(input_text)] == expected

        whole = redact_secret.scan_and_redact(input_text)
        for partition, chunks in enumerate(code_point_partitions(input_text)):
            text, findings = run_session(chunks)
            assert text == whole.text, (case["id"], partition)
            assert [_observable(finding) for finding in findings] == expected, (
                case["id"],
                partition,
            )


def test_payment_card_exact_and_global_selectors_in_fresh_installed_processes() -> None:
    child = """
import json
import sys
import redact_secret

redact_secret.initialize(pii=[sys.argv[1]])
findings = redact_secret.scan("card_number=4000008770000003")
print(json.dumps({
    "activation": redact_secret.pii_activation(),
    "types": [finding.type for finding in findings],
    "actions": [finding.action for finding in findings],
}))
"""
    cases = [
        (
            "pii:family:global:payment-card",
            "credentials=full;selectors=pii:family:global:payment-card;families="
            "pii:global:payment-card;vocabulary=pii-context/v1",
        ),
        (
            "pii:global",
            "credentials=full;selectors=pii:global;families=pii:global:email,"
            "pii:global:iban,pii:global:network-address,pii:global:payment-card;"
            "vocabulary=pii-context/v1",
        ),
    ]
    for ordinal, (selector, activation) in enumerate(cases):
        completed = subprocess.run(
            [sys.executable, "-c", child, selector],
            check=True,
            capture_output=True,
            text=True,
        )
        actual = json.loads(completed.stdout)
        assert actual == {
            "activation": activation,
            "types": ["pii_global_payment_card"],
            "actions": ["redact"],
        }, ordinal


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
