from __future__ import annotations

import unittest

from scripts.pii_current_qualification import (
    GATES,
    REASONS,
    current_qualification_errors,
    current_qualification_sentence,
)

FAMILIES = {"pii:global:email", "pii:us:ssn"}


def prepared():
    return {
        "schemaVersion": 1,
        "state": "prepared",
        "sourceCommit": "a" * 40,
        "supportClaims": False,
        "qualified": False,
        "evidenceScope": "public-synthetic-only",
        "publicMeasurement": {
            "state": "not-recorded",
            "mode": None,
            "reason": "current-comparison-not-recorded",
            "receiptDigest": None,
            "productArtifactDigest": None,
            "baselineSourceCommit": None,
            "engineBinaryDigest": None,
        },
        "gates": dict(GATES),
        "distribution": {"stable": 0, "provisional": 0, "pending": len(FAMILIES), "unsupported": 0},
        "families": [
            {"family": family, "status": "pending", "reasonCodes": ["current-public-comparison-not-recorded", *REASONS]}
            for family in sorted(FAMILIES)
        ],
    }


class CurrentQualificationTests(unittest.TestCase):
    def test_absent_is_backward_compatible_without_current_claim(self):
        self.assertEqual(current_qualification_errors(None, FAMILIES), [])
        self.assertIn("no current-target", current_qualification_sentence(None))

    def test_preparation_names_exact_target_with_all_pending(self):
        current = prepared()
        self.assertEqual(current_qualification_errors(current, FAMILIES), [])
        self.assertIn("2 families pending", current_qualification_sentence(current))
        self.assertIn("not an owner-approved deferral", current_qualification_sentence(current))

    def test_recorded_public_measurement_does_not_qualify(self):
        current = prepared()
        current["state"] = "recorded"
        current["publicMeasurement"] = {
            "state": "recorded",
            "mode": "official",
            "reason": None,
            "receiptDigest": "b" * 64,
            "productArtifactDigest": "c" * 64,
            "baselineSourceCommit": "d" * 40,
            "engineBinaryDigest": "e" * 64,
        }
        for row in current["families"]:
            row["reasonCodes"][0] = "product-validator-primitive-seam-unavailable"
        self.assertEqual(current_qualification_errors(current, FAMILIES), [])
        self.assertIn("qualified false", current_qualification_sentence(current))

    def test_higher_claims_and_invented_identity_fail_closed(self):
        for key, value in [
            ("qualified", True),
            ("sourceCommit", "a" * 8),
            ("ownerAcceptance", {}),
            ("gates", {**GATES, "profileCost": "met"}),
        ]:
            current = prepared()
            current[key] = value
            self.assertTrue(current_qualification_errors(current, FAMILIES), key)
        current = prepared()
        current["publicMeasurement"]["receiptDigest"] = "a" * 64
        self.assertTrue(current_qualification_errors(current, FAMILIES))

    def test_family_coverage_and_reason_contract_are_preserved(self):
        for mutate in [
            lambda q: q["families"].pop(),
            lambda q: q["families"][0].update(status="provisional"),
            lambda q: q["families"][0].update(reasonCodes=["approved-deferral"]),
            lambda q: q["distribution"].update(stable=False),
        ]:
            current = prepared()
            mutate(current)
            self.assertTrue(current_qualification_errors(current, FAMILIES))
