from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-precision-contracts.py"
SPEC = importlib.util.spec_from_file_location("audit_precision_contracts", SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class SyntheticReconstructionTests(unittest.TestCase):
    def test_synthetic_is_deterministic_and_respects_alphabet_and_length(self) -> None:
        first = AUDIT.synthetic("reviewed-formats:test", 70, "hex")
        second = AUDIT.synthetic("reviewed-formats:test", 70, "hex")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 70)
        self.assertTrue(set(first) <= set("0123456789abcdef"))

    def test_take_slices_the_same_stream_the_full_length_produces(self) -> None:
        full = AUDIT.render_token([{"synthetic": {"label": "x", "length": 40}}])
        taken = AUDIT.render_token([{"synthetic": {"label": "x", "length": 40, "take": 39}}])
        self.assertEqual(taken, full[:39])

    def test_render_fixture_reports_utf8_byte_offsets_for_the_unicode_context(self) -> None:
        construction = {"context": "unicode-crlf", "parts": [{"literal": "abc"}]}
        content, start, end = AUDIT.render_fixture(construction)
        self.assertEqual(content, "# \U0001F511 reviewed format\r\nabc\n\r\n")
        self.assertEqual((start, end), (24, 27))


class ContractEvaluationTests(unittest.TestCase):
    FAMILY = {
        "detector": "widget-token",
        "variants": [
            {"id": "exact", "grammar": "wgt_[a-f0-9]{8}"},
            {"id": "open-ended", "grammar": "wgo_[A-Za-z0-9]{4,}"},
        ],
    }

    def test_boundary_bytes_reject_an_embedded_or_overlong_candidate(self) -> None:
        pattern = AUDIT.compile_family(self.FAMILY)
        self.assertEqual(AUDIT.find_contract_matches("wgt_0123abcd", pattern), [
            {"start": 0, "end": 12, "variant": "exact"},
        ])
        self.assertEqual(AUDIT.find_contract_matches("wgt_0123abcde", pattern), [])
        self.assertEqual(AUDIT.find_contract_matches("legacywgt_0123abcd", pattern), [])
        self.assertEqual(AUDIT.find_contract_matches("(wgt_0123abcd).", pattern), [
            {"start": 1, "end": 13, "variant": "exact"},
        ])

    def test_matches_are_reported_in_utf8_bytes(self) -> None:
        pattern = AUDIT.compile_family(self.FAMILY)
        self.assertEqual(AUDIT.find_contract_matches("\U0001F511 wgo_abcd", pattern), [
            {"start": 5, "end": 13, "variant": "open-ended"},
        ])

    def test_audit_text_dispositions(self) -> None:
        pattern = AUDIT.compile_family(self.FAMILY)
        retained = AUDIT.audit_text("k=wgt_0123abcd", [{"start": 2, "end": 14}], pattern)
        self.assertEqual(retained["disposition"], "retained")
        broad = AUDIT.audit_text("k=wgt_0123abc", [{"start": 2, "end": 13}], pattern)
        self.assertEqual(broad["disposition"], "broad-shape")
        self.assertEqual(broad["lostRanges"], [{"start": 2, "end": 13}])
        silent = AUDIT.audit_text("k=wgt_", [], pattern)
        self.assertEqual(silent["disposition"], "silent")
        review = AUDIT.audit_text("k=wgt_0123abcd", [], pattern)
        self.assertEqual(review["disposition"], "review")
        self.assertEqual(review["contractOnlyMatches"], [{"start": 2, "end": 14, "variant": "exact"}])

    def test_family_patterns_omits_a_family_with_no_adopted_variant(self) -> None:
        contracts = {
            "families": [
                self.FAMILY,
                {"detector": "gizmo-token", "variants": []},
            ]
        }
        patterns = AUDIT.family_patterns(contracts)
        self.assertEqual(set(patterns), {"widget-token"})


class BaselineDerivationTests(unittest.TestCase):
    CONTRACTS = {"families": [{"detector": "widget-token", "variants": [{"id": "exact", "grammar": "wgt_[a-f0-9]{8}"}]}]}

    def _pair(self, twin_parts: list[dict], positive_expected: list[dict] | None = None) -> dict:
        positive_token = {"synthetic": {"label": "w", "length": 8, "alphabet": "hex"}}
        return {
            "family": "widget-token",
            "variant": "exact",
            "mutation": "length: 7 vs contracted 8",
            "positive": {
                "id": "widget-token-exact-plain",
                "construction": {"context": "plain", "parts": [{"literal": "wgt_"}, positive_token]},
                "expected": positive_expected if positive_expected is not None else [{"start": 0, "end": 12}],
                "actualBeta4": [{"start": 0, "end": 12}],
            },
            "negative": {
                "id": "widget-token-exact-plain-twin",
                "construction": {"context": "plain", "parts": twin_parts},
                "expected": [],
                "actualBeta4": [{"start": 0, "end": 11}],
            },
            "contractView": {},
        }

    def test_derives_hashes_ranges_and_contract_view(self) -> None:
        pair = self._pair([{"literal": "wgt_"}, {"synthetic": {"label": "w", "length": 8, "alphabet": "hex", "take": 7}}])
        derived, errors = AUDIT.derive_baseline({"pairs": [pair]}, self.CONTRACTS)
        self.assertEqual(errors, [])
        row = derived["pairs"][0]
        self.assertEqual(row["positive"]["contentBytes"], 14)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", row["positive"]["contentSha256"]))
        self.assertEqual(row["contractView"], {
            "positiveVariant": "exact",
            "positiveMatchesExpectedRange": True,
            "twinFlaggedByContract": False,
            "twinMutationRetained": True,
        })
        self.assertEqual(derived["counts"]["twinsFlaggedByContract"], 0)
        self.assertEqual(derived["counts"]["uniqueMutations"], 1)

    def test_a_twin_the_contract_still_matches_is_reported_not_hidden(self) -> None:
        pair = self._pair([{"literal": "wgt_"}, {"synthetic": {"label": "w", "length": 8, "alphabet": "hex"}}])
        derived, errors = AUDIT.derive_baseline({"pairs": [pair]}, self.CONTRACTS)
        self.assertEqual(errors, [])
        view = derived["pairs"][0]["contractView"]
        self.assertTrue(view["twinFlaggedByContract"])
        self.assertEqual(view["twinContractMatches"], [{"start": 0, "end": 12, "variant": "exact"}])

    def test_an_expected_range_that_disagrees_with_the_construction_is_an_error(self) -> None:
        pair = self._pair([{"literal": "wgt_"}, {"literal": "0123abc"}], positive_expected=[{"start": 0, "end": 11}])
        _, errors = AUDIT.derive_baseline({"pairs": [pair]}, self.CONTRACTS)
        self.assertTrue(any("does not equal the constructed token range" in e for e in errors))


class CommittedEvidenceTests(unittest.TestCase):
    """The committed evidence files must be exactly what the contracts derive."""

    def test_committed_baseline_and_corpus_audit_are_current(self) -> None:
        contracts = AUDIT.load_json(AUDIT.CONTRACTS_PATH)
        self.assertEqual(AUDIT.check(contracts), [])

    def test_every_frozen_twin_is_silent_and_every_paired_positive_survives(self) -> None:
        baseline = AUDIT.load_json(AUDIT.BASELINE_PATH)
        self.assertEqual(baseline["counts"]["twins"], 24)
        self.assertEqual(baseline["counts"]["uniqueMutations"], 12)
        self.assertEqual(baseline["counts"]["twinsFlaggedByBeta4"], 24)
        self.assertEqual(baseline["counts"]["twinsFlaggedByContract"], 0)
        self.assertEqual(baseline["counts"]["positivesPreservedByContract"], 24)

    def test_the_corpus_audit_never_carries_fixture_inputs(self) -> None:
        text = json.dumps(AUDIT.load_json(AUDIT.CORPUS_AUDIT_PATH))
        self.assertNotIn("SYNTHETIC_REVOKED", text)
        self.assertNotIn("T3BlbkFJ", text)


if __name__ == "__main__":
    unittest.main()
