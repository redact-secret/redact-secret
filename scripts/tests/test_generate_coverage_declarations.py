from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-coverage-declarations.py"
SPEC = importlib.util.spec_from_file_location("generate_coverage_declarations", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]

# evidence-requirements.md §4's requirement matrix, mirrored here (and in
# conformance/schema.ts's COVERAGE_REQUIREMENT_MATRIX) so this test can check
# generator output shape without a Node/TypeScript toolchain.
REQUIRED_DIMENSIONS = {
    "provider": {
        "positive", "near-miss-negative", "boundary", "malformed", "overlap",
        "host-context", "range", "adversarial",
    },
    "structural": {
        "positive", "near-miss-negative", "boundary", "malformed", "overlap",
        "host-context", "range", "adversarial",
    },
    "contextual": {
        "positive", "near-miss-negative", "boundary", "malformed", "overlap",
        "host-context", "range", "adversarial",
    },
    "incremental": {"malformed", "range", "incremental", "adversarial"},
    "binding-edge": {"malformed", "range", "incremental", "adversarial"},
}


def fixture(
    id_: str,
    detector: str,
    *,
    kind: str,
    support: str,
    tier: str = "canonical",
    expected_types: list[str] | None = None,
    contexts: list[str] | None = None,
    note: str = "note",
) -> dict:
    expected = (
        [
            {
                "detector": detector,
                "type": type_name,
                "confidence": "high",
                "specificity": "provider",
                "start": 0,
                "end": 1,
            }
            for type_name in expected_types
        ]
        if expected_types
        else []
    )
    return {
        "id": id_,
        "detector": detector,
        "kind": kind,
        "support": support,
        "tier": tier,
        "contexts": contexts or ["plain-text"],
        "input": "irrelevant",
        "expected": expected,
        "note": note,
    }


class BehaviorClassTests(unittest.TestCase):
    def test_structural_types_are_declared_structural(self) -> None:
        for type_name in ("private_key", "jwt", "bearer_token", "connection_string_password"):
            self.assertEqual(GEN.behavior_class_for(type_name), "structural")

    def test_contextual_types_are_declared_contextual(self) -> None:
        for type_name in ("contextual_secret", "authorization_credential"):
            self.assertEqual(GEN.behavior_class_for(type_name), "contextual")

    def test_everything_else_is_provider(self) -> None:
        self.assertEqual(GEN.behavior_class_for("github_token"), "provider")
        self.assertEqual(GEN.behavior_class_for("aws_access_key_id"), "provider")


class SlugTests(unittest.TestCase):
    def test_underscores_become_hyphens(self) -> None:
        self.assertEqual(GEN.slug("authorization_credential"), "authorization-credential")

    def test_already_kebab_is_unchanged(self) -> None:
        self.assertEqual(GEN.slug("github-token"), "github-token")


class KindEvidenceTests(unittest.TestCase):
    def test_positive_requires_supported(self) -> None:
        fixtures = [
            fixture("f1", "widget", kind="positive", support="supported", expected_types=["widget_token"]),
            fixture("f2", "widget", kind="positive", support="not-yet-evaluated", expected_types=["widget_token"]),
        ]
        ids = GEN.kind_evidence(fixtures, "widget_token", "positive", ambiguous_keyword=None)
        self.assertEqual(ids, ["f1"])

    def test_boundary_accepts_intentionally_unsupported(self) -> None:
        fixtures = [
            fixture("f1", "widget", kind="boundary", support="intentionally-unsupported"),
        ]
        ids = GEN.boundary_evidence(fixtures, "widget_token", ambiguous_keyword=None)
        self.assertEqual(ids, ["f1"])

    def test_boundary_ignores_not_yet_evaluated(self) -> None:
        fixtures = [
            fixture("f1", "widget", kind="boundary", support="not-yet-evaluated"),
        ]
        self.assertEqual(GEN.boundary_evidence(fixtures, "widget_token", ambiguous_keyword=None), [])

    def test_malformed_is_scoped_by_tier_not_kind(self) -> None:
        fixtures = [
            fixture("f1", "widget", kind="boundary", support="intentionally-unsupported", tier="malformed"),
            fixture("f2", "widget", kind="boundary", support="intentionally-unsupported", tier="canonical"),
        ]
        ids = GEN.malformed_evidence(fixtures, "widget_token", ambiguous_keyword=None)
        self.assertEqual(ids, ["f1"])


class SharedDetectorScopingTests(unittest.TestCase):
    """generic-token-shaped: two declared types on one detector, evidence
    scoped to the right one via `expected[].type` or, when `expected` is
    empty, the keyword fallback (`generate-coverage-inventory.py`'s
    `ambiguous_keyword` convention)."""

    def test_positive_evidence_is_scoped_by_expected_type(self) -> None:
        fixtures = [
            fixture("shared-a", "shared", kind="positive", support="supported", expected_types=["type_a"]),
            fixture("shared-b", "shared", kind="positive", support="supported", expected_types=["type_b"]),
        ]
        self.assertEqual(
            GEN.kind_evidence(fixtures, "type_a", "positive", ambiguous_keyword="type"),
            ["shared-a"],
        )
        self.assertEqual(
            GEN.kind_evidence(fixtures, "type_b", "positive", ambiguous_keyword="type"),
            ["shared-b"],
        )

    def test_excluded_kind_falls_back_to_keyword_when_expected_is_empty(self) -> None:
        fixtures = [
            fixture("type-a-negative", "shared", kind="negative", support="supported", note="type_a near miss"),
            fixture("type-b-negative", "shared", kind="negative", support="supported", note="type_b near miss"),
        ]
        self.assertEqual(
            GEN.near_miss_negative_evidence(fixtures, "type_a", ambiguous_keyword="type_a"),
            ["type-a-negative"],
        )


class ResolveSharedFamilyTests(unittest.TestCase):
    def test_shareable_dimension_borrows_from_a_sibling_with_direct_evidence(self) -> None:
        rows_by_type = {
            "type_a": {
                "type": "type_a",
                "dimensions": [GEN.dim("adversarial", GEN.supported(["ev-1"]))],
            },
            "type_b": {
                "type": "type_b",
                "dimensions": [GEN.dim("adversarial", GEN.pending("type-b-adversarial"))],
            },
        }
        GEN.resolve_shared_family(rows_by_type, ["type_a", "type_b"])
        adversarial = rows_by_type["type_b"]["dimensions"][0]
        self.assertEqual(adversarial["state"], "supported")
        self.assertEqual(
            adversarial["exception"],
            {"code": "single-detector-family", "sharedWith": "type_a"},
        )

    def test_overlap_is_never_borrowed_between_sibling_finding_types(self) -> None:
        rows_by_type = {
            "type_a": {
                "type": "type_a",
                "dimensions": [GEN.dim("overlap", GEN.supported(["ev-1"]))],
            },
            "type_b": {
                "type": "type_b",
                "dimensions": [GEN.dim("overlap", GEN.pending("type-b-overlap"))],
            },
        }
        GEN.resolve_shared_family(rows_by_type, ["type_a", "type_b"])
        overlap = rows_by_type["type_b"]["dimensions"][0]
        self.assertEqual(overlap["state"], "pending")

    def test_non_shareable_dimension_is_never_borrowed(self) -> None:
        rows_by_type = {
            "type_a": {
                "type": "type_a",
                "dimensions": [GEN.dim("positive", GEN.supported(["ev-1"]))],
            },
            "type_b": {
                "type": "type_b",
                "dimensions": [GEN.dim("positive", GEN.pending("type-b-positive"))],
            },
        }
        GEN.resolve_shared_family(rows_by_type, ["type_a", "type_b"])
        positive = rows_by_type["type_b"]["dimensions"][0]
        self.assertEqual(positive["state"], "pending")

    def test_borrowing_requires_the_sibling_to_carry_its_own_direct_evidence(self) -> None:
        rows_by_type = {
            "type_a": {
                "type": "type_a",
                "dimensions": [
                    GEN.dim(
                        "adversarial",
                        GEN.supported_via("owned-elsewhere", ownedBy="somewhere-else:adversarial"),
                    )
                ],
            },
            "type_b": {
                "type": "type_b",
                "dimensions": [GEN.dim("adversarial", GEN.pending("type-b-adversarial"))],
            },
        }
        GEN.resolve_shared_family(rows_by_type, ["type_a", "type_b"])
        adversarial = rows_by_type["type_b"]["dimensions"][0]
        self.assertEqual(adversarial["state"], "pending")


class ApplyKnownExceptionsTests(unittest.TestCase):
    def test_authorization_credential_pending_dimensions_cite_the_tracked_backlog_id(self) -> None:
        rows_by_type = {
            "authorization_credential": {
                "type": "authorization_credential",
                "dimensions": [
                    GEN.dim("positive", GEN.pending("authorization-credential-positive")),
                    GEN.dim("overlap", GEN.pending("authorization-credential-overlap")),
                ],
            },
        }
        GEN.apply_known_exceptions(rows_by_type)
        dims = {d["dimension"]: d for d in rows_by_type["authorization_credential"]["dimensions"]}
        self.assertEqual(dims["positive"]["exception"]["backlogId"], "C/F-03")
        # "overlap" is not one of the four dimensions this exception covers.
        self.assertEqual(dims["overlap"]["exception"]["backlogId"], "authorization-credential-overlap")


class BuildDeclarationsIntegrationTests(unittest.TestCase):
    """Runs the real generator over the real repo inputs -- the "migration"
    this generator performs, proven deterministic and structurally sound
    without a Node/TypeScript toolchain."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = GEN.INVENTORY.load_json(GEN.MANIFEST_PATH)
        cls.corpus = GEN.INVENTORY.load_json(GEN.CORPUS_PATH)
        cls.incremental_corpus = GEN.INVENTORY.load_json(GEN.INCREMENTAL_CORPUS_PATH)
        cls.lifecycle_corpus = GEN.INVENTORY.load_json(GEN.LIFECYCLE_CORPUS_PATH)
        cls.unicode_corpus = GEN.INVENTORY.load_json(GEN.UNICODE_CORPUS_PATH)
        cls.error_codes_doc = GEN.INVENTORY.load_json(GEN.ERROR_CODES_PATH)
        cls.report = GEN.build_declarations(
            cls.manifest,
            cls.corpus,
            cls.incremental_corpus,
            cls.lifecycle_corpus,
            cls.unicode_corpus,
            cls.error_codes_doc,
        )

    def test_is_deterministic_across_runs(self) -> None:
        second = GEN.build_declarations(
            self.manifest,
            self.corpus,
            self.incremental_corpus,
            self.lifecycle_corpus,
            self.unicode_corpus,
            self.error_codes_doc,
        )
        self.assertEqual(
            json.dumps(self.report, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_declares_exactly_one_row_per_declared_type_plus_incremental_plus_consumers(self) -> None:
        declared_types = {row["type"] for row in self.report["declarations"]}
        expected_types = {entry["type"] for entry in self.manifest["types"]}
        expected_types.add("incremental")
        expected_types.update(consumer["path"] for consumer in self.manifest["consumers"])
        self.assertEqual(declared_types, expected_types)
        self.assertEqual(len(declared_types), len(self.report["declarations"]))

    def test_every_row_declares_exactly_its_class_required_dimensions(self) -> None:
        for row in self.report["declarations"]:
            declared = {d["dimension"] for d in row["dimensions"]}
            self.assertEqual(
                declared,
                REQUIRED_DIMENSIONS[row["behaviorClass"]],
                f"{row['type']} ({row['behaviorClass']})",
            )

    def test_every_evidence_fixture_id_exists_somewhere_in_the_corpus(self) -> None:
        known_ids = {f["id"] for f in self.corpus["fixtures"]}
        known_ids.update(f["id"] for f in self.unicode_corpus["fixtures"])
        known_ids.update(f["id"] for f in self.incremental_corpus["fixtures"])
        known_ids.update(f["id"] for f in self.lifecycle_corpus["fixtures"])
        known_ids.update(c["code"] for c in self.error_codes_doc["codes"])
        for row in self.report["declarations"]:
            for dimension in row["dimensions"]:
                for evidence_id in dimension["evidenceFixtureIds"]:
                    self.assertIn(
                        evidence_id, known_ids, f"{row['type']}.{dimension['dimension']}"
                    )

    def test_every_pending_dimension_carries_a_bounded_backlog_id(self) -> None:
        for row in self.report["declarations"]:
            for dimension in row["dimensions"]:
                if dimension["state"] != "pending":
                    continue
                backlog_id = dimension["exception"]["backlogId"]
                self.assertTrue(backlog_id and " " not in backlog_id, backlog_id)

    def test_current_declarations_have_no_pending_dimensions(self) -> None:
        pending = {}
        for row in self.report["declarations"]:
            for dimension in row["dimensions"]:
                if dimension["state"] != "pending":
                    continue
                backlog_id = dimension["exception"]["backlogId"]
                pending.setdefault(backlog_id, set()).add(f"{row['type']}.{dimension['dimension']}")
        self.assertEqual(pending, {})

    def test_structural_host_context_breadth_is_owned_by_one_representative(self) -> None:
        structural_types = {
            "private_key",
            "jwt",
            "bearer_token",
            "connection_string_password",
            "otpauth_secret",
        }
        structural = {
            row["type"]: next(
                dimension
                for dimension in row["dimensions"]
                if dimension["dimension"] == "host-context"
            )
            for row in self.report["declarations"]
            if row["type"] in structural_types
        }

        representative = structural["connection_string_password"]
        self.assertEqual(representative["state"], "supported")
        self.assertTrue(representative["classLevel"])
        self.assertTrue(
            {
                "connection-host-dotenv",
                "connection-host-shell",
                "connection-host-javascript",
                "connection-host-log",
                "connection-host-markdown",
            }.issubset(representative["evidenceFixtureIds"])
        )
        for type_name in structural_types - {"connection_string_password"}:
            self.assertEqual(
                structural[type_name]["exception"],
                {
                    "code": "owned-elsewhere",
                    "ownedBy": "connection_string_password:host-context",
                },
            )

    def test_authorization_credential_resolves_the_dimensions_c_f_03_closed(self) -> None:
        """Issue #105 closed `C/F-03`'s exact scope: a supported positive
        fixture per scheme and a boundary fixture pinning
        `MIN_AUTHORIZATION_VALUE_LENGTH`. `host-context` is a real,
        separately-unmet gap the requirement matrix names but `C/F-03` never
        claimed (see `generate-coverage-declarations.py`'s
        `apply_known_exceptions`). Issue #190 independently closes that
        host-context gap with type-owned canonical evidence."""
        auth = next(
            row for row in self.report["declarations"] if row["type"] == "authorization_credential"
        )
        by_dimension = {d["dimension"]: d for d in auth["dimensions"]}
        self.assertEqual(by_dimension["positive"]["state"], "supported")
        self.assertEqual(by_dimension["boundary"]["state"], "supported")
        self.assertEqual(by_dimension["near-miss-negative"]["state"], "supported")

    def test_authorization_credential_owns_host_context_breadth(self) -> None:
        auth = next(
            row for row in self.report["declarations"] if row["type"] == "authorization_credential"
        )
        host_context = next(d for d in auth["dimensions"] if d["dimension"] == "host-context")
        self.assertEqual(host_context["state"], "supported")
        self.assertNotIn("classLevel", host_context)
        self.assertTrue(
            {
                "authorization-host-dotenv",
                "authorization-host-shell",
                "authorization-host-javascript",
                "authorization-host-log",
                "authorization-host-markdown",
            }.issubset(host_context["evidenceFixtureIds"])
        )

    def test_authorization_credential_overlap_is_supported_by_its_own_fixture(self) -> None:
        auth = next(
            row for row in self.report["declarations"] if row["type"] == "authorization_credential"
        )
        overlap = next(d for d in auth["dimensions"] if d["dimension"] == "overlap")
        self.assertEqual(overlap["state"], "supported")
        self.assertIn(
            "authorization-overlap-contextual-assignment",
            overlap["evidenceFixtureIds"],
        )

    def test_committed_coverage_declarations_is_up_to_date(self) -> None:
        """A built-in capability (detector, finding type, corpus evidence)
        added or removed without regenerating and committing
        ``docs/coverage/coverage-declarations.json`` fails here -- issue #104's
        drift-as-a-CI-failure guarantee for the canonical declarations file."""
        committed_path = ROOT / "docs" / "coverage" / "coverage-declarations.json"
        fresh = json.dumps(self.report, indent=2, sort_keys=True) + "\n"
        committed = committed_path.read_text(encoding="utf-8")
        self.assertEqual(
            fresh,
            committed,
            "docs/coverage/coverage-declarations.json is out of date; regenerate it with "
            "`python3 -B scripts/generate-coverage-declarations.py "
            "--out docs/coverage/coverage-declarations.json`",
        )


if __name__ == "__main__":
    unittest.main()
