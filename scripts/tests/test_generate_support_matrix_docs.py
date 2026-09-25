from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "generate-support-matrix-docs.py"
SPEC = importlib.util.spec_from_file_location("generate_support_matrix_docs", SCRIPT)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GEN
SPEC.loader.exec_module(GEN)

ROOT = SCRIPT.resolve().parents[1]

SCHEMA = {
    "properties": {
        "families": {
            "items": {
                "properties": {
                    "status": {"enum": ["stable", "provisional", "pending", "unsupported"]},
                    "evidenceTier": {"enum": ["T0", "T1", "T2", "T3", None]},
                    "evidenceBasis": {
                        "enum": [
                            "provider-documented",
                            "independently-corroborated",
                            "empirically-observed",
                            "project-policy",
                            "none",
                        ]
                    },
                    "qualificationProfile": {"enum": ["documented", "empirical", None]},
                }
            }
        },
        "distribution": {"properties": {"stable": {}, "provisional": {}, "pending": {}, "unsupported": {}}},
    }
}


def family(
    provider,
    family_id,
    name,
    status,
    *,
    reason=None,
    tier="T1",
    basis=None,
    profile=None,
    detectors=("widget-token",),
    provider_source=None,
    empirical_evidence=None,
):
    if status == "stable":
        basis = basis or "provider-documented"
        profile = profile or "documented"
    elif status == "unsupported":
        basis = "none"
    else:
        basis = basis or "independently-corroborated"
    return {
        "provider": provider,
        "family": family_id,
        "familyName": name,
        "status": status,
        "evidenceTier": tier if status != "unsupported" else None,
        "evidenceBasis": basis,
        "qualificationProfile": profile,
        "providerSource": provider_source,
        "corroboratingScanners": [],
        "twinCoverage": None,
        "unresolvedCriticalItems": None,
        "empiricalEvidence": empirical_evidence,
        "fixtureProfile": None,
        "detectors": list(detectors) if status != "unsupported" else [],
        "reason": reason if status != "stable" else None,
    }


def matrix(families):
    distribution = {"stable": 0, "provisional": 0, "pending": 0, "unsupported": 0}
    providers = set()
    for f in families:
        distribution[f["status"]] += 1
        if f["provider"]:
            providers.add(f["provider"])
    return {
        "schemaVersion": 1,
        "taxonomySchemaVersion": 1,
        "sourceReport": {
            "schemaVersion": 1,
            "generatedAt": "2026-09-21T00:00:00.000Z",
            "runId": "test-run",
            "revision": "0" * 40,
            "dirty": False,
            "criteriaSchemaVersion": 1,
        },
        "providerCount": len(providers),
        "familyCount": len(families),
        "distribution": distribution,
        "stableDistribution": {
            "documented": sum(
                f["status"] == "stable" and f["qualificationProfile"] == "documented" for f in families
            ),
            "empirical": sum(
                f["status"] == "stable" and f["qualificationProfile"] == "empirical" for f in families
            ),
        },
        "families": families,
    }


class ValidateMatrixTests(unittest.TestCase):
    def test_accepts_a_well_formed_matrix(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        self.assertEqual(GEN.validate_matrix(m, SCHEMA), [])

    def test_rejects_a_status_outside_the_vocabulary(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["families"][0]["status"] = "beta"
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("not in the matrix vocabulary" in e for e in errors))

    def test_rejects_a_non_stable_family_with_no_reason(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "pending", reason=None)])
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("carries no reason" in e for e in errors))

    def test_rejects_a_distribution_that_disagrees_with_the_families(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["distribution"]["stable"] = 0
        m["distribution"]["provisional"] = 1
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("does not match the families actually present" in e for e in errors))

    def test_rejects_a_wrong_provider_count(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["providerCount"] = 2
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("distinct providers" in e for e in errors))

    def test_rejects_a_wrong_family_count(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["familyCount"] = 2
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("families present" in e for e in errors))

    def test_accepts_t2_empirical_stable_without_rewriting_it_as_t1(self) -> None:
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    tier="T2",
                    basis="empirically-observed",
                    profile="empirical",
                )
            ]
        )
        self.assertEqual(GEN.validate_matrix(m, SCHEMA), [])
        self.assertEqual(m["families"][0]["evidenceTier"], "T2")

    def test_accepts_t2_corroborated_empirical_stable(self) -> None:
        # redact-secret-benchmarks' decision-qualify-empirical-stable-by-corroboration.
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    tier="T2",
                    basis="independently-corroborated",
                    profile="empirical",
                )
            ]
        )
        self.assertEqual(GEN.validate_matrix(m, SCHEMA), [])

    def test_rejects_empirical_qualification_on_a_non_empirical_basis(self) -> None:
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    tier="T2",
                    basis="project-policy",
                    profile="empirical",
                )
            ]
        )
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("must remain T2" in error for error in errors))

    def test_rejects_empirical_qualification_that_masquerades_as_t1(self) -> None:
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    tier="T1",
                    basis="empirically-observed",
                    profile="empirical",
                )
            ]
        )
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("must remain T2" in error for error in errors))

    def test_rejects_an_unknown_evidence_basis_and_qualification_profile(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["families"][0]["evidenceBasis"] = "marketing-claim"
        m["families"][0]["qualificationProfile"] = "assumed"
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("evidence basis" in error and "not in" in error for error in errors))
        self.assertTrue(any("qualification profile" in error and "not in" in error for error in errors))

    def test_rejects_a_stable_distribution_that_disagrees_with_profiles(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        m["stableDistribution"] = {"documented": 0, "empirical": 1}
        errors = GEN.validate_matrix(m, SCHEMA)
        self.assertTrue(any("stableDistribution" in error for error in errors))


class RenderMatrixMarkdownTests(unittest.TestCase):
    def test_every_status_section_and_count_is_present(self) -> None:
        m = matrix(
            [
                family("widget", "widget:token", "Widget token", "stable"),
                family("gadget", "gadget:token", "Gadget token", "provisional", reason="tool-corroborated only"),
                family("gizmo", "gizmo:token", "Gizmo token", "pending", reason="no positive contract yet"),
                family(
                    "sprocket",
                    "sprocket:legacy-token",
                    "Legacy token",
                    "unsupported",
                    reason="superseded by sprocket:token; no contract for the legacy shape",
                ),
            ]
        )
        text = GEN.render_matrix_markdown(m)
        self.assertIn("### `stable` (1)", text)
        self.assertIn("### `provisional` (1)", text)
        self.assertIn("### `pending` (1)", text)
        self.assertIn("### `unsupported` (1)", text)
        # Provisional's meaning must state it is not "almost stable" (issue #510 acceptance criterion).
        self.assertIn("not \"almost stable\"", text)
        # An unsupported family is shown with its reason, never silently absent.
        self.assertIn("Legacy token", text)
        self.assertIn("superseded by sprocket:token", text)

    def test_a_pipe_in_a_reason_does_not_break_the_table(self) -> None:
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "provisional",
                    reason="first check failed | second check failed",
                )
            ]
        )
        text = GEN.render_matrix_markdown(m)
        table_line = next(line for line in text.splitlines() if "Widget token" in line)
        # The literal pipe in the reason is escaped, not a sixth table delimiter.
        self.assertIn("first check failed \\| second check failed", table_line)
        self.assertEqual(len(table_line.split(" | ")), 8)

    def test_rendering_is_deterministic(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        self.assertEqual(GEN.render_matrix_markdown(m), GEN.render_matrix_markdown(m))

    def test_stable_copy_states_it_is_not_exhaustive(self) -> None:
        # Issue #589 acceptance criterion: stable must not read as "every
        # variant, forever" -- historical and future variants are explicitly
        # out of scope for the claim.
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_matrix_markdown(m)
        self.assertIn("does not mean every historical or future variant", text)

    def test_links_to_the_measurement_protocol_without_requiring_it_first(self) -> None:
        # Issue #589 acceptance criterion: the guide links to the detailed
        # protocol but says a reader need not read it first.
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_matrix_markdown(m)
        self.assertIn(
            "https://github.com/redact-secret/redact-secret-benchmarks/blob/"
            f"{m['sourceReport']['revision']}/docs/specs/support-status.md",
            text,
        )
        self.assertIn("You do not need to read it", text)

    def test_stable_family_exposes_supported_contexts_and_limitations(self) -> None:
        # Issue #589 acceptance criterion: a stable family's supported
        # contexts and known limitations are shown where evidence provides
        # them, drawn from its providerSource.covers rather than `reason`
        # (which is always null for `stable`).
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    provider_source={
                        "url": "https://example.invalid/docs",
                        "observedAt": "2026-09-01",
                        "formatVersion": "1",
                        "covers": "wgt_ prefix; the 8-character suffix variant is not covered",
                    },
                )
            ]
        )
        text = GEN.render_matrix_markdown(m)
        self.assertIn("Supported contexts & known limitations", text)
        self.assertIn("wgt_ prefix; the 8-character suffix variant is not covered", text)

    def test_stable_family_with_no_provider_source_falls_back(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable", provider_source=None)])
        text = GEN.render_matrix_markdown(m)
        self.assertIn("not recorded in the pinned evidence", text)

    def test_empirical_stable_keeps_t2_and_uses_the_expected_user_label(self) -> None:
        m = matrix(
            [
                family(
                    "widget",
                    "widget:token",
                    "Widget token",
                    "stable",
                    tier="T2",
                    basis="empirically-observed",
                    profile="empirical",
                    empirical_evidence={
                        "supportedContexts": ["assignment values"],
                        "uncertainty": "bare values are not covered",
                    },
                )
            ]
        )
        text = GEN.render_matrix_markdown(m)
        self.assertIn("Stable · Empirically qualified", text)
        self.assertIn("| T2 | Provider-issued observation | Empirical |", text)
        self.assertIn("supported contexts: assignment values", text)
        self.assertIn("uncertainty: bare values are not covered", text)

    def test_documented_and_tool_corroborated_labels_are_user_facing(self) -> None:
        m = matrix(
            [
                family("widget", "widget:token", "Widget token", "stable"),
                family("gadget", "gadget:token", "Gadget token", "provisional", reason="more evidence needed", tier="T2"),
            ]
        )
        text = GEN.render_matrix_markdown(m)
        self.assertIn("Stable · Provider documented", text)
        self.assertIn("Provisional · Tool corroborated", text)

    def test_counts_are_split_by_qualification_profile_and_evidence_tier(self) -> None:
        m = matrix(
            [
                family("widget", "widget:token", "Widget token", "stable"),
                family(
                    "gadget",
                    "gadget:token",
                    "Gadget token",
                    "stable",
                    tier="T2",
                    basis="empirically-observed",
                    profile="empirical",
                ),
                family("policy", "policy:token", "Policy token", "provisional", reason="policy only", tier="T3", basis="project-policy"),
            ]
        )
        text = GEN.render_matrix_markdown(m)
        self.assertIn("| Documented | 1 |", text)
        self.assertIn("| Empirical | 1 |", text)
        self.assertIn("| T1 | 1 |", text)
        self.assertIn("| T2 | 1 |", text)
        self.assertIn("| T3 | 1 |", text)


class ReadmeFragmentTests(unittest.TestCase):
    def test_injects_between_markers(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        fragment = GEN.render_readme_fragment(m)
        readme = f"# Title\n\n{GEN.README_START}\nold\n{GEN.README_END}\n\nrest\n"
        updated = GEN.inject_readme_fragment(readme, fragment)
        self.assertIn(fragment, updated)
        self.assertIn("rest", updated)
        self.assertNotIn("old\n", updated)

    def test_raises_when_markers_are_missing(self) -> None:
        with self.assertRaises(ValueError):
            GEN.inject_readme_fragment("# Title\n\nno markers here\n", "fragment")

    def test_explains_stable_profiles_and_reports_tier_counts(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        fragment = GEN.render_readme_fragment(m)
        self.assertIn("Provider documented", fragment)
        self.assertIn("Empirically qualified", fragment)
        self.assertIn("empirical qualification remains T2", fragment)
        self.assertIn("evidence tiers: T1: 1, T2: 0, T3: 0, T0: 0", fragment)


class ReleaseNoteTests(unittest.TestCase):
    def test_no_previous_matrix_states_so(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(m, None)
        self.assertIn("No previous pinned matrix was given to diff against.", text)

    def test_reports_a_moved_family(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "provisional", reason="tool-corroborated only")])
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("`widget:token`: stable -> provisional", text)

    def test_reports_the_stable_delta(self) -> None:
        # Issue #589 acceptance criterion: release notes show a measured
        # stable delta, not just the raw counts.
        current = matrix(
            [
                family("widget", "widget:token", "Widget token", "stable"),
                family("gadget", "gadget:token", "Gadget token", "stable"),
            ]
        )
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("Stable: 2 (+1 from 1).", text)

    def test_a_family_leaving_stable_is_tagged_a_regression(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "provisional", reason="tool-corroborated only")])
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("`widget:token`: stable -> provisional (regression)", text)

    def test_a_family_reaching_stable_is_tagged_an_improvement(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous = matrix([family("widget", "widget:token", "Widget token", "provisional", reason="tool-corroborated only")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("`widget:token`: provisional -> stable (improvement)", text)

    def test_a_move_between_non_stable_statuses_is_untagged(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "pending", reason="no positive contract yet")])
        previous = matrix([family("widget", "widget:token", "Widget token", "provisional", reason="tool-corroborated only")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("`widget:token`: provisional -> pending\n", text)

    def test_reports_no_movement(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("No family's status moved since the previous release.", text)

    def test_reports_added_and_removed_families(self) -> None:
        current = matrix([family("widget", "widget:new-token", "New token", "stable")])
        previous = matrix([family("widget", "widget:old-token", "Old token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("New families tracked: `widget:new-token`.", text)
        self.assertIn("Families no longer tracked: `widget:old-token`.", text)

    def test_a_different_benchmarks_revision_is_not_comparable(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous = matrix([family("widget", "widget:token", "Widget token", "provisional", reason="tool-corroborated only")])
        previous["sourceReport"]["revision"] = "1" * 40
        text = GEN.render_release_note(current, previous)
        self.assertIn("The previous pinned matrix is not comparable", text)
        self.assertNotIn("Stable: 1 (", text)
        self.assertNotIn("improvement", text)

    def test_a_candidate_build_baseline_is_not_comparable(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous["sourceReport"]["product"] = {"sourceCommit": "2" * 40}
        text = GEN.render_release_note(current, previous)
        self.assertIn("The previous pinned matrix is not comparable", text)
        self.assertIn("candidate build", text)

    def test_a_comparable_baseline_is_named(self) -> None:
        current = matrix([family("widget", "widget:token", "Widget token", "stable")])
        previous = matrix([family("widget", "widget:token", "Widget token", "stable")])
        text = GEN.render_release_note(current, previous)
        self.assertIn("Baseline: the previous release's published package measured on this corpus", text)


class ChangelogFragmentTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp)
        (self.tmp / "releases" / "1.0.0").mkdir(parents=True)
        self.fragment = "### Support status\n\n1 providers, 1 credential families.\n"
        (self.tmp / "releases" / "1.0.0" / GEN.FRAGMENT_NAME).write_text(self.fragment, encoding="utf-8")
        self.changelog = self.tmp / "CHANGELOG.md"

    def problems(self, body: str) -> list[str]:
        self.changelog.write_text(body, encoding="utf-8")
        return GEN.check_changelog_fragments(self.changelog, self.tmp / "releases")

    def test_matching_section_passes(self) -> None:
        body = "## Unreleased\n\n## 1.0.0 — 2026-01-01\n\nProse.\n\n" + self.fragment + "\n### Other\n\nx\n"
        self.assertEqual(self.problems(body), [])

    def test_hand_edited_section_fails(self) -> None:
        body = "## 1.0.0 — 2026-01-01\n\n### Support status\n\n1 providers, 2 credential families.\n"
        self.assertEqual(len(self.problems(body)), 1)

    def test_missing_section_fails(self) -> None:
        self.assertEqual(len(self.problems("## 1.0.0 — 2026-01-01\n\nProse.\n")), 1)

    def test_the_next_version_is_not_read_into_this_one(self) -> None:
        body = "## 1.0.0 — 2026-01-01\n\nProse.\n\n## 0.9.0 — 2025-01-01\n\n" + self.fragment
        self.assertEqual(len(self.problems(body)), 1)

    def test_committed_changelog_matches_committed_fragments(self) -> None:
        self.assertEqual(GEN.check_changelog_fragments(GEN.CHANGELOG_PATH, GEN.RELEASES_DIR), [])


class RealRepoReconciliationTests(unittest.TestCase):
    """Exercises the generator over the real, pinned `benchmarks/support-matrix.json`
    and its vendored schema, the same way `python3 -B
    scripts/generate-support-matrix-docs.py` would."""

    def test_committed_matrix_is_structurally_valid(self) -> None:
        pinned_matrix = GEN.load_json(GEN.MATRIX_PATH)
        schema = GEN.load_json(GEN.SCHEMA_PATH)
        self.assertEqual(GEN.validate_matrix(pinned_matrix, schema), [])

    def test_committed_support_matrix_doc_is_up_to_date(self) -> None:
        pinned_matrix = GEN.load_json(GEN.MATRIX_PATH)
        fresh = GEN.render_matrix_markdown(pinned_matrix)
        committed = GEN.DOC_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            fresh,
            committed,
            "docs/support-matrix.md is out of date; regenerate it with "
            "`python3 -B scripts/generate-support-matrix-docs.py`",
        )

    def test_committed_readme_support_section_is_up_to_date(self) -> None:
        pinned_matrix = GEN.load_json(GEN.MATRIX_PATH)
        fragment = GEN.render_readme_fragment(pinned_matrix)
        readme = GEN.README_PATH.read_text(encoding="utf-8")
        start = readme.find(GEN.README_START)
        end = readme.find(GEN.README_END) + len(GEN.README_END)
        self.assertNotEqual(start, -1, "README.md is missing the support-matrix markers")
        self.assertEqual(
            readme[start:end],
            fragment,
            "README.md's support-status section is out of date; regenerate it with "
            "`python3 -B scripts/generate-support-matrix-docs.py`",
        )

    def test_docs_never_render_a_status_outside_the_schema_vocabulary(self) -> None:
        """Mirrors redact-secret-benchmarks' `check-support-ui.mjs` UI gate
        (#50): a probe matrix built for each vocabulary status must render
        only that status, never a hardcoded or renamed one (issue #510's "CI
        fails if a doc ... carries a support status that is not in the
        matrix" acceptance criterion)."""
        schema = GEN.load_json(GEN.SCHEMA_PATH)
        vocabulary = schema["properties"]["families"]["items"]["properties"]["status"]["enum"]
        for status in vocabulary:
            probe = matrix([family("probe", "probe:family", "Probe family", status, reason="probe")])
            text = GEN.render_matrix_markdown(probe)
            other_statuses = [s for s in vocabulary if s != status]
            for other in other_statuses:
                # The status legend still documents every status; only the per-family
                # sections and counts may exclusively carry the probed status.
                self.assertIn(f"### {other.capitalize()}\n\nNone.", text)


DOCUMENTED_REASON = (
    "documented.minimumPositiveAxes: 2 < 4 — Positive coverage must span four axes. | "
    "documented.minimumBenignCases: 5 < 8 — Eight benign controls are required. | "
    "documented.minimumControlAxes: 3 < 4 — Benign coverage must span four axes."
)
EMPIRICAL_REASON = (
    "empirical.evidenceBasis: independently-corroborated — T2 remains empirical provenance. | "
    "empirical.minimumObservations: 0 < 5 — Five observations are the minimum. | "
    "empirical.minimumSubjects: 0 < 2 — Two subjects. | "
    "empirical.minimumIssuanceDates: 0 < 2 — Two dates. | "
    "empirical.minimumCorroborationClasses: 0 < 2 — Two classes. | "
    "empirical.uncertainty: missing — explicit uncertainty is required | "
    "empirical.supportedContexts: none — supported-context limits are required | "
    "empirical.minimumTwinPairs: 3 < 8 — Eight twin pairs. | "
    "empirical.mode: missing — choose shape or context-constrained qualification"
)
RAW_IDENTIFIERS = ("documented.", "empirical.", "fixtureProfile", "qualificationProfile", "positiveContractTier", " < ")


class UserFacingReasonTests(unittest.TestCase):
    """Issue #723: Reason cells group evaluator gates into plain language."""

    def assert_plain(self, text: str) -> None:
        for identifier in RAW_IDENTIFIERS:
            self.assertNotIn(identifier, text)

    def test_documented_fixture_gates_group_into_one_sentence(self) -> None:
        text = GEN.user_facing_reason(DOCUMENTED_REASON)
        self.assertEqual(text, "Not yet stable: needs broader positive test contexts and more benign controls.")
        self.assert_plain(text)

    def test_empirical_gates_group_observations_twins_and_boundary(self) -> None:
        text = GEN.user_facing_reason(EMPIRICAL_REASON)
        self.assertEqual(
            text,
            "Not yet stable: needs independent observations of provider-issued keys, more near-miss twin pairs "
            "and a defined supported-context boundary with its uncertainty stated.",
        )
        self.assertIn("independent observations of provider-issued keys", text)
        self.assertIn("more near-miss twin pairs", text)
        self.assertIn("a defined supported-context boundary with its uncertainty stated", text)
        self.assertNotIn("positive test contexts", text)
        self.assert_plain(text)

    def test_context_boundary_alone(self) -> None:
        text = GEN.user_facing_reason("empirical.mode: missing — choose a mode")
        self.assertEqual(
            text, "Not yet stable: needs a defined supported-context boundary with its uncertainty stated."
        )

    def test_project_policy_family_is_explained_without_tier_names(self) -> None:
        text = GEN.user_facing_reason(
            "qualificationProfile: tier T3 is not eligible for documented or empirical stable"
        )
        self.assertIn("project policy", text)
        self.assertIn("not eligible for stable qualification", text)
        self.assert_plain(text)
        self.assertNotIn("T3", text)

    def test_pending_family_with_no_contract(self) -> None:
        text = GEN.user_facing_reason("positiveContractTier T0 — no positive fixture has cleared review yet")
        self.assertEqual(text, "No reviewed detection contract is available yet.")

    def test_unsupported_free_text_is_kept_verbatim(self) -> None:
        reason = "superseded by sprocket:token; no contract for the legacy shape"
        self.assertEqual(GEN.user_facing_reason(reason), reason)

    def test_an_unmapped_gate_identifier_fails_loudly(self) -> None:
        with self.assertRaisesRegex(ValueError, "unmapped support-matrix gate 'empirical.newGate'"):
            GEN.user_facing_reason("empirical.newGate: 0 < 1 — a gate added upstream")

    def test_corroborated_route_gates_name_both_empirical_routes_once(self) -> None:
        text = GEN.user_facing_reason(
            "empirical.corroborated.minimumReferences: 0 < 3 — refs. (corroborated route) | "
            "empirical.corroborated.minimumOwners: 0 < 3 — owners. (corroborated route) | "
            "empirical.minimumObservations: 0 < 5 — obs. (observed route, optional)"
        )
        self.assertEqual(
            text,
            "Not yet stable: needs independent corroboration of its format "
            "(several sources, or provider-issued keys).",
        )
        self.assert_plain(text)

    def test_unresolved_contradictions_and_context_constrained_gates(self) -> None:
        text = GEN.user_facing_reason(
            "empirical.unresolvedContradictions: 4 > 0 — doubt. | "
            "empirical.contextConstrained.minimumContextTwinPairs: 2 < 10 — twins. | "
            "empirical.contextConstrained.minimumFixtures: 32 < 48 — fixtures."
        )
        self.assertEqual(
            text,
            "Not yet stable: needs its conflicting format evidence settled, more near-miss twin pairs "
            "and more test fixtures overall.",
        )
        self.assert_plain(text)

    def test_fixture_profile_debt_groups_by_cell(self) -> None:
        text = GEN.user_facing_reason(
            "fixtureProfile stable-empirical: 20 total fixtures < 40 (20 short) | "
            "fixtureProfile stable-empirical: 5 positive/context cases < 8 (3 short) | "
            "fixtureProfile stable-empirical: 3 twin pairs < 8 (5 short)"
        )
        self.assertEqual(
            text,
            "Not yet stable: needs broader positive test contexts, more near-miss twin pairs "
            "and more test fixtures overall.",
        )
        self.assert_plain(text)

    def test_an_unmapped_fixture_profile_segment_fails_loudly(self) -> None:
        with self.assertRaisesRegex(ValueError, "unmapped support-matrix gate 'fixtureProfile stable-empirical'"):
            GEN.user_facing_reason("fixtureProfile stable-empirical: requires T2 evidence, the contract is T1")

    def test_rendering_changes_only_the_reason_cell(self) -> None:
        fam = family("gadget", "gadget:token", "Gadget token", "provisional", reason=DOCUMENTED_REASON, tier="T1",
                     basis="provider-documented")
        m = matrix([fam])
        before = repr(m)
        doc = GEN.render_matrix_markdown(m)
        self.assertEqual(repr(m), before, "rendering must not mutate the pinned matrix")
        self.assertIn("Not yet stable: needs broader positive test contexts and more benign controls.", doc)
        self.assertIn("| gadget | Gadget token | Provisional · Provider documentation | T1 |", doc)
        self.assertNotIn("documented.minimumPositiveAxes", doc)

    def test_the_committed_matrix_renders_without_raw_identifiers(self) -> None:
        committed = GEN.load_json(GEN.MATRIX_PATH)
        for fam in committed["families"]:
            if fam.get("reason"):
                self.assert_plain(GEN.user_facing_reason(fam["reason"]))

    def test_status_descriptions_do_not_depend_on_tier_codes(self) -> None:
        for status, copy in GEN.STATUS_COPY.items():
            for code in ("T0", "T1", "T2", "T3"):
                self.assertNotIn(code, copy, status)


if __name__ == "__main__":
    unittest.main()
