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
        "families": {"items": {"properties": {"status": {"enum": ["stable", "provisional", "pending", "unsupported"]}}}},
        "distribution": {"properties": {"stable": {}, "provisional": {}, "pending": {}, "unsupported": {}}},
    }
}


def family(provider, family_id, name, status, *, reason=None, tier="T1", detectors=("widget-token",)):
    return {
        "provider": provider,
        "family": family_id,
        "familyName": name,
        "status": status,
        "evidenceTier": tier if status != "unsupported" else None,
        "providerSource": None,
        "corroboratingScanners": [],
        "twinCoverage": None,
        "unresolvedCriticalItems": None,
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
        self.assertEqual(len(table_line.split(" | ")), 5)

    def test_rendering_is_deterministic(self) -> None:
        m = matrix([family("widget", "widget:token", "Widget token", "stable")])
        self.assertEqual(GEN.render_matrix_markdown(m), GEN.render_matrix_markdown(m))


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


if __name__ == "__main__":
    unittest.main()
