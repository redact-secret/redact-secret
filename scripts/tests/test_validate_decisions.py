from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate-decisions.py"
REPO_ROOT = SCRIPT.parents[1]
SPEC = importlib.util.spec_from_file_location("validate_decisions", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


def record(
    decision_id: str = "decision-use-rust",
    spec: str = "engine",
    title: str = "Use Rust",
    extra_frontmatter: str = "",
    status: str = "accepted",
    body_extra: str = "",
) -> str:
    return f"""---
decision_id: {decision_id}
status: {status}
scope: workspace
title: {title}
spec: {spec}
{extra_frontmatter}---

# {title}
{body_extra}
## Decision

Use a Rust core.
"""


def add_record(root: Path, name: str, content: str, spec: str | None = "engine") -> None:
    decision_dir = root / "docs" / "decisions"
    decision_dir.mkdir(parents=True, exist_ok=True)
    (decision_dir / name).write_text(content, encoding="utf-8")
    index = decision_dir / "DECISIONS.md"
    existing = index.read_text(encoding="utf-8") if index.exists() else "# Decisions\n\n"
    index.write_text(existing + f"- [{name}]({name})\n", encoding="utf-8")
    if spec is not None:
        route(root, name, spec)


def route(root: Path, name: str, spec: str) -> None:
    """Link a record from a spec file's Rules table -- the routing source of truth."""
    specs_dir = root / "docs" / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    spec_file = specs_dir / f"{spec}.md"
    if not spec_file.exists():
        spec_file.write_text(f"# {spec}\n\n## Rules\n\n", encoding="utf-8")
    existing = spec_file.read_text(encoding="utf-8")
    spec_file.write_text(existing + f"| a rule | [{name}](../decisions/{name}) |\n", encoding="utf-8")


def ensure_all_specs_exist(root: Path) -> None:
    specs_dir = root / "docs" / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    for spec_name in VALIDATOR.SPEC_NAMES:
        spec_file = specs_dir / f"{spec_name}.md"
        if not spec_file.exists():
            spec_file.write_text(f"# {spec_name}\n\n## Rules\n\n", encoding="utf-8")


class DecisionValidationTests(unittest.TestCase):
    """Baseline behavior, updated for the (errors, warnings) return shape."""

    def test_public_workspace_decision_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record())
            ensure_all_specs_exist(root)
            errors, warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])
            self.assertEqual(warnings, [])

    def test_multiple_workspace_locations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record())
            (root / "_notes" / "decisions").mkdir(parents=True)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("multiple workspace decision locations" in error for error in errors))

    def test_record_must_be_indexed_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record())
            ensure_all_specs_exist(root)
            index = root / "docs" / "decisions" / "DECISIONS.md"
            index.write_text("# Decisions\n", encoding="utf-8")
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("is indexed 0 times" in error for error in errors))


# -- spec: required field + spec routing -----------------------------------


class SpecRoutingTests(unittest.TestCase):
    def test_missing_spec_field_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            content = record().replace("spec: engine\n", "")
            add_record(root, "2026-09-09-use-rust.md", content, spec=None)
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("missing required field spec" in error for error in errors))

    def test_unknown_spec_value_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record(spec="not-a-real-spec"), spec=None)
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("is not one of" in error for error in errors))

    def test_record_routed_from_zero_specs_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record(), spec=None)
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("routed from 0 spec file(s)" in error for error in errors))

    def test_record_routed_from_two_specs_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record(), spec="engine")
            route(root, "2026-09-09-use-rust.md", "distribution")
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("routed from 2 spec file(s)" in error for error in errors))

    def test_declared_spec_must_match_the_routing_spec_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # declares spec: engine in frontmatter, but is only linked from distribution.md
            add_record(root, "2026-09-09-use-rust.md", record(spec="engine"), spec="distribution")
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("does not match the spec file that routes it" in error for error in errors))

    def test_valid_single_routing_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record(spec="distribution"), spec="distribution")
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])


# -- supersession bidirectionality ------------------------------------------


class SupersessionTests(unittest.TestCase):
    def test_reciprocal_supersession_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-old.md",
                record(decision_id="decision-old", title="Old", extra_frontmatter="superseded_by: decision-new\n"),
            )
            add_record(
                root,
                "2026-09-10-new.md",
                record(decision_id="decision-new", title="New", extra_frontmatter="supersedes: decision-old\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])

    def test_one_sided_supersession_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-old.md",
                record(decision_id="decision-old", title="Old", extra_frontmatter="superseded_by: decision-new\n"),
            )
            add_record(root, "2026-09-10-new.md", record(decision_id="decision-new", title="New"))
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("not reciprocated" in error for error in errors))

    def test_supersedes_unknown_decision_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-old.md",
                record(
                    decision_id="decision-old",
                    title="Old",
                    extra_frontmatter="superseded_by: decision-does-not-exist\n",
                ),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("references unknown decision_id" in error for error in errors))


# -- aliases uniqueness / resolvability -------------------------------------


class AliasTests(unittest.TestCase):
    def test_unique_well_formed_alias_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-use-rust.md",
                record(extra_frontmatter="aliases: decision-old-merged-in\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])

    def test_malformed_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record(extra_frontmatter="aliases: Not Valid!\n"))
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("invalid alias" in error for error in errors))

    def test_alias_colliding_with_a_real_decision_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-a.md", record(decision_id="decision-a", title="A"))
            add_record(
                root,
                "2026-09-10-b.md",
                record(decision_id="decision-b", title="B", extra_frontmatter="aliases: decision-a\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("collides with a real decision_id" in error for error in errors))

    def test_duplicate_alias_across_records_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-a.md",
                record(decision_id="decision-a", title="A", extra_frontmatter="aliases: decision-merged\n"),
            )
            add_record(
                root,
                "2026-09-10-b.md",
                record(decision_id="decision-b", title="B", extra_frontmatter="aliases: decision-merged\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("already used by" in error for error in errors))


# -- 12 KB size warning (non-fatal) -----------------------------------------


class SizeWarningTests(unittest.TestCase):
    def test_small_record_has_no_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(root, "2026-09-09-use-rust.md", record())
            ensure_all_specs_exist(root)
            _errors, warnings = VALIDATOR.validate(root)
            self.assertEqual(warnings, [])

    def test_large_record_warns_but_does_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            big_body = "Padding text.\n" * 1000
            add_record(root, "2026-09-09-use-rust.md", record(body_extra=big_body))
            ensure_all_specs_exist(root)
            errors, warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])
            self.assertTrue(any("exceeds the 12000-byte guideline" in warning for warning in warnings))


# -- '## Current application' appendix rejection, with the grandfather allowlist --


class CurrentApplicationTests(unittest.TestCase):
    def test_new_current_application_appendix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-use-rust.md",
                record(body_extra="\n## Current application — 2026-09-22 (#1)\n\nUpdated.\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("Current application' appendices are rejected" in error for error in errors))

    def test_grandfathered_current_application_appendix_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # The allowlist is keyed by the exact real repository-relative
            # path, so the fixture must be named to match it.
            add_record(
                root,
                "2026-09-10-adopt-redact-secret-naming-contract.md",
                record(body_extra="\n## Current application — 2026-09-19 (#442)\n\nUpdated.\n"),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertFalse(any("appendices are rejected" in error for error in errors))

    def test_allowlist_entries_name_real_files_with_a_rationale(self) -> None:
        errors = VALIDATOR.check_allowlist_shape(REPO_ROOT)
        self.assertEqual(errors, [])


# -- full_record permalink format -------------------------------------------


class FullRecordTests(unittest.TestCase):
    def test_well_formed_permalink_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            permalink = "https://github.com/redact-secret/redact-secret/blob/" + ("a" * 40) + "/docs/decisions/x.md"
            add_record(root, "2026-09-09-use-rust.md", record(extra_frontmatter=f"full_record: {permalink}\n"))
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertEqual(errors, [])

    def test_malformed_permalink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            add_record(
                root,
                "2026-09-09-use-rust.md",
                record(
                    extra_frontmatter=(
                        "full_record: https://github.com/redact-secret/redact-secret/blob/main/docs/decisions/x.md\n"
                    )
                ),
            )
            ensure_all_specs_exist(root)
            errors, _warnings = VALIDATOR.validate(root)
            self.assertTrue(any("full_record is not a main-commit blob permalink" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
