from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "reconcile-artifact-plan.py"
SPEC = importlib.util.spec_from_file_location("reconcile_artifact_plan", SCRIPT)
assert SPEC and SPEC.loader
PLAN = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PLAN
SPEC.loader.exec_module(PLAN)


PUBLISHED_MATCHING = PLAN.Observation(live_published=True, content_matches=True)
PUBLISHED_CONFLICTING = PLAN.Observation(live_published=True, content_matches=False)
UNPUBLISHED_AVAILABLE = PLAN.Observation(live_published=False, artifact_available=True)
UNPUBLISHED_EXPIRED = PLAN.Observation(live_published=False, artifact_available=False)
UNOBSERVABLE = PLAN.Observation(live_published=False, registry_observable=False, reason="HTTP 429")


class ClassifyTests(unittest.TestCase):
    """Covers the clean, partial-success, conflicting-version, and
    expired-artifact classes for one artifact considered on its own -- the
    npm dependency package and PyPI distribution shape."""

    def test_clean_state_is_skipped(self) -> None:
        decision = PLAN.classify(PUBLISHED_MATCHING)
        self.assertEqual(decision.action, "skip")

    def test_missing_but_available_is_eligible_to_publish(self) -> None:
        decision = PLAN.classify(UNPUBLISHED_AVAILABLE)
        self.assertEqual(decision.action, "publish")

    def test_conflicting_version_is_blocked(self) -> None:
        decision = PLAN.classify(PUBLISHED_CONFLICTING)
        self.assertEqual(decision.action, "block")
        self.assertIn("conflicting version", decision.reason)

    def test_expired_artifact_is_blocked(self) -> None:
        decision = PLAN.classify(UNPUBLISHED_EXPIRED)
        self.assertEqual(decision.action, "block")
        self.assertIn("expired", decision.reason)

    def test_unobservable_registry_state_is_blocked(self) -> None:
        decision = PLAN.classify(UNOBSERVABLE)
        self.assertEqual(decision.action, "block")
        self.assertIn("could not be established", decision.reason)
        self.assertIn("HTTP 429", decision.reason)


class PlanIndependentTests(unittest.TestCase):
    """The npm-dependency/PyPI shape: every artifact decided on its own, so a
    partial-success state publishes only the missing ones."""

    def test_a_fully_clean_manifest_publishes_nothing(self) -> None:
        plan = PLAN.plan_independent(
            {"npm:@redact-secret/wasm": PUBLISHED_MATCHING, "pypi:redact-secret": PUBLISHED_MATCHING}
        )
        self.assertEqual({name: decision.action for name, decision in plan.items()}, {
            "npm:@redact-secret/wasm": "skip",
            "pypi:redact-secret": "skip",
        })

    def test_partial_success_publishes_only_the_missing_artifact(self) -> None:
        plan = PLAN.plan_independent(
            {
                "npm:@redact-secret/node-darwin-arm64": PUBLISHED_MATCHING,
                "npm:@redact-secret/wasm": UNPUBLISHED_AVAILABLE,
            }
        )
        self.assertEqual(plan["npm:@redact-secret/node-darwin-arm64"].action, "skip")
        self.assertEqual(plan["npm:@redact-secret/wasm"].action, "publish")

    def test_pypi_partial_success_publishes_the_missing_distribution(self) -> None:
        plan = PLAN.plan_independent({"pypi:redact-secret": UNPUBLISHED_AVAILABLE})
        self.assertEqual(plan["pypi:redact-secret"].action, "publish")

    def test_pypi_expired_artifact_is_blocked(self) -> None:
        plan = PLAN.plan_independent({"pypi:redact-secret": UNPUBLISHED_EXPIRED})
        self.assertEqual(plan["pypi:redact-secret"].action, "block")

    def test_unknown_pypi_state_blocks_publication(self) -> None:
        plan = PLAN.plan_independent({"pypi:redact-secret": UNOBSERVABLE})
        self.assertEqual(plan["pypi:redact-secret"].action, "block")


class PlanCratePairTests(unittest.TestCase):
    """The core-crate-success/CLI-crate-failure shape and its "wrong-source"
    counterpart, where the existing core publication cannot verify against
    this source revision."""

    def test_core_success_cli_failure_publishes_only_the_missing_cli_crate(self) -> None:
        plan = PLAN.plan_crate_pair(core=PUBLISHED_MATCHING, cli=UNPUBLISHED_AVAILABLE)
        self.assertEqual(plan["core"].action, "skip")
        self.assertEqual(plan["cli"].action, "publish")

    def test_both_missing_and_available_publishes_both(self) -> None:
        plan = PLAN.plan_crate_pair(core=UNPUBLISHED_AVAILABLE, cli=UNPUBLISHED_AVAILABLE)
        self.assertEqual(plan["core"].action, "publish")
        self.assertEqual(plan["cli"].action, "publish")

    def test_clean_crate_pair_publishes_neither(self) -> None:
        plan = PLAN.plan_crate_pair(core=PUBLISHED_MATCHING, cli=PUBLISHED_MATCHING)
        self.assertEqual(plan["core"].action, "skip")
        self.assertEqual(plan["cli"].action, "skip")

    def test_wrong_source_core_blocks_the_cli_crate_too(self) -> None:
        # The core crate is published but its content does not verify against
        # this source revision; the CLI crate must not be published even
        # though its own state (missing, available) would otherwise qualify.
        plan = PLAN.plan_crate_pair(core=PUBLISHED_CONFLICTING, cli=UNPUBLISHED_AVAILABLE)
        self.assertEqual(plan["core"].action, "block")
        self.assertEqual(plan["cli"].action, "block")
        self.assertIn("does not verify against this source revision", plan["cli"].reason)

    def test_expired_core_artifact_blocks_the_cli_crate_too(self) -> None:
        plan = PLAN.plan_crate_pair(core=UNPUBLISHED_EXPIRED, cli=UNPUBLISHED_AVAILABLE)
        self.assertEqual(plan["core"].action, "block")
        self.assertEqual(plan["cli"].action, "block")

    def test_unobservable_core_artifact_blocks_the_cli_crate_too(self) -> None:
        plan = PLAN.plan_crate_pair(core=UNOBSERVABLE, cli=UNPUBLISHED_AVAILABLE)
        self.assertEqual(plan["core"].action, "block")
        self.assertEqual(plan["cli"].action, "block")


class CliTests(unittest.TestCase):
    def _write(self, payload: dict) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "observations.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_cli_reports_ok_and_exits_zero_when_clean(self) -> None:
        path = self._write({"pypi:redact-secret": {"live_published": True, "content_matches": True}})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = PLAN.main(["--observations", str(path)])
        self.assertEqual(status, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["pypi:redact-secret"]["action"], "skip")

    def test_cli_exits_nonzero_when_any_artifact_is_blocked(self) -> None:
        path = self._write(
            {"pypi:redact-secret": {"live_published": True, "content_matches": False}}
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = PLAN.main(["--observations", str(path)])
        self.assertEqual(status, 1)

    def test_cli_applies_the_crate_pair_rule(self) -> None:
        path = self._write(
            {
                "crate:redact-secret": {"live_published": True, "content_matches": False},
                "crate:redact-secret-cli": {"live_published": False, "artifact_available": True},
            }
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = PLAN.main(
                ["--observations", str(path), "--crate-pair", "crate:redact-secret", "crate:redact-secret-cli"]
            )
        self.assertEqual(status, 1)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["crate:redact-secret-cli"]["action"], "block")

    def test_cli_blocks_unobservable_registry_state(self) -> None:
        path = self._write(
            {
                "crate:redact-secret": {
                    "live_published": False,
                    "registry_observable": False,
                    "reason": "crates.io returned HTTP 500",
                }
            }
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = PLAN.main(["--observations", str(path)])
        self.assertEqual(status, 1)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["crate:redact-secret"]["action"], "block")
        self.assertIn("HTTP 500", payload["crate:redact-secret"]["reason"])


if __name__ == "__main__":
    unittest.main()
