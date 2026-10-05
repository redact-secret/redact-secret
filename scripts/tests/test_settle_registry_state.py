from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "settle-registry-state.py"
SPEC = importlib.util.spec_from_file_location("settle_registry_state", SCRIPT)
assert SPEC and SPEC.loader
SETTLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SETTLE
SPEC.loader.exec_module(SETTLE)

Observation = SETTLE.Observation
SHASUM = "c" * 40
SHA256 = "d" * 64


class FakeWorld:
    """A deterministic clock and registry: nothing sleeps and nothing touches the network."""

    def __init__(self, visible_after: dict[str, float] | None = None) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.reads: list[str] = []
        self.visible_after = visible_after or {}

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def observe(self, identity: str, version: str) -> "Observation":
        self.reads.append(identity)
        if identity not in self.visible_after or self.now < self.visible_after[identity]:
            return Observation("unpublished")
        if identity.startswith("pypi:"):
            return Observation("published", file_digests={"a.whl": SHA256, "a.tar.gz": SHA256[::-1]})
        return Observation("published", SHASUM)

    def settle(self, states: dict, digests: dict, registries: set[str], timeout: float = 100, interval: float = 10):
        return SETTLE.settle(
            states,
            digests,
            version="0.1.0-beta.1",
            registries=registries,
            observe=self.observe,
            sleep=self.sleep,
            clock=self.clock,
            timeout_seconds=timeout,
            interval_seconds=interval,
        )


def npm_record(published: str | None = None) -> list[dict]:
    return [
        {
            "file": "x.node",
            "built": "a" * 64,
            "qualified": "a" * 64,
            "published": published,
            "comparable": False,
            "note": "n",
        }
    ]


class SettleTests(unittest.TestCase):
    def test_lagging_npm_package_is_recorded_published_with_its_digest(self) -> None:
        world = FakeWorld({"npm:@redact-secret/node-darwin-x64": 30})
        states, digests, log = world.settle(
            {"npm:@redact-secret/node-darwin-x64": "unpublished"},
            {"npm:@redact-secret/node-darwin-x64": npm_record()},
            {"npm"},
        )
        self.assertEqual(states, {"npm:@redact-secret/node-darwin-x64": "published"})
        self.assertEqual(digests["npm:@redact-secret/node-darwin-x64"][0]["published"], SHASUM)
        self.assertEqual(world.sleeps, [10, 10, 10])
        self.assertTrue(any("settled as published" in line for line in log))

    def test_lagging_pypi_files_get_their_own_digests(self) -> None:
        world = FakeWorld({"pypi:redact-secret": 10})
        records = [
            {
                "file": "a.whl",
                "built": SHA256,
                "qualified": SHA256,
                "published": None,
                "comparable": True,
                "note": None,
            },
            {
                "file": "a.tar.gz",
                "built": SHA256[::-1],
                "qualified": SHA256[::-1],
                "published": None,
                "comparable": True,
                "note": None,
            },
        ]
        states, digests, _ = world.settle(
            {"pypi:redact-secret": "published"}, {"pypi:redact-secret": records}, {"pypi"}
        )
        self.assertEqual([r["published"] for r in digests["pypi:redact-secret"]], [SHA256, SHA256[::-1]])
        self.assertEqual(states["pypi:redact-secret"], "published")

    def test_genuinely_unpublished_version_is_still_recorded_unpublished_after_the_bound(self) -> None:
        world = FakeWorld()
        states, digests, log = world.settle(
            {"npm:@redact-secret/core": "unpublished"}, {"npm:@redact-secret/core": npm_record()}, {"npm"}, timeout=50
        )
        self.assertEqual(states["npm:@redact-secret/core"], "unpublished")
        self.assertIsNone(digests["npm:@redact-secret/core"][0]["published"])
        self.assertLessEqual(world.now, 60)
        self.assertEqual(len(world.sleeps), 5)
        self.assertTrue(any("still unsettled" in line for line in log))

    def test_state_is_never_promoted_without_a_digest(self) -> None:
        ticks = iter(range(0, 1000, 100))
        states, _, _ = SETTLE.settle(
            {"npm:a": "unpublished"},
            {},
            version="1",
            registries={"npm"},
            observe=lambda *_: Observation("published"),
            sleep=lambda _: None,
            clock=lambda: next(ticks),
            timeout_seconds=150,
        )
        self.assertEqual(states["npm:a"], "unpublished")

    def test_settled_artifacts_cost_no_registry_read(self) -> None:
        world = FakeWorld({"npm:a": 0})
        world.settle({"npm:a": "published"}, {"npm:a": npm_record("e" * 40)}, {"npm"})
        self.assertEqual(world.reads, [])
        self.assertEqual(world.sleeps, [])

    def test_unselected_registries_are_not_observed_or_waited_on(self) -> None:
        world = FakeWorld({"crate:redact-secret": 0})
        states, _, _ = world.settle({"crate:redact-secret": "unpublished"}, {}, {"npm", "pypi"})
        self.assertEqual(world.reads, [])
        self.assertEqual(states["crate:redact-secret"], "unpublished")

    def test_recorded_published_state_and_digest_are_never_downgraded_or_overwritten(self) -> None:
        world = FakeWorld()  # the registry now reads unpublished for everything
        states, digests, _ = world.settle(
            {"npm:a": "published", "npm:b": "published"},
            {"npm:a": npm_record("e" * 40), "npm:b": npm_record()},
            {"npm"},
            timeout=20,
        )
        self.assertEqual(states, {"npm:a": "published", "npm:b": "published"})
        self.assertEqual(digests["npm:a"][0]["published"], "e" * 40)
        self.assertIsNone(digests["npm:b"][0]["published"])

        world = FakeWorld({"npm:a": 0})
        _, digests, _ = world.settle({"npm:a": "published"}, {"npm:a": npm_record("e" * 40) + npm_record()}, {"npm"})
        self.assertEqual([r["published"] for r in digests["npm:a"]], ["e" * 40, SHASUM])

    def test_a_failing_registry_read_is_one_more_miss_not_a_crash(self) -> None:
        calls: list[str] = []

        def flaky(identity: str, version: str) -> "Observation":
            calls.append(identity)
            if len(calls) == 1:
                raise OSError("boom")
            return Observation("published", SHASUM)

        ticks = iter(range(0, 1000, 5))
        states, digests, log = SETTLE.settle(
            {"npm:a": "unknown"},
            {"npm:a": npm_record()},
            version="1",
            registries={"npm"},
            observe=flaky,
            sleep=lambda _: None,
            clock=lambda: next(ticks),
            timeout_seconds=100,
        )
        self.assertEqual(states["npm:a"], "published")
        self.assertEqual(digests["npm:a"][0]["published"], SHASUM)
        self.assertTrue(any("registry read failed" in line for line in log))

    def test_inputs_are_not_mutated(self) -> None:
        world = FakeWorld({"npm:a": 0})
        states, digests = {"npm:a": "unpublished"}, {"npm:a": npm_record()}
        world.settle(states, digests, {"npm"})
        self.assertEqual(states, {"npm:a": "unpublished"})
        self.assertIsNone(digests["npm:a"][0]["published"])


class ObserveRegistryTests(unittest.TestCase):
    def _observe(self, identity: str, status: int, body: object) -> "Observation":
        original = SETTLE._get_json
        SETTLE._get_json = lambda url: (status, body)
        try:
            return SETTLE.observe_registry(identity, "0.1.0-beta.1")
        finally:
            SETTLE._get_json = original

    def test_npm(self) -> None:
        body = {"name": "@redact-secret/core", "version": "0.1.0-beta.1", "dist": {"shasum": SHASUM}}
        self.assertEqual(self._observe("npm:@redact-secret/core", 200, body), Observation("published", SHASUM))
        self.assertEqual(self._observe("npm:@redact-secret/core", 404, None).state, "unpublished")
        self.assertEqual(self._observe("npm:@redact-secret/core", 500, None).state, "unknown")
        self.assertEqual(self._observe("npm:@redact-secret/core", 200, dict(body, name="other")).state, "unknown")
        self.assertEqual(self._observe("npm:@redact-secret/core", 200, {"dist": {"shasum": "zz"}}).state, "unknown")

    def test_pypi(self) -> None:
        body = {"urls": [{"filename": "a.whl", "digests": {"sha256": SHA256}}, {"filename": "bad"}]}
        self.assertEqual(self._observe("pypi:redact-secret", 200, body).file_digests, {"a.whl": SHA256})
        self.assertEqual(self._observe("pypi:redact-secret", 404, None).state, "unpublished")
        self.assertFalse(self._observe("pypi:redact-secret", 200, {"urls": []}).has_digest)

    def test_crate(self) -> None:
        self.assertEqual(
            self._observe("crate:redact-secret", 200, {"version": {"checksum": SHA256}}),
            Observation("published", SHA256),
        )
        self.assertEqual(self._observe("crate:redact-secret", 404, None).state, "unpublished")
        self.assertEqual(self._observe("crate:redact-secret", 200, {}).state, "unknown")


class CliTests(unittest.TestCase):
    def test_unreadable_input_leaves_files_alone_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            states = directory / "s.json"
            states.write_text("not json")
            digests = directory / "d.json"
            digests.write_text("{}")
            code = SETTLE.main(
                ["--states-file", str(states), "--digests-file", str(digests), "--version", "1", "--settle", "npm"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(states.read_text(), "not json")

    def test_nothing_to_settle_makes_no_registry_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            states = directory / "s.json"
            states.write_text(json.dumps({"npm:a": "published"}))
            digests = directory / "d.json"
            digests.write_text(json.dumps({"npm:a": npm_record("e" * 40)}))
            original = SETTLE.observe_registry
            SETTLE.observe_registry = lambda *_: self.fail("unexpected registry read")
            try:
                code = SETTLE.main(
                    ["--states-file", str(states), "--digests-file", str(digests), "--version", "1", "--settle", "npm"]
                )
            finally:
                SETTLE.observe_registry = original
            self.assertEqual(code, 0)


class WorkflowWiringTests(unittest.TestCase):
    def _manifest_step(self) -> str:
        workflow = (SCRIPT.parents[1] / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Build and record the manifest\n", 1)[1]
        return step.split("      - name:", 1)[0]

    def test_manifest_step_settles_only_registries_whose_publishers_succeeded(self) -> None:
        step = self._manifest_step()
        self.assertIn("scripts/settle-registry-state.py", step)
        for env in ("NPM_PUBLISH_RESULTS", "CRATES_PUBLISH_RESULT", "PYPI_PUBLISH_RESULT"):
            self.assertRegex(step, rf"{env}: \$\{{\{{ needs\.")
        self.assertIn('[[ "$NPM_PUBLISH_RESULTS" == "success success success" ]]', step)

    def test_registry_states_are_read_back_after_settling(self) -> None:
        step = self._manifest_step()
        settle_at = step.index("python3 -B scripts/settle-registry-state.py")
        self.assertGreater(step.index("registry_args+=("), settle_at)
        self.assertGreater(step.index("release-manifest.py \\"), settle_at)
        self.assertIsNone(re.search(r"\$\{\{[^}]*settle", step))


if __name__ == "__main__":
    unittest.main()
