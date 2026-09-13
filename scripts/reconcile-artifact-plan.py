#!/usr/bin/env python3
"""Decide, per artifact, whether Reconcile Release may skip, publish, or must
block a registry's state for one release manifest's source revision.

`scripts/reconcile-guard.py` decides whether `source_revision` may be acted on
at all (ancestor-of-main, a manifest exists, and it records the requested
version). Once that gate passes, this module decides -- independently for
each artifact `release.yml`'s `record-manifest` step already tracks in
`registry_state` -- whether the currently observed registry state lets
reconcile complete a partial publication safely:

- an artifact already published with content matching this source revision is
  left alone (`skip`);
- an artifact not yet published, whose qualified build artifact is still
  available to publish, is eligible (`publish`);
- an artifact whose registry state could not be established is refused
  (`block`);
- an artifact already published with content that does NOT match this source
  revision is a conflicting version and reconcile refuses it (`block`);
- an artifact not yet published whose qualified build artifact has expired --
  a GitHub Actions artifact past its retention window, for example -- cannot
  be safely reconciled without rebuilding, so reconcile refuses it (`block`)
  rather than guess at a replacement.

`decision-release-bindings-in-lockstep` treats `redact-secret-cli` and
`redact-secret` as one product at one version, and `redact-secret-cli`'s
manifest depends on `redact-secret`'s registry release (`release.yml`
publishes core before CLI for the same reason). `plan_crate_pair` therefore refuses to
publish a missing CLI crate unless the core crate's own state first resolves
to `skip` or `publish`: an existing core publication that does not verify
against this source revision blocks the CLI crate too, even when the CLI
crate's own state would otherwise look publishable on its own.

This module only decides; it queries no registry, downloads no artifact, and
publishes nothing. `.github/workflows/reconcile-release.yml` gathers the
observed state (via `npm view`, the crates.io API, and the PyPI API) and
executes exactly the `publish` verdicts this module returns.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Observation:
    """What reconcile observed for one artifact at `source_revision`.

    `content_matches` is meaningless (and ignored) when `live_published` is
    False -- an unpublished artifact has no published content to compare.
    `artifact_available` is meaningless (and ignored) when `live_published`
    is True -- an already-published artifact needs nothing republished, so
    whether its build artifact expired does not matter.
    """

    live_published: bool
    content_matches: bool = False
    artifact_available: bool = True
    registry_observable: bool = True
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    action: str  # "skip", "publish", or "block"
    reason: str


def classify(observation: Observation) -> Decision:
    """The verdict for one artifact considered on its own."""
    if not observation.registry_observable:
        reason = observation.reason or "registry state could not be established"
        return Decision("block", f"registry state could not be established: {reason}")
    if observation.live_published:
        if observation.content_matches:
            return Decision("skip", "already published and matches this source revision")
        return Decision(
            "block",
            "already published with content that does not match this source revision "
            "(conflicting version)",
        )
    if observation.artifact_available:
        return Decision("publish", "not yet published; the qualified artifact is available")
    return Decision(
        "block",
        "not yet published, and the qualified build artifact has expired; "
        "a full release run is required",
    )


def plan_crate_pair(core: Observation, cli: Observation) -> dict[str, Decision]:
    """`redact-secret` (core) must verify against this source revision before
    `redact-secret-cli` may be published, even when the CLI crate's own state
    looks publishable -- the CLI crate's `Cargo.toml` depends on the core
    crate's registry release, so publishing it against an unverified or
    conflicting core would ship a CLI whose declared dependency is not
    actually the core this source revision qualified.
    """
    core_decision = classify(core)
    if core_decision.action == "block":
        return {
            "core": core_decision,
            "cli": Decision(
                "block",
                "redact-secret-cli cannot be reconciled: the existing redact-secret (core) "
                f"publication does not verify against this source revision ({core_decision.reason})",
            ),
        }
    return {"core": core_decision, "cli": classify(cli)}


def plan_independent(observations: dict[str, Observation]) -> dict[str, Decision]:
    """Each artifact decided on its own, with no cross-artifact dependency --
    the shape npm dependency packages and the PyPI distribution need."""
    return {name: classify(observation) for name, observation in observations.items()}


def _load_observation(payload: dict) -> Observation:
    return Observation(
        live_published=bool(payload.get("live_published", False)),
        content_matches=bool(payload.get("content_matches", False)),
        artifact_available=bool(payload.get("artifact_available", True)),
        registry_observable=bool(payload.get("registry_observable", True)),
        reason=str(payload.get("reason", "")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--observations",
        required=True,
        help="path to a JSON file: {name: {live_published, content_matches, artifact_available}}",
    )
    parser.add_argument(
        "--crate-pair",
        nargs=2,
        metavar=("CORE_NAME", "CLI_NAME"),
        default=None,
        help="treat these two observation names as the core/CLI crate pair",
    )
    args = parser.parse_args(argv)

    with open(args.observations, encoding="utf-8") as handle:
        raw = json.load(handle)
    observations = {name: _load_observation(payload) for name, payload in raw.items()}

    decisions: dict[str, Decision] = {}
    if args.crate_pair:
        core_name, cli_name = args.crate_pair
        pair = plan_crate_pair(observations.pop(core_name), observations.pop(cli_name))
        decisions[core_name] = pair["core"]
        decisions[cli_name] = pair["cli"]
    decisions.update(plan_independent(observations))

    payload = {name: asdict(decision) for name, decision in decisions.items()}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if any(decision.action == "block" for decision in decisions.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
