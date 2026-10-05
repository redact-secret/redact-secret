#!/usr/bin/env python3
"""Re-observe just-published versions before the release manifest records them.

Issue #1197: registries lag right after a publish. The per-job "Report ...
registry state" and "Record artifact digest evidence" steps read each registry
once, seconds after the publish, so beta.13's durable manifest recorded two
published npm packages as `unpublished` and left three PyPI files without a
published digest, although the same run's publish jobs succeeded and the live
registries carried every artifact. This script runs in `record-manifest`, after
every publish job, over the merged states and digests, and re-reads the
registry for exactly the artifacts that still look unsettled, for a bounded
time.

Rules (release tooling only; the core never touches a network):

- Only artifacts of a registry named with `--settle` are re-observed. The
  workflow names a registry only when every publisher job for it succeeded, so
  a genuinely failed publish is recorded after one single observation, not
  after the bound.
- An artifact is unsettled when its state is not `published` or when one of
  its digest records has no `published` digest. Settled artifacts cost no
  request.
- Observations only ever upgrade. `unpublished` or `unknown` becomes
  `published` only when the registry returned a digest for the artifact, so a
  state is never promoted without a digest. A `published` state is never
  downgraded and a recorded `published` digest is never overwritten.
- When the bound expires, whatever is still unsettled stays exactly as the
  publish jobs recorded it. This script never fails the run and never turns a
  missing version into a published one.

The clock, the sleep and the registry reader are injectable, so tests run
without sleeping or network access.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

USER_AGENT = "redact-secret-release (https://github.com/redact-secret/redact-secret)"
DEFAULT_TIMEOUT_SECONDS = 600.0
DEFAULT_INTERVAL_SECONDS = 15.0
REGISTRIES = ("npm", "crate", "pypi")


@dataclass(frozen=True)
class Observation:
    """What a registry returned for one artifact at one moment.

    `state` is `published`, `unpublished` or `unknown`. `digest` is the one
    digest that applies to every record of the artifact (npm tarball shasum,
    crate checksum); `file_digests` maps a file name to its digest (PyPI).
    """

    state: str
    digest: str | None = None
    file_digests: dict[str, str] = field(default_factory=dict)

    @property
    def has_digest(self) -> bool:
        return bool(self.digest or self.file_digests)


Observe = Callable[[str, str], Observation]


def _get_json(url: str) -> tuple[int, object]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https registry hosts
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


def observe_registry(identity: str, version: str) -> Observation:
    """Read the registry named by an artifact identity such as `npm:@scope/name`."""
    registry, _, name = identity.partition(":")
    if registry == "npm":
        status, body = _get_json(
            f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}"
            f"?release_check={int(time.time())}"
        )
        if status == 404:
            return Observation("unpublished")
        shasum = body.get("dist", {}).get("shasum") if isinstance(body, dict) else None
        valid = (
            status == 200
            and isinstance(body, dict)
            and body.get("name") == name
            and body.get("version") == version
            and isinstance(shasum, str)
            and len(shasum) == 40
            and all(c in "0123456789abcdef" for c in shasum)
        )
        return Observation("published", shasum) if valid else Observation("unknown")
    if registry == "pypi":
        status, body = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
        if status == 404:
            return Observation("unpublished")
        if status != 200 or not isinstance(body, dict):
            return Observation("unknown")
        files = {
            entry["filename"]: entry["digests"]["sha256"]
            for entry in body.get("urls", [])
            if isinstance(entry, dict) and entry.get("filename") and entry.get("digests", {}).get("sha256")
        }
        return Observation("published", file_digests=files)
    if registry == "crate":
        status, body = _get_json(
            f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}"
        )
        if status == 404:
            return Observation("unpublished")
        checksum = body.get("version", {}).get("checksum") if isinstance(body, dict) else None
        if status == 200 and isinstance(checksum, str) and checksum:
            return Observation("published", checksum)
        return Observation("unknown")
    return Observation("unknown")


def _unsettled(identity: str, states: dict, digests: dict) -> bool:
    if states.get(identity) != "published":
        return True
    records = digests.get(identity)
    return isinstance(records, list) and any(isinstance(r, dict) and not r.get("published") for r in records)


def _apply(identity: str, observation: Observation, states: dict, digests: dict) -> bool:
    """Upgrade `states`/`digests` from one observation; True when anything changed."""
    if observation.state != "published" or not observation.has_digest:
        return False
    changed = False
    if states.get(identity) != "published":
        states[identity] = "published"
        changed = True
    records = digests.get(identity)
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or record.get("published"):
                continue
            digest = observation.digest or observation.file_digests.get(str(record.get("file")))
            if digest:
                record["published"] = digest
                changed = True
    return changed


def settle(
    states: dict[str, str],
    digests: dict[str, list],
    *,
    version: str,
    registries: set[str],
    observe: Observe = observe_registry,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
) -> tuple[dict[str, str], dict[str, list], list[str]]:
    """Return `(states, digests, log)` after re-observing unsettled artifacts.

    The inputs are not mutated. Observations that raise are treated as one more
    miss. The wait ends as soon as nothing is unsettled or the bound expires.
    """
    states = dict(states)
    digests = json.loads(json.dumps(digests))
    log: list[str] = []
    deadline = clock() + timeout_seconds
    first = True
    while True:
        pending = sorted(
            identity
            for identity in states
            if identity.partition(":")[0] in registries and _unsettled(identity, states, digests)
        )
        if not pending:
            return states, digests, log
        if not first and clock() >= deadline:
            for identity in pending:
                log.append(
                    f"{identity}: still unsettled after {timeout_seconds:g}s; recorded as observed by its publisher job"
                )
            return states, digests, log
        for identity in pending:
            try:
                observation = observe(identity, version)
            except Exception as error:  # noqa: BLE001 - a transport error is one more miss, never a failure
                log.append(f"{identity}: registry read failed ({type(error).__name__})")
                continue
            if _apply(identity, observation, states, digests):
                log.append(f"{identity}: settled as {states[identity]} after re-observation")
        first = False
        if not any(
            identity.partition(":")[0] in registries and _unsettled(identity, states, digests) for identity in states
        ):
            return states, digests, log
        sleep(interval_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--states-file", required=True, type=Path, help="merged registry-state JSON object, rewritten in place"
    )
    parser.add_argument(
        "--digests-file", required=True, type=Path, help="merged artifact-digests JSON object, rewritten in place"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--settle", dest="registries", action="append", default=[], choices=REGISTRIES)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--interval-seconds", type=float, default=DEFAULT_INTERVAL_SECONDS)
    args = parser.parse_args(argv)

    try:
        states = json.loads(args.states_file.read_text(encoding="utf-8"))
        digests = json.loads(args.digests_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        # The manifest must still be written; leave both files untouched.
        print(f"WARN registry settling skipped: {error}", file=sys.stderr)
        return 0
    if not isinstance(states, dict) or not isinstance(digests, dict) or not args.registries:
        return 0

    states, digests, log = settle(
        states,
        digests,
        version=args.version,
        registries=set(args.registries),
        timeout_seconds=args.timeout_seconds,
        interval_seconds=args.interval_seconds,
    )
    args.states_file.write_text(json.dumps(states, sort_keys=True), encoding="utf-8")
    args.digests_file.write_text(json.dumps(digests, sort_keys=True), encoding="utf-8")
    for line in log:
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
