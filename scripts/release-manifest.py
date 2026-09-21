#!/usr/bin/env python3
"""Build the durable release manifest `release.yml` records for every run.

`decision-release-bindings-in-lockstep` and `ARCHITECTURE.md`'s "Versioning,
qualification, and release" section both require the release process to
record a manifest carrying the source commit, conformance revision, product
version, required artifacts, and the observed publication state of each
registry -- so a partial publication is visible and repairable instead of
assumed atomic. `.github/workflows/release.yml` calls this script as its last
step, with `if: always()`, so the manifest is emitted even when an earlier
step in the same run failed; the workflow then uploads the result as a
`release-manifest-<version>` artifact. `reconcile-release.yml` downloads that
artifact and hands it to `reconcile-guard.py`.

Issue #528 adds a sixth, optional field: `artifact_digests`. Issue #527
proved, for Python alone, that "qualified" and "published" have to be the
same bytes, not just the same workflow topology, and that the comparison has
to fail loudly and independently of the build graph. `artifact_digests`
generalizes the *recording* half of that to every artifact family (npm,
WASM, crate, Python): each artifact identity (the same strings
`artifact_set` already carries, e.g. `npm:@redact-secret/wasm`) maps to a
list of per-file records with `built`, `qualified`, and `published` digests,
a `comparable` flag, and a `note`. `built` and `qualified` are the same
measurement for every family here, because every artifact is still built
exactly once (issue #527's property, now general); `published` differs
because some ecosystems re-pack the qualified bytes before upload (`npm
publish` wraps a file in a new tarball) and a byte comparison against that
repack is not meaningful -- `comparable: false` with a non-empty `note`
records that explicitly instead of silently omitting the field. When
`comparable` is true (crates.io and PyPI both publish the exact digest of
the file they received), any two non-null stages that disagree are a defect
this script fails loudly on, naming the artifact, the file, and both
digests -- but the manifest is still written first, so `record-manifest`'s
`if: always()` still leaves a durable record of a run that failed this
check.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

FIELDS = (
    "source_revision",
    "conformance_identity",
    "version",
    "artifact_set",
    "registry_state",
)

DIGEST_STAGES = ("built", "qualified", "published")


def normalize_artifact_digests(raw: dict) -> tuple[dict, list[str]]:
    """Validate and sort `artifact_digests`, returning `(normalized, errors)`.

    `errors` lists every digest mismatch found (comparable stages that
    disagree) and every record missing a required `note`. The caller writes
    the manifest regardless of `errors` -- a mismatch is a fact about this
    run, not a reason to withhold the record of it.
    """
    normalized: dict[str, list[dict]] = {}
    errors: list[str] = []
    for identity in sorted(raw):
        records = raw[identity]
        if not isinstance(records, list):
            errors.append(f"{identity}: artifact_digests entry must be a list of records")
            continue
        normalized_records = []
        for record in records:
            file_name = str(record.get("file") or "unknown")
            comparable = bool(record.get("comparable", False))
            note = record.get("note")
            stages = {stage: record.get(stage) or None for stage in DIGEST_STAGES}
            if not comparable and not note:
                errors.append(
                    f"{identity} ({file_name}): comparable=false requires a note explaining why "
                    "a byte comparison across stages is not meaningful"
                )
            if comparable:
                present = {stage: value for stage, value in stages.items() if value}
                distinct = set(present.values())
                if len(distinct) > 1:
                    pairs = ", ".join(f"{stage}={value}" for stage, value in present.items())
                    errors.append(
                        f"{identity} ({file_name}): digest mismatch across stages -- {pairs}"
                    )
            normalized_records.append(
                {
                    "file": file_name,
                    **stages,
                    "comparable": comparable,
                    "note": note or None,
                }
            )
        normalized[identity] = normalized_records
    return normalized, errors


def build_manifest(
    *,
    source_revision: str,
    conformance_identity: str,
    version: str,
    artifact_set: list[str],
    registry_state: dict[str, str],
) -> dict:
    """Assemble the five-field release manifest.

    Raises ValueError when any field is empty, so a run that could not
    determine one of them fails loudly instead of recording a manifest that
    looks complete but is missing what reconcile would need.
    """
    manifest = {
        "source_revision": source_revision,
        "conformance_identity": conformance_identity,
        "version": version,
        "artifact_set": sorted(artifact_set),
        "registry_state": dict(sorted(registry_state.items())),
    }
    missing = [field for field in FIELDS if not manifest[field]]
    if missing:
        raise ValueError(f"release manifest is missing required field(s): {', '.join(missing)}")
    return manifest


def _parse_registry_state(pairs: list[str]) -> dict[str, str]:
    state: dict[str, str] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not name or not value:
            raise ValueError(f"--registry-state expects name=state, got {pair!r}")
        state[name] = value
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--conformance-identity", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--artifact",
        dest="artifacts",
        action="append",
        default=[],
        help="repeatable: an artifact this release qualifies, e.g. npm:@redact-secret/core",
    )
    parser.add_argument(
        "--registry-state",
        dest="registry_states",
        action="append",
        default=[],
        help="repeatable: registry=state, e.g. npm=published",
    )
    parser.add_argument(
        "--artifact-digests",
        default="{}",
        help=(
            "JSON object mapping an artifact identity (an artifact_set entry) to a list of "
            "{file, built, qualified, published, comparable, note} records (issue #528)"
        ),
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        manifest = build_manifest(
            source_revision=args.source_revision,
            conformance_identity=args.conformance_identity,
            version=args.version,
            artifact_set=args.artifacts,
            registry_state=_parse_registry_state(args.registry_states),
        )
    except ValueError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1

    try:
        raw_digests = json.loads(args.artifact_digests)
    except json.JSONDecodeError as error:
        print(f"ERROR --artifact-digests is not valid JSON: {error}", file=sys.stderr)
        return 1
    if not isinstance(raw_digests, dict):
        print("ERROR --artifact-digests must be a JSON object", file=sys.stderr)
        return 1
    artifact_digests, digest_errors = normalize_artifact_digests(raw_digests)
    manifest["artifact_digests"] = artifact_digests

    # Written before the digest errors are evaluated: `record-manifest` runs
    # `if: always()` specifically so a run that fails this new check still
    # leaves a durable record of what it observed, the same as any other
    # partial or failed release (issue #528 acceptance criterion 4).
    args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if digest_errors:
        for error in digest_errors:
            print(f"ERROR {error}", file=sys.stderr)
        print(
            f"Recorded release manifest for {manifest['version']} at {args.out} "
            f"({len(digest_errors)} artifact digest error(s))",
            file=sys.stderr,
        )
        return 1

    print(f"Recorded release manifest for {manifest['version']} at {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
