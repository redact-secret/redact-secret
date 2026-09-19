#!/usr/bin/env python3
"""Catch cross-repository pin drift between this repository and
redact-secret-benchmarks (issue #427).

Three pins connect the two repositories -- a detector registry snapshot's
source revision, the benchmark corpus it was measured against, and the
product commits it names as evidence -- and until this script existed,
nothing checked any of them. Detectors could be added or removed on either
side and CI would stay green.

`conformance/benchmark-regressions.json` is the provenance ledger for
benchmark-originated product regressions
(docs/decisions/2026-09-18-govern-benchmark-regression-promotion.md). This
script reconciles it against a small, committed copy of the benchmarks
repository's own pin manifest, `benchmarks/pin-manifest.json` (published by
that repository's `scripts/generate-pin-manifest.mjs`; see
redact-secret-benchmarks#15). Two checks are pure JSON reconciliation and
need neither git history nor network access -- they run in `npm run ci` on
every push:

1. Every ledger record's `corpusHashes` entries exist in the manifest's
   corpus hash set. A record pointing at corpus content the currently
   pinned benchmark revision no longer recognizes is a dangling reference.
2. Every ledger record's `benchmarkFixtureIds` entries exist in the
   manifest's fixture id list -- the same dangling-reference shape, for
   fixture identities instead of corpus hashes.

Two further checks resolve commit ancestry across full git history and (for
one of them) the GitHub API, so they run only with --check-ancestry, from a
dedicated CI job with a full checkout and GITHUB_TOKEN -- never inside the
fast, network-free `npm run ci` path (see the `benchmark-pin-drift` job in
.github/workflows/ci.yml):

3. Every ledger record's `benchmarkCommit` (added in #426) must be an
   ancestor of redact-secret-benchmarks' main. Evidence pointing at a
   commit that fell out of that repository's history is rejected, not
   silently accepted.
4. The manifest's `pins.sourceRevision` must be an ancestor of this
   repository's main -- a build-blocking error when it is not. Whether
   crates/secret-scan-core/src/detectors/ has changed after that revision is
   also reported, but only as a non-blocking warning for now: the product
   repository cannot itself refresh redact-secret-benchmarks' detector
   registry snapshot, so failing the build on it would leave every PR stuck
   red until an unrelated repository catches up. Tracked in #427 pending a
   cross-repo fix; promote it to a build-blocking error once
   redact-secret-benchmarks can be refreshed as part of the same change.

Like `reconcile-guard.py`'s `is_ancestor` and the counterpart
redact-secret-benchmarks#15 check (`benchmarks/lib/pin-drift.ts`), the
ancestry-checking function below takes pre-computed ancestry facts from its
caller, so it stays dependency-free and unit-testable on its own; only
`main()` resolves those facts -- via local `git merge-base --is-ancestor`
for check 4 (same repository, no network needed) and the GitHub compare API
for check 3 (the other repository, where only a live query can answer it).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_PATH = Path("benchmarks") / "pin-manifest.json"
LEDGER_PATH = Path("conformance") / "benchmark-regressions.json"
DETECTORS_PATH = "crates/secret-scan-core/src/detectors"
BENCHMARKS_REPO = "redact-secret/redact-secret-benchmarks"
BENCHMARKS_BRANCH = "main"
PRODUCT_BRANCH = "main"
# actions/checkout (fetch-depth: 0, pull_request trigger) fetches every
# branch into refs/remotes/origin/* and checks out a detached PR merge ref --
# it never creates a local `main` branch, so local git ancestry lookups must
# target `origin/main`. PRODUCT_BRANCH stays the human-readable name used in
# messages; PRODUCT_LOCAL_REF is the ref that actually resolves in that
# checkout (and in an ordinary local clone, where both names resolve).
PRODUCT_LOCAL_REF = "origin/main"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_reconciliation(manifest: dict, ledger: dict) -> list[str]:
    """Checks 1 and 2: dangling corpus-hash and fixture-id references.

    Pure JSON set-membership -- no git, no network.
    """
    errors: list[str] = []
    revision = manifest.get("revision", "<unknown>")
    corpus_hash_values = set(manifest.get("corpusHashes", {}).values())
    fixture_ids = set(manifest.get("fixtureIds", []))
    for record in ledger.get("records", []):
        record_id = record.get("id", "unknown")
        for corpus_hash in record.get("corpusHashes", []):
            if corpus_hash not in corpus_hash_values:
                errors.append(
                    f"{record_id}: corpusHashes entry {corpus_hash} is not in the corpus hash set "
                    f"at the pinned benchmark revision {revision}"
                )
        for fixture_id in record.get("benchmarkFixtureIds", []):
            if fixture_id not in fixture_ids:
                errors.append(
                    f"{record_id}: benchmarkFixtureIds entry {fixture_id!r} does not exist at the "
                    f"pinned benchmark revision {revision}"
                )
    return errors


def collect_benchmark_commits(ledger: dict) -> list[str]:
    """Every distinct benchmarkCommit named in the ledger, deduplicated and sorted."""
    commits = {
        record["benchmarkCommit"]
        for record in ledger.get("records", [])
        if record.get("benchmarkCommit")
    }
    return sorted(commits)


@dataclass
class AncestryFindings:
    """Check 3 and the source_revision half of check 4 are build-blocking.

    The detectors-changed half of check 4 is a known, currently unfixable
    gap (see the module docstring) and is reported separately as a
    non-blocking warning so it doesn't fail every PR.
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def check_ancestry(
    manifest: dict,
    ledger: dict,
    *,
    source_revision_is_ancestor: bool,
    detectors_changed_since_source_revision: bool,
    benchmark_commit_is_ancestor: dict[str, bool],
) -> AncestryFindings:
    """Checks 3 and 4. Network- and git-free: ancestry facts are supplied by the
    caller, matching redact-secret-benchmarks#15's checkPinAncestry."""
    findings = AncestryFindings()
    source_revision = manifest.get("pins", {}).get("sourceRevision", "<unknown>")
    if not source_revision_is_ancestor:
        findings.errors.append(
            f"pins.sourceRevision ({source_revision}) is not an ancestor of this repository's "
            f"{PRODUCT_BRANCH}"
        )
    if detectors_changed_since_source_revision:
        findings.warnings.append(
            f"{DETECTORS_PATH} changed after pins.sourceRevision ({source_revision}); the "
            f"{BENCHMARKS_REPO} detector registry snapshot needs to be refreshed (#427)"
        )
    for record in ledger.get("records", []):
        commit = record.get("benchmarkCommit")
        if commit is None:
            continue
        if benchmark_commit_is_ancestor.get(commit) is not True:
            findings.errors.append(
                f"{record.get('id', 'unknown')}: benchmarkCommit ({commit}) is not a recorded "
                f"ancestor of {BENCHMARKS_REPO}@{BENCHMARKS_BRANCH}"
            )
    return findings


def local_is_ancestor(repo: Path, commit: str, candidate_ref: str) -> bool:
    """True when `commit` is `candidate_ref` or one of its ancestors, in `repo`'s own history."""
    result = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, candidate_ref],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def local_path_changed_since(repo: Path, commit: str, candidate_ref: str, path: str) -> bool:
    """True when `path` has a commit strictly between `commit` (exclusive) and `candidate_ref`."""
    result = subprocess.run(
        ["git", "-C", str(repo), "log", "--oneline", f"{commit}..{candidate_ref}", "--", path],
        capture_output=True,
        text=True,
        check=True,
    )
    return bool(result.stdout.strip())


def gh_compare_is_ancestor(repo_slug: str, base: str, head: str) -> bool:
    """True when `base` is `head` or one of its ancestors, per the GitHub compare API."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo_slug}/compare/{base}...{head}", "--jq", ".status"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    status = result.stdout.strip()
    return status in ("identical", "ahead")


def resolve_ancestry_facts(root: Path, manifest: dict, ledger: dict) -> dict:
    source_revision = manifest["pins"]["sourceRevision"]
    source_is_ancestor = local_is_ancestor(root, source_revision, PRODUCT_LOCAL_REF)
    detectors_changed = (
        local_path_changed_since(root, source_revision, PRODUCT_LOCAL_REF, DETECTORS_PATH)
        if source_is_ancestor
        else False
    )
    commit_is_ancestor = {
        commit: gh_compare_is_ancestor(BENCHMARKS_REPO, commit, BENCHMARKS_BRANCH)
        for commit in collect_benchmark_commits(ledger)
    }
    return {
        "source_revision_is_ancestor": source_is_ancestor,
        "detectors_changed_since_source_revision": detectors_changed,
        "benchmark_commit_is_ancestor": commit_is_ancestor,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument(
        "--check-ancestry",
        action="store_true",
        help=(
            "also run checks 3 and 4 (commit ancestry); needs full git history and, for "
            f"check 3, `gh api` access to {BENCHMARKS_REPO}"
        ),
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    manifest = load_json(root / MANIFEST_PATH)
    ledger = load_json(root / LEDGER_PATH)

    errors = check_reconciliation(manifest, ledger)
    warnings: list[str] = []
    if args.check_ancestry:
        facts = resolve_ancestry_facts(root, manifest, ledger)
        findings = check_ancestry(manifest, ledger, **facts)
        errors += findings.errors
        warnings += findings.warnings

    for warning in warnings:
        print(f"WARNING {warning}")
    for error in errors:
        print(f"ERROR {error}")
    summary = f"Benchmark pin drift check complete: {len(errors)} error(s)"
    if warnings:
        summary += f", {len(warnings)} warning(s)"
    print(summary)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
