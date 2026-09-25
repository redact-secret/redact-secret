#!/usr/bin/env python3
"""Catch cross-repository pin drift between this repository and
redact-secret-benchmarks (issue #427; manifest provenance added by #637).

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
redact-secret-benchmarks#15 and benchmarks/README.md for what each vendored
file is and how it is re-pinned). Three checks are pure JSON reconciliation
and need neither git history nor network access -- they run in `npm run ci`
on every push:

1. Every ledger record's `corpusHashes` entries exist in the manifest's
   corpus hash set, for records whose `benchmarkRevalidation` gate has not
   passed. A pending record still has to be measured against the currently
   pinned corpus, so pointing at corpus content that revision no longer
   recognizes is a dangling reference: re-pin the record's hash (and rerun)
   when the benchmarks corpus regenerates. Once the gate has passed, the
   hashes are the frozen identity of the corpus that was actually measured,
   and the record is anchored by its `benchmarkCommit` (check 3) instead --
   a corpus digest changes on every upstream corpus edit by design, so
   re-checking closed records against the current digest would fail every
   closed record forever after the first regeneration (#637).
2. Every ledger record's `benchmarkFixtureIds` entries exist in the
   manifest's fixture id list -- the same dangling-reference shape, for
   fixture identities instead of corpus hashes. Fixture ids are stable
   identities rather than content digests, so this applies to every record.
7. `pins.redactSecretVersion` is not older than this repository's own
   product version (package.json `version`). Reported as a non-blocking
   warning, not an error: an `rc/{version}` branch bumps package.json before
   publication, and redact-secret-benchmarks re-pins only after the version
   is published, so blocking here would turn every release candidate red.
   The blocking form of this rule is check 6 -- byte identity with the
   benchmarks copy carries whatever version that repository last pinned.

Four further checks resolve commit ancestry across full git history and
(for three of them) the GitHub API, so they run only with --check-ancestry,
from a dedicated CI job with a full checkout and GITHUB_TOKEN -- never
inside the fast, network-free `npm run ci` path (see the
`benchmark-pin-drift` job in .github/workflows/ci.yml):

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
5. `benchmarks/support-matrix-schema.json` -- the other file this repository
   vendors from redact-secret-benchmarks, read by
   `check-support-matrix-drift.py` and `generate-support-matrix-docs.py` --
   must stay byte-identical to `schemas/support-matrix-v1.json` at
   BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF. The immutable ref is the accepted
   evidence contract this repository consumes; it is independent of both the
   detector-registry snapshot and the benchmarks site's promotion cadence.
   Unlike checks 1-4, this is a copy of a whole file rather than a set of
   ids, so it can only be verified by fetching that file's content live --
   it runs alongside checks 3 and 4, not in the offline path.
   (`benchmarks/support-matrix-drift-schema.json` was a third vendored
   file; issue #605 (DS10) removed it instead of adding a check, since
   nothing in this repository ever read it.)
6. `benchmarks/pin-manifest.json` itself (#637). Until this check existed,
   checks 1-5 never compared the vendored manifest with the benchmarks
   repository at all, so `benchmark-pins:check` stayed green while the copy
   was three pre-releases stale and named a revision (`f1d4fac`) at which
   the manifest did not even exist yet. Three facts are now required:
   (a) the manifest's recorded `revision` is an ancestor of
   redact-secret-benchmarks' main; (b) that revision contains
   `benchmarks/pin-manifest.json`, i.e. the generator existed there; and
   (c) the vendored content is byte-identical to the benchmarks copy on
   BENCHMARKS_BRANCH, the same rule as check 5. The content is compared
   against the branch head rather than against the file at `revision`
   because `generate-pin-manifest.mjs` records `git rev-parse HEAD` at
   generation time and the result is committed afterwards: the copy stored
   *at* `revision` is always the previous generation, so "the file at
   `revision`" can never equal the file that names it. Byte identity with
   the branch head is the stricter and only well-defined form. It also
   means a benchmarks corpus regeneration turns this job red until someone
   runs `npm run benchmark-pins:sync` here; that is the intended cadence --
   an unbounded lag is exactly what #637 found.

Like `reconcile-guard.py`'s `is_ancestor` and the counterpart
redact-secret-benchmarks#15 check (`benchmarks/lib/pin-drift.ts`), the
checking functions below take pre-computed facts from their caller, so they
stay dependency-free and unit-testable on their own; only `main()` resolves
those facts -- via local `git merge-base --is-ancestor` for check 4 (same
repository, no network needed) and the GitHub compare and contents APIs for
checks 3, 5, and 6 (the other repository, where only a live query can
answer).

`--sync` rewrites both vendored files from their declared upstream refs before
running the offline checks, so re-pinning is one command
(`npm run benchmark-pins:sync`) rather than a hand-copy.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_PATH = Path("benchmarks") / "pin-manifest.json"
LEDGER_PATH = Path("conformance") / "benchmark-regressions.json"
SUPPORT_MATRIX_SCHEMA_PATH = Path("benchmarks") / "support-matrix-schema.json"
PRODUCT_MANIFEST_PATH = Path("package.json")
DETECTORS_PATH = "crates/secret-scan-core/src/detectors"
BENCHMARKS_REPO = "redact-secret/redact-secret-benchmarks"
BENCHMARKS_BRANCH = "main"
# Where each vendored copy lives in redact-secret-benchmarks itself. The
# manifest keeps its path; redact-secret-benchmarks#133 moved the schema out
# of that repository's own `benchmarks/`.
BENCHMARKS_MANIFEST_PATH = "benchmarks/pin-manifest.json"
BENCHMARKS_SUPPORT_MATRIX_SCHEMA_PATH = "schemas/support-matrix-v1.json"
# The beta.8 support-evidence contract, pinned to an immutable benchmarks
# commit: the `main` merge (redact-secret-benchmarks#273) that the vendored
# benchmarks/support-matrix.json was generated at, so the schema and the matrix
# it validates carry the same fields (corroboration counts, profileCoverage).
# The benchmarks manifest continues to track the living `main` copy
# independently.
BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF = "25e31c8319c441097f98db4e00b560395676f4a4"
# (local vendored path, upstream path, upstream ref) for every file `--sync`
# rewrites and checks 5 and 6 compare byte-for-byte.
VENDORED_FILES: tuple[tuple[Path, str, str], ...] = (
    (MANIFEST_PATH, BENCHMARKS_MANIFEST_PATH, BENCHMARKS_BRANCH),
    (
        SUPPORT_MATRIX_SCHEMA_PATH,
        BENCHMARKS_SUPPORT_MATRIX_SCHEMA_PATH,
        BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF,
    ),
)
PRODUCT_BRANCH = "main"
# actions/checkout (fetch-depth: 0, pull_request trigger) fetches every
# branch into refs/remotes/origin/* and checks out a detached PR merge ref --
# it never creates a local `main` branch, so local git ancestry lookups must
# target `origin/main`. PRODUCT_BRANCH stays the human-readable name used in
# messages; PRODUCT_LOCAL_REF is the ref that actually resolves in that
# checkout (and in an ordinary local clone, where both names resolve).
PRODUCT_LOCAL_REF = "origin/main"

SEMVER = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def benchmark_revalidation_passed(record: dict) -> bool:
    return record.get("gates", {}).get("benchmarkRevalidation", {}).get("status") == "passed"


def check_reconciliation(manifest: dict, ledger: dict) -> list[str]:
    """Checks 1 and 2: dangling corpus-hash and fixture-id references.

    Pure JSON set-membership -- no git, no network. Check 1 skips records
    whose benchmarkRevalidation gate has passed (see the module docstring).
    """
    errors: list[str] = []
    revision = manifest.get("revision", "<unknown>")
    corpus_hash_values = set(manifest.get("corpusHashes", {}).values())
    fixture_ids = set(manifest.get("fixtureIds", []))
    for record in ledger.get("records", []):
        record_id = record.get("id", "unknown")
        if not benchmark_revalidation_passed(record):
            for corpus_hash in record.get("corpusHashes", []):
                if corpus_hash not in corpus_hash_values:
                    errors.append(
                        f"{record_id}: corpusHashes entry {corpus_hash} is not in the corpus hash set "
                        f"at the pinned benchmark revision {revision}; the record's benchmarkRevalidation "
                        "gate is still open, so re-pin it to the corpus it will be measured against"
                    )
        for fixture_id in record.get("benchmarkFixtureIds", []):
            if fixture_id not in fixture_ids:
                errors.append(
                    f"{record_id}: benchmarkFixtureIds entry {fixture_id!r} does not exist at the "
                    f"pinned benchmark revision {revision}"
                )
    return errors


def parse_semver(version: str) -> tuple[tuple[int, int, int], tuple[tuple[int, int | str], ...] | None]:
    """A sortable key for a semver 2.0.0 string, or raise ValueError.

    Pre-release identifiers compare per the spec: numeric before
    alphanumeric, numeric ones numerically, and a shorter list that is a
    prefix of a longer one sorts first. A version without a pre-release
    sorts after every pre-release of the same core, which the key expresses
    as `None` handled by `compare_semver`.
    """
    match = SEMVER.match(version)
    if match is None:
        raise ValueError(f"not a semver version: {version!r}")
    core = (int(match["major"]), int(match["minor"]), int(match["patch"]))
    if match["pre"] is None:
        return core, None
    identifiers: list[tuple[int, int | str]] = []
    for identifier in match["pre"].split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier)))
        else:
            identifiers.append((1, identifier))
    return core, tuple(identifiers)


def compare_semver(left: str, right: str) -> int:
    """-1, 0, or 1 as `left` sorts before, equal to, or after `right`."""
    left_core, left_pre = parse_semver(left)
    right_core, right_pre = parse_semver(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    if left_pre == right_pre:
        return 0
    if left_pre is None:
        return 1
    if right_pre is None:
        return -1
    return -1 if left_pre < right_pre else 1


def check_pinned_version(manifest: dict, product_version: str) -> list[str]:
    """Check 7: the pinned redactSecretVersion must not be older than this
    repository's product version. Warnings, not errors (module docstring)."""
    pinned = manifest.get("pins", {}).get("redactSecretVersion")
    if not isinstance(pinned, str):
        return [f"{MANIFEST_PATH} has no pins.redactSecretVersion to compare with {PRODUCT_MANIFEST_PATH}"]
    try:
        older = compare_semver(pinned, product_version) < 0
    except ValueError as error:
        return [f"cannot compare pins.redactSecretVersion with {PRODUCT_MANIFEST_PATH} version: {error}"]
    if older:
        return [
            f"pins.redactSecretVersion ({pinned}) is older than this repository's product version "
            f"({product_version} in {PRODUCT_MANIFEST_PATH}); once {BENCHMARKS_REPO} has pinned the "
            "published release, run `npm run benchmark-pins:sync`"
        ]
    return []


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


def gh_fetch_file(repo_slug: str, ref: str, path: str) -> str:
    """The text content of `path` in `repo_slug` at `ref`, via the GitHub contents API."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo_slug}/contents/{path}?ref={ref}", "--jq", ".content"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return base64.b64decode(result.stdout.strip()).decode("utf-8")


def gh_path_exists(repo_slug: str, ref: str, path: str) -> bool:
    """True when `path` exists in `repo_slug` at `ref`; False on the API's 404.

    Any other failure (auth, rate limit, network) propagates: absence must be
    proven, not inferred from an unrelated error.
    """
    result = subprocess.run(
        ["gh", "api", f"repos/{repo_slug}/contents/{path}?ref={ref}", "--jq", ".sha"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode == 0:
        return True
    if "HTTP 404" in result.stderr:
        return False
    raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)


def check_vendored_file_drift(
    local_path: Path, local_content: str, live_content: str, *, live_source: str
) -> list[str]:
    """A vendored copy must be byte-identical to its upstream file (checks 5 and 6c)."""
    if local_content != live_content:
        return [
            f"{local_path} has drifted from {live_source}; "
            "run `npm run benchmark-pins:sync` to regenerate the vendored copy from that file"
        ]
    return []


def check_schema_drift(local_content: str, live_content: str, *, live_source: str) -> list[str]:
    """Check 5: the vendored support-matrix schema must be byte-identical to
    redact-secret-benchmarks' own current copy."""
    return check_vendored_file_drift(
        SUPPORT_MATRIX_SCHEMA_PATH, local_content, live_content, live_source=live_source
    )


def check_manifest_provenance(
    manifest: dict,
    *,
    revision_is_ancestor: bool,
    revision_has_manifest: bool,
    local_content: str,
    live_content: str,
    live_source: str,
) -> list[str]:
    """Check 6: the vendored manifest names a real benchmarks revision that
    already carried the manifest, and matches the benchmarks copy byte for
    byte. Facts are supplied by the caller (see the module docstring);
    `revision_has_manifest` is only meaningful -- and only reported -- when
    the revision is an ancestor, since a commit outside that history has no
    tree to look in."""
    errors: list[str] = []
    revision = manifest.get("revision", "<unknown>")
    if not revision_is_ancestor:
        errors.append(
            f"{MANIFEST_PATH} revision ({revision}) is not a recorded ancestor of "
            f"{BENCHMARKS_REPO}@{BENCHMARKS_BRANCH}"
        )
    elif not revision_has_manifest:
        errors.append(
            f"{MANIFEST_PATH} revision ({revision}) does not contain {BENCHMARKS_MANIFEST_PATH} in "
            f"{BENCHMARKS_REPO}; the vendored copy names a revision its generator never ran at"
        )
    errors += check_vendored_file_drift(MANIFEST_PATH, local_content, live_content, live_source=live_source)
    return errors


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


def resolve_manifest_provenance_facts(root: Path, manifest: dict) -> dict:
    revision = manifest["revision"]
    is_ancestor = gh_compare_is_ancestor(BENCHMARKS_REPO, revision, BENCHMARKS_BRANCH)
    has_manifest = (
        gh_path_exists(BENCHMARKS_REPO, revision, BENCHMARKS_MANIFEST_PATH) if is_ancestor else False
    )
    return {
        "revision_is_ancestor": is_ancestor,
        "revision_has_manifest": has_manifest,
        "local_content": (root / MANIFEST_PATH).read_text(encoding="utf-8"),
        "live_content": gh_fetch_file(BENCHMARKS_REPO, BENCHMARKS_BRANCH, BENCHMARKS_MANIFEST_PATH),
        "live_source": f"{BENCHMARKS_REPO}@{BENCHMARKS_BRANCH}:{BENCHMARKS_MANIFEST_PATH}",
    }


def sync_vendored_files(
    root: Path, fetch: Callable[[str, str, str], str] = gh_fetch_file
) -> list[tuple[Path, str]]:
    """Rewrite every vendored copy from its declared upstream ref."""
    written: list[tuple[Path, str]] = []
    for local_path, upstream_path, upstream_ref in VENDORED_FILES:
        content = fetch(BENCHMARKS_REPO, upstream_ref, upstream_path)
        (root / local_path).write_text(content, encoding="utf-8")
        written.append((local_path, upstream_ref))
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument(
        "--check-ancestry",
        action="store_true",
        help=(
            "also run checks 3 to 6 (commit ancestry, vendored-schema drift, and manifest "
            f"provenance); needs full git history and `gh api` access to {BENCHMARKS_REPO}"
        ),
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help=(
            f"rewrite the vendored copies from their declared refs in {BENCHMARKS_REPO} before checking; "
            "needs `gh api` access"
        ),
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.sync:
        for path, upstream_ref in sync_vendored_files(root):
            print(f"SYNCED {path} from {BENCHMARKS_REPO}@{upstream_ref}")

    manifest = load_json(root / MANIFEST_PATH)
    ledger = load_json(root / LEDGER_PATH)
    product_version = load_json(root / PRODUCT_MANIFEST_PATH)["version"]

    errors = check_reconciliation(manifest, ledger)
    warnings = check_pinned_version(manifest, product_version)
    if args.check_ancestry:
        facts = resolve_ancestry_facts(root, manifest, ledger)
        findings = check_ancestry(manifest, ledger, **facts)
        errors += findings.errors
        warnings += findings.warnings

        live_source = (
            f"{BENCHMARKS_REPO}@{BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF}:"
            f"{BENCHMARKS_SUPPORT_MATRIX_SCHEMA_PATH}"
        )
        local_schema = (root / SUPPORT_MATRIX_SCHEMA_PATH).read_text(encoding="utf-8")
        live_schema = gh_fetch_file(
            BENCHMARKS_REPO,
            BENCHMARKS_SUPPORT_MATRIX_SCHEMA_REF,
            BENCHMARKS_SUPPORT_MATRIX_SCHEMA_PATH,
        )
        errors += check_schema_drift(local_schema, live_schema, live_source=live_source)

        errors += check_manifest_provenance(manifest, **resolve_manifest_provenance_facts(root, manifest))

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
