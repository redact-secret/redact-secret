"""The candidate-bound public-contract review identity of a release inventory.

`record-artifact-inventory.py` writes, and `validate-release-records.py`
reads, the review obligation a release candidate must meet before release
approval is requested (`docs/releasing.md`, "Review and approval"). This module
holds the one definition of that identity, so neither script hardcodes a path
under `docs/audits/`
(`decision-retire-historical-audit-bodies-before-release-qualification`).

Two jobs, both offline:

1. **Select and verify the review for the version under qualification.** The
   review is the one temporary unit under `docs/audits/` whose front matter
   binds it to that exact `candidate_version`. A review written for another
   version, however well it was done, is history: it can be cited, and it can
   never satisfy this candidate. The unit's front matter carries the lifecycle
   fields the decision fixes (`owner`, `reviewed_source`, `status`,
   `retire_on`) and the fields that bind it to a candidate
   (`candidate_version`, `review_scope`, `disposition`, optional
   `limitations`, optional `previous_review_record` and
   `previous_review_sha256` citing an older review as history).

2. **Read an already-recorded inventory.** Inventories published before this
   module (`schemaVersion` absent, "legacy") recorded two bare
   `{path, sha256}` pairs. Their bodies may be deleted from the tree, so the
   legacy reader never opens the file: it reports the recorded path and
   digest and derives the permalink from the inventory's own `sourceCommit`,
   the commit at which that digest was computed. `verify_recorded_blob` can
   additionally confirm the digest against that commit's git object when it is
   available locally; it never uses the network.

A review is evidence. It is never an approval: nothing here approves, publishes
or tags, and every record states `reviewAuthorizesRelease: false`.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Callable

SCHEMA_VERSION = 2
REQUIRED_SCOPE = "public-api-and-compatibility"
ACCEPTED_DISPOSITIONS = ("accepted", "accepted-with-limitations")
LIFECYCLE_STATUS = "retained"
AUDITS_DIR = Path("docs/audits")
RELEASES_DIR = Path("docs/releases")
REPOSITORY = "redact-secret/redact-secret"

SHA40 = re.compile(r"[0-9a-f]{40}")
SHA64 = re.compile(r"[0-9a-f]{64}")
PERMALINK = re.compile(rf"https://github\.com/{re.escape(REPOSITORY)}/blob/([0-9a-f]{{40}})/(docs/[^\s#?]+)")
FIELD = re.compile(r"([a-z][a-z0-9_]*):\s*(.+)")

STATUS_BOUND = "bound"
STATUS_RELEASE_RECORD = "recorded-in-release-record"
STATUS_REHEARSAL = "not-required-rehearsal"

Relation = Callable[[Path, str, str], str]


class ReviewIdentityError(Exception):
    """One or more reasons the candidate's review identity is not satisfied."""

    def __init__(self, messages: list[str]):
        super().__init__("; ".join(messages))
        self.messages = messages


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def permalink(commit: str, path: str) -> str:
    return f"https://github.com/{REPOSITORY}/blob/{commit}/{path}"


def parse_front_matter(text: str) -> tuple[dict[str, str] | None, list[str]]:
    """The `key: value` block `scripts/validate-decisions.py` parses, or None.

    Returns `(None, [])` for a document that carries no block at all, which is
    what every review written before the lifecycle policy is.
    """
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, []
    try:
        end = lines.index("---", 1)
    except ValueError:
        return {}, ["front matter has no closing ---"]
    fields: dict[str, str] = {}
    errors: list[str] = []
    for number, line in enumerate(lines[1:end], 2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = FIELD.fullmatch(line)
        if match is None:
            errors.append(f"front matter line {number}: unsupported syntax")
            continue
        key, value = match.groups()
        if key in fields:
            errors.append(f"front matter line {number}: duplicate field {key}")
        fields[key] = value.strip().strip("\"'")
    return fields, errors


def git_relation(root: Path, reviewed: str, source: str) -> str:
    """`ancestor` when `reviewed` is `source` or one of its ancestors,
    `not-ancestor` when both commits exist and it is not, otherwise
    `unresolvable` (a missing commit or a shallow clone). Local only."""
    try:
        for commit in (reviewed, source):
            probe = subprocess.run(
                ["git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=root, capture_output=True, check=False
            )
            if probe.returncode != 0:
                return "unresolvable"
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", reviewed, source], cwd=root, capture_output=True, check=False
        )
    except OSError:
        return "unresolvable"
    return {0: "ancestor", 1: "not-ancestor"}.get(result.returncode, "unresolvable")


def _cited_history(fields: dict[str, str], root: Path, errors: list[str]) -> dict | None:
    record, digest = fields.get("previous_review_record"), fields.get("previous_review_sha256")
    if record is None and digest is None:
        return None
    if record is None or digest is None:
        errors.append("previous_review_record and previous_review_sha256 must be given together")
        return None
    match = PERMALINK.fullmatch(record)
    if match is None:
        errors.append("previous_review_record must be a full 40-hex permalink to a file under docs/")
        return None
    if SHA64.fullmatch(digest) is None:
        errors.append("previous_review_sha256 must be a 64-hex SHA-256")
        return None
    commit, path = match.groups()
    state = verify_blob(root, commit, path, digest)
    if state == "mismatch":
        errors.append(
            f"previous_review_record names a blob whose SHA-256 is not previous_review_sha256 ({commit[:12]}:{path})"
        )
        return None
    return {
        "role": "history",
        "record": record,
        "sha256": digest,
        "verifiedLocally": state == "verified",
    }


def verify_blob(root: Path, commit: str, path: str, expected: str) -> str:
    """`verified`, `mismatch`, or `unavailable` (commit or path not local)."""
    try:
        result = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=root, capture_output=True, check=False)
    except OSError:
        return "unavailable"
    if result.returncode != 0:
        return "unavailable"
    return "verified" if sha256_bytes(result.stdout) == expected else "mismatch"


def _candidate_units(root: Path) -> list[tuple[Path, dict[str, str], list[str]]]:
    units: list[tuple[Path, dict[str, str], list[str]]] = []
    directory = root / AUDITS_DIR
    if not directory.is_dir():
        return units
    for path in sorted(directory.glob("*.md")):
        if path.name == "README.md":
            continue
        fields, errors = parse_front_matter(path.read_text(encoding="utf-8"))
        if fields is not None and "candidate_version" in fields:
            units.append((path, fields, errors))
    return units


def select_candidate_review(
    version: str,
    source: str,
    *,
    root: Path,
    rehearsal: bool = False,
    relation: Relation = git_relation,
) -> dict:
    """The review identity that satisfies `version`'s obligation, or raise.

    Only a unit bound to this exact `candidate_version` is considered, so a
    review of any other version is never selected. When no unit exists the
    obligation can still be met by a published release record for the version
    (the closeout moved the conclusions there and retired the body), or waived
    for a throwaway rehearsal, whose inventory is not release evidence.
    """
    units = _candidate_units(root)
    matching = [unit for unit in units if unit[1].get("candidate_version") == version]
    if not matching:
        other = sorted({fields.get("candidate_version", "?") for _, fields, _ in units})
        release_record = root / RELEASES_DIR / version / "manifest.json"
        if release_record.is_file():
            return {
                "status": STATUS_RELEASE_RECORD,
                "version": version,
                "releaseRecord": f"{RELEASES_DIR.as_posix()}/{version}/README.md",
                "reviewAuthorizesRelease": False,
            }
        if rehearsal:
            return {
                "status": STATUS_REHEARSAL,
                "version": version,
                "reason": "throwaway rehearsal inventory; not release evidence",
                "reviewAuthorizesRelease": False,
            }
        found = f" (found reviews bound to: {', '.join(other)}; a review of another version is history, not this candidate's review)" if other else ""
        raise ReviewIdentityError(
            [
                f"no candidate public-contract review for {version}: expected one {AUDITS_DIR.as_posix()}/*.md "
                f"unit with front matter candidate_version: {version}{found}"
            ]
        )
    if len(matching) > 1:
        names = ", ".join(path.name for path, _, _ in matching)
        raise ReviewIdentityError([f"more than one review is bound to {version}: {names}"])

    path, fields, errors = matching[0]
    relative = path.relative_to(root).as_posix()
    errors = [f"{relative}: {message}" for message in errors]

    def bad(message: str) -> None:
        errors.append(f"{relative}: {message}")

    for required in ("owner", "reviewed_source", "status", "retire_on", "review_scope", "disposition"):
        if not fields.get(required):
            bad(f"missing front matter field {required}")
    reviewed = fields.get("reviewed_source", "")
    if reviewed and SHA40.fullmatch(reviewed) is None:
        bad("reviewed_source must be a full 40-hex commit")
    elif reviewed:
        state = relation(root, reviewed, source)
        if state == "not-ancestor":
            bad(f"reviewed_source {reviewed[:12]} is not an ancestor of the qualified source {source[:12]}")
        elif state != "ancestor":
            bad(f"cannot resolve reviewed_source {reviewed[:12]} against {source[:12]} (shallow clone or missing commit)")
    if fields.get("status") and fields["status"] != LIFECYCLE_STATUS:
        bad(f"status is {fields['status']!r}; the current candidate review must be {LIFECYCLE_STATUS!r}")
    if fields.get("retire_on") and fields["retire_on"] != f"after-release:{version}":
        bad(f"retire_on must be after-release:{version}")
    if fields.get("review_scope") and fields["review_scope"] != REQUIRED_SCOPE:
        bad(f"review_scope is {fields['review_scope']!r}; the obligation requires {REQUIRED_SCOPE!r}")
    disposition = fields.get("disposition")
    if disposition and disposition not in ACCEPTED_DISPOSITIONS:
        bad(f"disposition {disposition!r} does not accept the candidate (expected one of {', '.join(ACCEPTED_DISPOSITIONS)})")
    if disposition == "accepted-with-limitations" and not fields.get("limitations"):
        bad("disposition accepted-with-limitations requires a limitations field")
    history = _cited_history(fields, root, errors)
    if errors:
        raise ReviewIdentityError(errors)

    identity = {
        "status": STATUS_BOUND,
        "version": version,
        "path": relative,
        "sha256": sha256_bytes(path.read_bytes()),
        "reviewedSource": reviewed,
        "owner": fields["owner"],
        "scope": fields["review_scope"],
        "disposition": disposition,
        "reviewAuthorizesRelease": False,
    }
    if fields.get("limitations"):
        identity["limitations"] = fields["limitations"]
    if history is not None:
        identity["history"] = [history]
    return identity


def read_recorded_identity(inventory: dict) -> dict | None:
    """Interpret the review a stored inventory recorded, without any file.

    Returns None when the inventory records no release readiness at all (the
    beta.1 inventory predates it). Raises ReviewIdentityError for a shape this
    reader does not know. The result is a normalized view:

    - `schema`: `legacy` or the integer schema version;
    - `reviews`: each recorded review with `role` (`current`, `historical` or
      `candidate`), `path`, `sha256`, and a `permalink` at the inventory's own
      `sourceCommit`, which is where the digest was computed.
    """
    readiness = inventory.get("releaseReadiness")
    if not isinstance(readiness, dict):
        return None
    review = readiness.get("publicApiAndChangelogReview")
    source = str(inventory.get("sourceCommit", ""))
    if not isinstance(review, dict) or SHA40.fullmatch(source) is None:
        raise ReviewIdentityError(["inventory records no readable public API review block or source commit"])
    version = readiness.get("schemaVersion")
    if version is None:
        reviews = []
        for key, role in (("currentPublicApiReview", "current"), ("publicApiReview", "historical")):
            entry = review.get(key)
            if entry is None:
                continue
            path, digest = str(entry.get("path", "")), str(entry.get("sha256", ""))
            if not path.startswith("docs/") or SHA64.fullmatch(digest) is None:
                raise ReviewIdentityError([f"legacy {key} is not a docs path with a SHA-256"])
            reviews.append(
                {
                    "role": role,
                    "path": path,
                    "sha256": digest,
                    "scope": entry.get("scope", "legacy-unspecified"),
                    "permalink": permalink(source, path),
                }
            )
        if not reviews:
            raise ReviewIdentityError(["legacy inventory records neither a current nor a historical review"])
        return {"schema": "legacy", "reviews": reviews}
    if version != SCHEMA_VERSION:
        raise ReviewIdentityError([f"unsupported releaseReadiness schemaVersion {version!r}"])
    candidate = review.get("candidateReview")
    if not isinstance(candidate, dict) or candidate.get("status") not in (
        STATUS_BOUND,
        STATUS_RELEASE_RECORD,
        STATUS_REHEARSAL,
    ):
        raise ReviewIdentityError(["schema 2 inventory has no recognized candidateReview"])
    reviews = []
    if candidate["status"] == STATUS_BOUND:
        if SHA64.fullmatch(str(candidate.get("sha256", ""))) is None or SHA40.fullmatch(
            str(candidate.get("reviewedSource", ""))
        ) is None:
            raise ReviewIdentityError(["candidateReview lacks a SHA-256 or a 40-hex reviewedSource"])
        if candidate.get("reviewAuthorizesRelease") is not False:
            raise ReviewIdentityError(["candidateReview must state reviewAuthorizesRelease: false"])
        reviews.append(
            {
                "role": "candidate",
                "path": candidate["path"],
                "sha256": candidate["sha256"],
                "scope": candidate.get("scope"),
                "permalink": permalink(source, candidate["path"]),
            }
        )
    return {"schema": SCHEMA_VERSION, "status": candidate["status"], "reviews": reviews}


def verify_recorded_blob(identity: dict, source: str, root: Path) -> list[str]:
    """For each recorded review: `verified`, `mismatch` or `unavailable`,
    judged against git objects at `source`, never against the working tree."""
    return [verify_blob(root, source, review["path"], review["sha256"]) for review in identity["reviews"]]
