#!/usr/bin/env python3
"""Enforce the review and evidence lifecycle under `docs/audits/` (#1266).

`decision-retire-historical-audit-bodies-before-release-qualification` makes a
file under `docs/audits/` a *temporary* review: it may be committed while work
is in progress, it carries a front matter block, and its body leaves the tree
before release qualification. This script is the mechanical half of that rule.
It re-derives the units straight from the filesystem (every
`docs/audits/*.md` except `README.md`, and every `docs/audits/evidence/<unit>/`
directory) and judges each one from its own front matter block. It is
deterministic and offline: no network, no GitHub or issue API, no environment
dependence. It only reads. It never edits or deletes a file, never approves a
release and never publishes anything; a failure is a message for a maintainer.

Two modes:

* development (default, `npm run lifecycle:check`): accepts a valid temporary
  unit. Fails on a unit with no or an invalid block (a new, unclassified
  audit), a stale exception (`after-release:<v>` for a version that already has
  `docs/releases/<v>/manifest.json`; `after-issue:#N` when N is listed in the
  `--closed-issues` snapshot), a `record` that is not a 40-hex permalink (a
  moving ref such as `blob/main` is rejected), a `final` unit whose `record`
  does not verify against local history, or more than one `retained` unit.
  Historical bodies listed in the migration list (below) are warnings.
* release (`--release`, `npm run lifecycle:release`): everything above, plus a
  rejection of every unit that is not declared `deferred` or `retained` --
  `status: final`, `status: in-progress`, `retire_on: before-qualification`,
  anything still in the migration list -- and of a `retained` unit whose
  `after-release:<version>` is not the candidate version or was already
  published. Run by the qualification entry points before anything is built or
  published. Eligibility is decided per unit, never by counting files.

Inputs, all optional: `--root` (default: this repository), `--version` (the
candidate version; default is `packages/javascript/package.json`),
`--closed-issues FILE` (see below), `--legacy-file FILE`.

Offline staleness of `after-issue:#N`. Whether issue N is still open is a fact
about GitHub, which this check never reads. The honest offline contract is a
maintainer-supplied snapshot: `--closed-issues FILE` takes one issue number
per line (or a JSON array), for example the output of
`gh issue list --state closed --limit 1000 --json number --jq '.[].number'`.
A unit whose N is in the snapshot is stale and fails. Without a snapshot the
check cannot know, so it does not pretend to: release mode prints every
unverified `after-issue` exception as a NOTICE for the maintainer to confirm,
and still fails every other rule. The snapshot is never committed (it would be
a second archive that goes stale) and never fetched here.

Migration list. Units written before the policy carry no block. They are not
"new unclassified audits": `scripts/audit-lifecycle-legacy-units.txt` names
them (one path per line) so development stays green while #1265 retires them.
It can only shrink: a unit named there that is absent is a warning, a unit
missing from it is an error, and release mode rejects both the units and the
file's continued existence. The cleanup deletes the file with the last unit.

`record` verification for a `final` unit uses `check-historical-permalinks.py`
against local history: the commit must be an ancestor of main and hold every
file of the unit byte-identical to the tree. A shallow clone cannot judge it;
that is reported as a warning in development and is moot in release mode, where
a `final` unit fails regardless.

Exit status: 0 clean (warnings and notices allowed), 1 errors, 2 cannot run.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDITS = "docs/audits"
LEGACY_FILE = "scripts/audit-lifecycle-legacy-units.txt"
REPOSITORY = "redact-secret/redact-secret"

SHA40 = re.compile(r"[0-9a-f]{40}")
OWNER = re.compile(r"#[1-9][0-9]*|[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
AFTER_ISSUE = re.compile(r"after-issue:#([1-9][0-9]*)")
AFTER_RELEASE = re.compile(r"after-release:(" + VERSION.pattern + ")")
RECORD = re.compile(rf"https://github\.com/{re.escape(REPOSITORY)}/(blob|tree)/([0-9a-f]{{40}})/([^\s#?]+)")
TRAILING_COMMENT = re.compile(r"\s+#\s.*$")
STATUSES = ("in-progress", "final", "deferred", "retained")
REQUIRED = ("owner", "reviewed_source", "status", "retire_on")

REMEDIATION = {
    "unclassified": (
        "Add the front matter block to the entry file (owner, reviewed_source, status, retire_on; see "
        "CONVENTIONS.md 'Review and evidence lifecycle'), or delete the unit."
    ),
    "invalid": "Fix the front matter field named in the message; the allowed values are in CONVENTIONS.md.",
    "stale": (
        "The exception's trigger has fired: retire the unit (pin a 40-hex permalink, keep current conclusions in "
        "the spec or release record, delete the body) or move retire_on to a still-valid trigger with a reason."
    ),
    "record": "Set `record` to the 40-hex blob permalink of the unit at a commit on main; never blob/main or a branch.",
    "historical": (
        "Retire the body before qualification: pin a 40-hex permalink on main, keep every current conclusion in "
        "the spec, contract or release record, delete the body with no stub, then remove its line from "
        f"{LEGACY_FILE}. Do not move it to another tracked folder."
    ),
    "not-releasable": (
        "A unit that is `final`, `in-progress` or `before-qualification` is not carried into qualification: "
        "retire it, or declare it `deferred` (open issue that cannot be restated without the body) or `retained` "
        "(the one current candidate review). The exact cleaned commit is the qualification identity."
    ),
    "expired": "Retire the retained review: its release is published or it belongs to a different version.",
    "retained": "At most one unit may be `retained`; retire or re-declare the others.",
    "legacy-file": f"Delete {LEGACY_FILE} in the cleanup that retires the last historical unit.",
    "stray": "Only README.md, <name>.md and evidence/<unit>/ belong under docs/audits/; delete or relocate the file.",
    "legacy-stale": f"Remove the line from {LEGACY_FILE}.",
}


@dataclass(frozen=True)
class Unit:
    path: str  # `docs/audits/<name>.md` or `docs/audits/evidence/<unit>`
    entry: str  # the file that carries the front matter block


@dataclass(frozen=True)
class Finding:
    level: str  # error | warning | notice
    category: str
    path: str
    message: str


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


def parse_block(text: str) -> tuple[dict[str, str] | None, list[str]]:
    """The `key: value` block `scripts/validate-decisions.py` parses.

    `(None, [])` for a document with no block; a trailing ` # comment` after a
    value is ignored (the ADR's example block carries them).
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
        match = re.fullmatch(r"([a-z][a-z0-9_]*):\s*(.+)", line)
        if match is None:
            errors.append(f"front matter line {number}: unsupported syntax")
            continue
        key, value = match.groups()
        if key in fields:
            errors.append(f"front matter line {number}: duplicate field {key}")
        fields[key] = TRAILING_COMMENT.sub("", value).strip().strip("\"'")
    return fields, errors


def list_units(root: Path) -> tuple[list[Unit], list[str]]:
    """Units and stray paths, from the filesystem alone."""
    audits = root / AUDITS
    units: list[Unit] = []
    strays: list[str] = []
    if not audits.is_dir():
        return units, strays
    for child in sorted(audits.iterdir()):
        rel = f"{AUDITS}/{child.name}"
        if child.name == "README.md":
            continue
        if child.is_file() and child.suffix == ".md":
            units.append(Unit(rel, rel))
        elif child.is_dir() and child.name == "evidence":
            for unit in sorted(child.iterdir()):
                if unit.is_dir():
                    units.append(Unit(f"{rel}/{unit.name}", f"{rel}/{unit.name}/README.md"))
                else:
                    strays.append(f"{rel}/{unit.name}")
        else:
            strays.append(rel)
    return units, strays


def read_legacy(root: Path, legacy_file: Path | None = None) -> tuple[list[str] | None, list[str]]:
    """Paths in the migration list, or None when the file does not exist."""
    path = legacy_file if legacy_file is not None else root / LEGACY_FILE
    if not path.is_file():
        return None, []
    entries: list[str] = []
    errors: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(rf"{AUDITS}/[^/\s]+\.md|{AUDITS}/evidence/[^/\s]+", line) is None:
            errors.append(f"{LEGACY_FILE}:{number}: not a unit path: {line}")
        else:
            entries.append(line)
    return entries, errors


def load_closed_issues(path: Path) -> set[int]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return {int(item) for item in json.loads(text)}
    return {int(token.lstrip("#")) for token in text.split() if token.lstrip("#").isdigit()}


def published_versions(root: Path) -> set[str]:
    releases = root / "docs" / "releases"
    if not releases.is_dir():
        return set()
    return {p.name for p in releases.iterdir() if (p / "manifest.json").is_file()}


def candidate_version(root: Path) -> str | None:
    try:
        data = json.loads((root / "packages" / "javascript" / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    version = data.get("version")
    return version if isinstance(version, str) else None


def strip_block(text: str) -> str:
    """The document without its leading front matter block."""
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return text
    for index, line in enumerate(lines[1:], 1):
        if line.rstrip("\r\n") == "---":
            return "".join(lines[index + 1 :])
    return text


def _verify_record(root: Path, unit: Unit, sha: str) -> tuple[list[str], list[str]]:
    """(errors, warnings) from local history; never the network.

    The commit must be an ancestor of main and hold every tracked file of the
    unit. A file other than the entry file must be byte-identical. The entry
    file is compared below its front matter block: the block is lifecycle
    metadata that cannot match, because it carries the `record` naming the
    commit that preceded it.
    """
    hp = _load("check_historical_permalinks", "check-historical-permalinks.py")
    try:
        repo = hp.Repo(root)
    except hp.Unavailable as unavailable:
        return [], [f"record cannot be verified here: {unavailable}"]
    except OSError as error:
        return [], [f"record cannot be verified here: {error}"]
    if not repo.commit_exists(sha):
        message = f"record commit {sha} is not in the local history{repo.shallow_hint()}"
        return ([], [message]) if repo.shallow_hint() else ([message], [])
    if not repo.is_ancestor(sha):
        return [f"record commit {sha} is not an ancestor of {repo.main_ref}"], []
    prefix = unit.path + ("/" if "/evidence/" in unit.path else "")
    listing = repo._git("ls-files", "-z", "--", prefix, binary=True).stdout.decode("utf-8")
    errors: list[str] = []
    for name in (n for n in listing.split("\0") if n):
        pinned = repo.blob(sha, name)
        if pinned is None:
            errors.append(f"{name}: does not exist at record commit {sha[:12]}")
            continue
        current = (root / name).read_bytes()
        if name == unit.entry:
            same = strip_block(pinned.decode("utf-8", errors="replace")) == strip_block(
                current.decode("utf-8", errors="replace")
            )
        else:
            same = pinned == current
        if not same:
            errors.append(
                f"{name}: differs from the record commit {sha[:12]}, so the permalink does not preserve this body"
            )
    return errors, []


def temporary_units(root: Path) -> list[str]:
    """Paths of units whose valid block says `in-progress` or `final`.

    A temporary unit is tracked by this check, not by the audit index or the
    docs reachability walk: being indexed implies no permanent retention, and
    writing a review must not require editing a navigation page.
    """
    found: list[str] = []
    units, _ = list_units(root)
    for unit in units:
        entry = root / unit.entry
        if not entry.is_file():
            continue
        fields, problems = parse_block(entry.read_text(encoding="utf-8", errors="replace"))
        if (
            fields
            and not problems
            and fields.get("status") in ("in-progress", "final")
            and all(k in fields for k in REQUIRED)
        ):
            found.append(unit.path)
    return found


def check_unit(
    unit: Unit,
    root: Path,
    *,
    release: bool,
    version: str | None,
    published: set[str],
    closed: set[int] | None,
    legacy: set[str],
    verify_records: bool,
) -> list[Finding]:
    out: list[Finding] = []

    def add(level: str, category: str, message: str) -> None:
        out.append(Finding(level, category, unit.path, message))

    entry = root / unit.entry
    fields: dict[str, str] | None = None
    problems: list[str] = []
    if entry.is_file():
        try:
            fields, problems = parse_block(entry.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as error:
            problems = [f"cannot read {unit.entry}: {error}"]
            fields = {}
    if fields is None or (not fields and not problems):
        where = "its entry file" if entry.is_file() else f"{unit.entry} (the entry file is missing)"
        if unit.path in legacy:
            add(
                "error" if release else "warning",
                "historical",
                f"historical body with no lifecycle block, eligible for retirement ({where})",
            )
        else:
            add("error", "unclassified", f"no front matter block in {where}: a new audit must declare its lifecycle")
        return out
    for problem in problems:
        add("error", "invalid", problem)
    missing = [key for key in REQUIRED if key not in fields]
    if missing:
        add("error", "invalid", f"missing required field(s): {', '.join(missing)}")
        return out

    owner, reviewed, status, retire_on = (fields[key] for key in REQUIRED)
    bad = False
    if OWNER.fullmatch(owner) is None:
        add("error", "invalid", f"owner {owner!r} is neither an issue number (#N) nor a GitHub login")
        bad = True
    if SHA40.fullmatch(reviewed) is None:
        add("error", "invalid", f"reviewed_source {reviewed!r} is not a full 40-hex commit")
        bad = True
    if status not in STATUSES:
        add("error", "invalid", f"status {status!r} is not one of {', '.join(STATUSES)}")
        bad = True
    after_issue, after_release = AFTER_ISSUE.fullmatch(retire_on), AFTER_RELEASE.fullmatch(retire_on)
    if retire_on != "before-qualification" and not after_issue and not after_release:
        add(
            "error",
            "invalid",
            f"retire_on {retire_on!r} is not before-qualification, after-issue:#N or after-release:<version>",
        )
        bad = True
    if bad:
        return out

    if status == "final" and retire_on != "before-qualification":
        add("error", "invalid", "a `final` unit has retire_on: before-qualification")
    if status == "deferred" and not after_issue:
        add("error", "invalid", "a `deferred` unit has retire_on: after-issue:#N (the open issue it waits on)")
    if status == "retained" and not after_release:
        add("error", "invalid", "a `retained` unit has retire_on: after-release:<version>")

    if after_release and after_release.group(1) in published:
        add(
            "error",
            "stale",
            f"retire_on after-release:{after_release.group(1)} but docs/releases/{after_release.group(1)}/manifest.json "
            "exists: that version is published, so this unit is expired",
        )
    if after_issue:
        number = int(after_issue.group(1))
        if closed is not None and number in closed:
            add(
                "error",
                "stale",
                f"retire_on after-issue:#{number} but #{number} is closed in the --closed-issues snapshot",
            )
        elif release and closed is None:
            add("notice", "stale", f"after-issue:#{number} is unverified offline: confirm #{number} is still open")
    if release and status == "retained" and after_release and version and after_release.group(1) != version:
        add("error", "expired", f"retained for {after_release.group(1)}, not the candidate version {version}")

    if "record" in fields or status == "final":
        record = fields.get("record")
        match = RECORD.fullmatch(record) if record else None
        if match is None:
            moving = bool(record and re.search(rf"github\.com/{re.escape(REPOSITORY)}/(blob|tree)/[^/]+/", record))
            reason = "a moving ref or abbreviated commit" if moving else "absent or not a blob permalink"
            add(
                "error",
                "record",
                f"record is {reason}; it must be https://github.com/{REPOSITORY}/blob/<40-hex>/{unit.path}",
            )
        elif not (
            match.group(3) == unit.path or match.group(3) == unit.entry or match.group(3).rstrip("/") == unit.path
        ):
            add("error", "record", f"record names {match.group(3)}, not this unit ({unit.path})")
        elif verify_records and status == "final":
            errors, warnings = _verify_record(root, unit, match.group(2))
            for message in errors:
                add("error", "record", message)
            for message in warnings:
                add("warning", "record", message)

    if release:
        if status == "final":
            add("error", "not-releasable", "status: final, eligible for retirement now")
        elif status == "in-progress":
            add(
                "error",
                "not-releasable",
                "status: in-progress, which becomes final or deferred or is deleted before qualification",
            )
        elif retire_on == "before-qualification":
            add("error", "not-releasable", "retire_on: before-qualification")
    return out


def run(
    root: Path,
    *,
    release: bool = False,
    version: str | None = None,
    closed: set[int] | None = None,
    legacy_file: Path | None = None,
    verify_records: bool = True,
) -> list[Finding]:
    root = root.resolve()
    version = version or candidate_version(root)
    units, strays = list_units(root)
    legacy_entries, legacy_errors = read_legacy(root, legacy_file)
    legacy = set(legacy_entries or [])
    published = published_versions(root)
    findings: list[Finding] = [Finding("error", "invalid", LEGACY_FILE, message) for message in legacy_errors]
    for stray in strays:
        findings.append(Finding("error", "stray", stray, "not a review unit and not README.md"))
    present = {unit.path for unit in units}
    for stale in sorted(legacy - present):
        findings.append(
            Finding("warning", "legacy-stale", stale, "named in the migration list but no longer in the tree")
        )
    if release and legacy_entries is not None:
        findings.append(
            Finding("error", "legacy-file", LEGACY_FILE, "the migration list must not exist at qualification")
        )
    retained: list[str] = []
    for unit in units:
        result = check_unit(
            unit,
            root,
            release=release,
            version=version,
            published=published,
            closed=closed,
            legacy=legacy,
            verify_records=verify_records,
        )
        findings.extend(result)
        entry = root / unit.entry
        if entry.is_file():
            fields, _ = parse_block(entry.read_text(encoding="utf-8", errors="replace"))
            if fields and fields.get("status") == "retained":
                retained.append(unit.path)
    if len(retained) > 1:
        for path in retained:
            findings.append(
                Finding("error", "retained", path, f"{len(retained)} units are `retained`; at most one may be")
            )
    return findings


def render(findings: list[Finding], *, release: bool) -> str:
    lines: list[str] = []
    for level in ("error", "warning", "notice"):
        for item in sorted((f for f in findings if f.level == level), key=lambda f: (f.category, f.path)):
            lines.append(f"{level.upper()} [{item.category}] {item.path}: {item.message}")
    categories = sorted({f.category for f in findings if f.level == "error"})
    if categories:
        lines.append("")
        lines.append("Remediation (the check changes nothing; a maintainer must act):")
        for category in categories:
            lines.append(f"  [{category}] {REMEDIATION[category]}")
    errors = sum(f.level == "error" for f in findings)
    warnings = sum(f.level == "warning" for f in findings)
    notices = sum(f.level == "notice" for f in findings)
    lines.append(
        f"Audit lifecycle check ({'release' if release else 'development'}) complete: "
        f"{errors} error(s), {warnings} warning(s), {notices} notice(s)"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--release", action="store_true", help="candidate-qualification mode")
    parser.add_argument("--version", help="candidate version (default: packages/javascript/package.json)")
    parser.add_argument("--closed-issues", type=Path, help="maintainer snapshot of closed issue numbers")
    parser.add_argument("--legacy-file", type=Path, help="migration list (default: <root>/" + LEGACY_FILE + ")")
    parser.add_argument("--no-verify-records", action="store_true", help="skip git verification of `record`")
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        print(f"UNAVAILABLE {args.root} is not a directory", file=sys.stderr)
        return 2
    closed = None
    if args.closed_issues is not None:
        try:
            closed = load_closed_issues(args.closed_issues)
        except (OSError, ValueError) as error:
            print(f"UNAVAILABLE cannot read --closed-issues: {error}", file=sys.stderr)
            return 2
    try:
        findings = run(
            args.root,
            release=args.release,
            version=args.version,
            closed=closed,
            legacy_file=args.legacy_file,
            verify_records=not args.no_verify_records,
        )
    except (subprocess.SubprocessError, OSError) as error:
        print(f"UNAVAILABLE {error}", file=sys.stderr)
        return 2
    print(render(findings, release=args.release))
    return 1 if any(f.level == "error" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
