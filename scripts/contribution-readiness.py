#!/usr/bin/env python3
"""Summarize a change's contribution readiness (issue #1051, part of #999).

The repository has many justified gates. This script does not add one and does
not weaken one: it reads a diff, groups it into the contribution classes that
cost first-time contributors the most, and prints what is present (a check
mark) and what needs action (an arrow, with the exact command to run).

    python3 -B scripts/contribution-readiness.py                      # origin/main...HEAD plus uncommitted files
    python3 -B scripts/contribution-readiness.py --base main --head my-branch
    python3 -B scripts/contribution-readiness.py --paths changes.txt  # no git; lines are `A path`, `M path` or `path`

Boundaries, all deliberate:

- It reports and never decides. The exit status is 0 whatever the diff looks
  like, so this script can neither pass nor fail a pull request. CI stays
  strict through the gates themselves; the `contribution-readiness` job in
  `.github/workflows/ci.yml` is `continue-on-error` and runs `if: always()`
  after them, only to read their outcomes (`--gate name=result`).
- It prints file names and commands only. A path outside a conservative
  character set is withheld, and no file's content is ever printed (the one
  file it reads, `CHANGELOG.md`, is compared, not shown). Fixture values,
  secret-shaped material, protected evidence and shadow-score internals never
  reach the output.
- The vocabulary is the contribution funnel's (#1049,
  `docs/contracts/contribution/implementation-ready-handoff.md`): `intake`,
  `research-needed`, `implementation-ready`, `verification-needed`,
  `complete`. Those label an issue, never a family's support status, and this
  script never writes one. It names the next handoff only.
- The output is deterministic: sorted, no timestamps, no environment data.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STATES = ("intake", "research-needed", "implementation-ready", "verification-needed", "complete")

DETECTOR_DIR = "crates/secret-scan-core/src/detectors/"
DETECTOR_REGISTRY = (DETECTOR_DIR + "mod.rs", "crates/secret-scan-core/src/registry.rs")
CORE_TESTS_DIR = "crates/secret-scan-core/tests/"
INVENTORY = "docs/coverage/detector-inventory.json"
CORPUS = "conformance/fixtures/synchronous-corpus.json"
REGRESSIONS = "conformance/benchmark-regressions.json"
CHANGELOG = "CHANGELOG.md"
SAST_BASELINE = "sast/baseline.json"
PIN_SOURCE = "benchmarks/pin-source.json"
PIN_MANIFEST = "benchmarks/pin-manifest.json"

# Generated from INVENTORY by the two doc generators, then from the corpus and
# inventory by the three coverage generators.
INVENTORY_DOCS = ("docs/reference/detection.md", "docs/specs/detector-families.md")
INVENTORY_DOC_COMMANDS = (
    "python3 -B scripts/generate-detector-inventory-docs.py",
    "python3 -B scripts/generate-detector-families-table.py",
)
COVERAGE_REPORTS = (
    "docs/coverage/inventory-report.json",
    "docs/coverage/coverage-declarations.json",
    "docs/coverage/coverage-report.md",
)
COVERAGE_COMMANDS = (
    "python3 -B scripts/generate-coverage-inventory.py --out docs/coverage/inventory-report.json",
    "python3 -B scripts/generate-coverage-declarations.py --out docs/coverage/coverage-declarations.json",
    "python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md",
)

# The scoped local checks, from the CONTRIBUTION.md table.
CHECK_DOCS = "npm run check:docs"
CHECK_FIXTURE = "npm run check:detector && npm run check:js && npm run check:rust"
CHECK_DETECTOR = "npm run check:rust && npm run check:detector"
CHECK_RELEASE = "npm run check:release"
INVENTORY_TEST = "cargo test -p redact-secret --locked --test detector_inventory"

# What to run for a CI gate that failed, keyed by the CI job id.
GATE_COMMANDS = {
    "test": "npm run check:changed",
    "lint": "npm run lint && ruff check bindings/python scripts && ruff format --check bindings/python scripts",
    "changelog-coverage": "python3 -B scripts/check-changelog-coverage.py --base origin/main",
    "scoring-artifact-identity": "python3 -B scripts/check-scoring-artifact.py --base origin/main",
}
GATE_RESULTS = ("success", "failure", "cancelled", "skipped")

SAFE_PATH = re.compile(r"[A-Za-z0-9._/@+~-]{1,200}")
SAFE_COMMAND = re.compile(r"[A-Za-z0-9 ._:/=@&|+-]{1,300}")
SHOWN_PATHS = 4

OK = "✓"
TODO = "→"


@dataclass(frozen=True)
class Change:
    status: str  # "A" added, "M" modified, "D" deleted
    path: str


@dataclass
class Row:
    ok: bool
    text: str
    run: tuple[str, ...] = ()


@dataclass
class Section:
    title: str
    rows: list[Row] = field(default_factory=list)
    check: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def pending(self) -> bool:
        return any(not row.ok for row in self.rows)


@dataclass
class Report:
    sections: list[Section]
    gates: list[Row]
    stage: str
    handoff: list[str]

    @property
    def pending(self) -> bool:
        return any(section.pending for section in self.sections) or any(not row.ok for row in self.gates)


def _load_changelog_check():
    spec = importlib.util.spec_from_file_location(
        "check_changelog_coverage", Path(__file__).resolve().parent / "check-changelog-coverage.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def names(paths: list[str]) -> str:
    """Comma-separated, sorted, capped file names; unsafe names are withheld."""
    ordered = sorted(set(paths))
    shown = [path if SAFE_PATH.fullmatch(path) else "<path withheld>" for path in ordered[:SHOWN_PATHS]]
    more = len(ordered) - SHOWN_PATHS
    return ", ".join(shown) + (f" (+{more} more)" if more > 0 else "")


def parse_changes(lines: list[str]) -> list[Change]:
    """`A path`, `M path`, `D path`, or a bare `path` (modified)."""
    changes: dict[str, str] = {}
    for raw in lines:
        parts = raw.strip().split(None, 1)
        if not parts:
            continue
        status, path = ("M", parts[0]) if len(parts) == 1 else (parts[0][:1].upper(), parts[1].strip())
        if status not in ("A", "M", "D"):
            status = "M"
        if changes.get(path) != "A":
            changes[path] = status
    return [Change(status, path) for path, status in sorted(changes.items())]


def missing(paths: set[str], expected: tuple[str, ...]) -> list[str]:
    return [path for path in expected if path not in paths]


def generated_rows(paths: set[str]) -> list[Row]:
    """Whether the generated outputs a source change feeds are in the diff."""
    rows: list[Row] = []
    if INVENTORY in paths:
        absent = missing(paths, INVENTORY_DOCS)
        if absent:
            rows.append(
                Row(False, f"generated detector inventory docs are stale: {names(absent)}", INVENTORY_DOC_COMMANDS)
            )
        else:
            rows.append(Row(True, "generated detector inventory docs are in the diff"))
    if INVENTORY in paths or CORPUS in paths:
        absent = missing(paths, COVERAGE_REPORTS)
        if absent:
            rows.append(Row(False, f"generated coverage reports are stale: {names(absent)}", COVERAGE_COMMANDS))
        else:
            rows.append(Row(True, "generated coverage reports are in the diff"))
    return rows


def detector_section(changes: list[Change], paths: set[str]) -> Section | None:
    sources = [c.path for c in changes if c.path.startswith(DETECTOR_DIR)]
    if not sources and INVENTORY not in paths:
        return None
    section = Section("New or changed detector", check=CHECK_DETECTOR)
    new = [
        c.path
        for c in changes
        if c.status == "A" and c.path.startswith(DETECTOR_DIR) and c.path not in DETECTOR_REGISTRY
    ]
    if sources:
        section.rows.append(Row(True, f"detector source changed: {names(sources)}"))
    if new:
        if any(path in paths for path in DETECTOR_REGISTRY):
            section.rows.append(Row(True, "detector registered"))
        else:
            section.rows.append(
                Row(False, f"new detector module is not registered ({DETECTOR_REGISTRY[0]})", (INVENTORY_TEST,))
            )
        if INVENTORY in paths:
            section.rows.append(Row(True, "policy classification present (detector inventory)"))
        else:
            section.rows.append(
                Row(
                    False,
                    f"policy classification missing: declare the detector in {INVENTORY}",
                    (INVENTORY_TEST,),
                )
            )
    if CORPUS in paths:
        section.rows.append(Row(True, "synchronous conformance fixture present"))
    else:
        section.rows.append(
            Row(
                False,
                f"synchronous conformance fixture missing: add a synthetic case to {CORPUS}",
                (CHECK_FIXTURE,),
            )
        )
    if CORPUS in paths or any(path.startswith(CORE_TESTS_DIR) for path in paths):
        section.rows.append(Row(True, "deterministic test present"))
    else:
        section.rows.append(Row(False, "no deterministic test in the diff", ("cargo test -p redact-secret --locked",)))
    section.rows.extend(generated_rows(paths))
    if new:
        section.notes.append(
            "Evidence arrival (provider evidence, twins, controls) is gated in redact-secret-benchmarks, "
            "not here: run `npm run arrival:check` there."
        )
    return section


def fixture_section(changes: list[Change], paths: set[str], with_generated: bool) -> Section | None:
    fixtures = [c.path for c in changes if c.path.startswith("conformance/") and c.path != REGRESSIONS]
    if not fixtures:
        return None
    section = Section("Conformance fixture", check=CHECK_FIXTURE)
    section.rows.append(Row(True, f"conformance files changed: {names(fixtures)}"))
    if with_generated:
        section.rows.extend(generated_rows(paths))
    section.notes.append("Fixture values stay synthetic; this summary never prints them.")
    return section


def docs_section(changes: list[Change], guarded_paths: list[str]) -> Section | None:
    if not changes or guarded_paths:
        return None
    if not all(c.path.endswith(".md") or c.path.startswith("docs/") for c in changes):
        return None
    section = Section("Documentation only", check=CHECK_DOCS)
    section.rows.append(Row(True, f"documentation files only: {names([c.path for c in changes])}"))
    section.rows.append(Row(True, "no changelog entry required: no guarded code path changed"))
    return section


def regression_section(paths: set[str]) -> Section | None:
    if REGRESSIONS not in paths:
        return None
    section = Section("Benchmark-originated product regression", check="npm run coverage:check")
    section.rows.append(Row(True, f"regression record changed: {REGRESSIONS}"))
    if CORPUS in paths:
        section.rows.append(Row(True, "minimal canonical regression present"))
    else:
        section.rows.append(
            Row(
                False,
                f"minimal canonical regression missing from {CORPUS}",
                (CHECK_FIXTURE,),
            )
        )
    section.notes.append(
        "The exact fixed candidate is measured and linked in redact-secret-benchmarks; "
        "until that evidence is recorded the issue stays verification-needed."
    )
    return section


def release_section(changes: list[Change], paths: set[str]) -> Section | None:
    prefixes = (".github/", "scripts/", "sast/", "docs/releases/")
    exact = (
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "package-lock.json",
        "deny.toml",
        "rust-toolchain.toml",
        "docs/releasing.md",
        PIN_SOURCE,
        PIN_MANIFEST,
    )
    touched = [c.path for c in changes if c.path.startswith(prefixes) or c.path in exact]
    if not touched:
        return None
    section = Section("Release, CI, packaging or manifest change", check=CHECK_RELEASE)
    section.rows.append(Row(True, f"release or CI surface changed: {names(touched)}"))
    if any(path.startswith(".github/workflows/") for path in paths):
        if SAST_BASELINE in paths:
            section.rows.append(Row(True, "SAST baseline is in the diff"))
        else:
            section.rows.append(
                Row(
                    False,
                    f"workflow changed; {SAST_BASELINE} is keyed by line number, so re-key it if lines shifted",
                    ("python3 -B scripts/run-sast.py",),
                )
            )
    if (PIN_SOURCE in paths) != (PIN_MANIFEST in paths):
        section.rows.append(
            Row(False, "benchmark pin source and manifest changed separately", ("npm run benchmark-pins:check",))
        )
    elif PIN_SOURCE in paths:
        section.rows.append(Row(True, "benchmark pin source and manifest changed together"))
    section.notes.append("Version, tag and publication stay maintainer-approved (AGENTS.md, release authority).")
    return section


def changelog_section(
    guarded_paths: list[str], changelog_updated: bool, labels: list[str], waiver: str
) -> Section | None:
    if not guarded_paths:
        return None
    section = Section("Changelog coverage")
    if changelog_updated:
        section.rows.append(Row(True, "CHANGELOG.md Unreleased entry present"))
    elif waiver in labels:
        section.rows.append(Row(True, f"`{waiver}` label applied (waiver visible to the reviewer)"))
    else:
        section.rows.append(
            Row(
                False,
                f"changelog coverage missing for {names(guarded_paths)}: add an Unreleased entry "
                f"or apply the `{waiver}` label when no observable behavior changed",
                ("python3 -B scripts/check-changelog-coverage.py --base origin/main",),
            )
        )
    return section


def gate_rows(gates: dict[str, str]) -> list[Row]:
    rows: list[Row] = []
    passed = sorted(name for name, result in gates.items() if result == "success")
    if passed:
        rows.append(Row(True, f"gates passed: {', '.join(passed)}"))
    for name in sorted(gates):
        result = gates[name]
        if result in ("failure", "cancelled"):
            command = GATE_COMMANDS.get(name, "npm run check:changed")
            rows.append(Row(False, f"CI gate `{name}` {result}; the gate itself is authoritative", (command,)))
    return rows


def read_handoff(path: Path) -> list[str]:
    """State, route and scoped commands of a handoff file; nothing else is read out."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["handoff file unreadable"]
    if not isinstance(data, dict):
        return ["handoff file unreadable"]
    lines: list[str] = []
    state = data.get("state")
    if state in STATES:
        lines.append(f"handoff state: {state}")
    identity = data.get("identity")
    route = identity.get("route") if isinstance(identity, dict) else None
    if isinstance(route, str) and re.fullmatch(r"[a-z-]{1,40}", route):
        lines.append(f"handoff route: {route}")
    commands = data.get("commands")
    if isinstance(commands, list):
        for command in commands:
            if isinstance(command, str) and SAFE_COMMAND.fullmatch(command):
                lines.append(f"handoff command: {command}")
    return lines


def evaluate(
    changes: list[Change],
    changelog_updated: bool = False,
    labels: list[str] | None = None,
    gates: dict[str, str] | None = None,
    handoff: list[str] | None = None,
) -> Report:
    """Pure: file changes (and optional CI gate results) in, a report out."""
    labels = labels or []
    check = _load_changelog_check()
    paths = {c.path for c in changes}
    guarded_paths = check.guarded(sorted(paths))

    detector = detector_section(changes, paths)
    fixture = fixture_section(changes, paths, with_generated=detector is None)
    regression = regression_section(paths)
    sections = [
        section
        for section in (
            detector,
            fixture,
            regression,
            docs_section(changes, guarded_paths),
            release_section(changes, paths),
            changelog_section(guarded_paths, changelog_updated, labels, check.WAIVER_LABEL),
        )
        if section is not None
    ]
    gate_results = gate_rows(gates or {})
    report = Report(sections, gate_results, "", handoff or [])
    if detector is not None or regression is not None:
        # A candidate with nothing left to do is the reverse handoff; otherwise
        # the reviewed contract is still being implemented.
        report.stage = "verification-needed" if not report.pending else "implementation-ready"
    return report


STAGE_TEXT = {
    "implementation-ready": "finish the items marked above against the reviewed contract",
    "verification-needed": "hand this exact candidate to redact-secret-benchmarks for measurement",
}


def render(report: Report) -> str:
    lines = ["Contribution readiness", ""]
    if not report.sections and not report.gates:
        lines.append("No contribution class detected in this diff.")
    for section in report.sections:
        lines.append(section.title)
        for row in section.rows:
            lines.append(f"  {OK if row.ok else TODO} {row.text}")
            for command in row.run:
                lines.append(f"      run: {command}")
        if section.check:
            lines.append(f"  scoped check: {section.check}")
        for note in section.notes:
            lines.append(f"  note: {note}")
        lines.append("")
    if report.gates:
        lines.append("CI gates")
        for row in report.gates:
            lines.append(f"  {OK if row.ok else TODO} {row.text}")
            for command in row.run:
                lines.append(f"      run: {command}")
        lines.append("")
    for line in report.handoff:
        lines.append(f"  {line}")
    if report.handoff:
        lines.append("")
    if report.stage:
        lines.append(f"Funnel stage: {report.stage} - {STAGE_TEXT[report.stage]}.")
        lines.append("A funnel stage labels an issue; it is never a support status.")
    lines.append("This summary reports only. CI gates stay strict and authoritative; none is replaced or relaxed.")
    return "\n".join(lines) + "\n"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def default_base() -> str:
    for ref in ("origin/main", "main"):
        try:
            git("rev-parse", "--verify", "--quiet", ref)
            return ref
        except subprocess.CalledProcessError:
            continue
    raise SystemExit("error: neither origin/main nor main exists; pass --base")


def git_changes(base: str, head: str | None) -> list[Change]:
    lines = [
        f"{line.split(chr(9))[0][:1]} {line.split(chr(9))[-1]}"
        for line in git("diff", "--name-status", "-M", f"{base}...{head or 'HEAD'}").splitlines()
        if line
    ]
    if head is None:
        # Local default: also count uncommitted and untracked work.
        lines += [
            f"{line.split(chr(9))[0][:1]} {line.split(chr(9))[-1]}"
            for line in git("diff", "--name-status", "-M", "HEAD").splitlines()
            if line
        ]
        lines += [f"A {line}" for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line]
    return parse_changes(lines)


def git_changelog_updated(base: str, head: str | None) -> bool:
    check = _load_changelog_check()

    def at(ref: str) -> str:
        try:
            return git("show", f"{ref}:{CHANGELOG}")
        except subprocess.CalledProcessError:
            return ""

    base_text = at(base)
    head_text = at(head) if head else (ROOT / CHANGELOG).read_text(encoding="utf-8")
    return check.unreleased_section(head_text) != check.unreleased_section(base_text)


def parse_gates(values: list[str]) -> dict[str, str]:
    gates: dict[str, str] = {}
    for value in values:
        name, _, result = value.partition("=")
        if not re.fullmatch(r"[a-z0-9-]{1,60}", name) or result not in GATE_RESULTS:
            raise SystemExit(f"error: --gate expects <job-id>=<{'|'.join(GATE_RESULTS)}>, got a malformed value")
        gates[name] = result
    return gates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="the base ref (default: origin/main, else main)")
    parser.add_argument("--head", help="the head ref (default: HEAD plus uncommitted and untracked files)")
    parser.add_argument("--paths", help="read `A|M|D path` lines from this file (`-` is stdin) instead of git")
    parser.add_argument(
        "--changelog-updated", action="store_true", help="with --paths: CHANGELOG.md Unreleased changed"
    )
    parser.add_argument("--labels", default="", help="comma-separated pull-request labels")
    parser.add_argument("--gate", action="append", default=[], help="a CI gate outcome, <job-id>=<result>; repeatable")
    parser.add_argument(
        "--handoff", help="an implementation-ready handoff file; only state, route and commands are read"
    )
    parser.add_argument("--step-summary", action="store_true", help="also append to $GITHUB_STEP_SUMMARY when set")
    args = parser.parse_args(argv)

    labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    if args.paths:
        text = sys.stdin.read() if args.paths == "-" else Path(args.paths).read_text(encoding="utf-8")
        changes = parse_changes(text.splitlines())
        changelog_updated = args.changelog_updated
    else:
        try:
            base = args.base or default_base()
            changes = git_changes(base, args.head)
            changelog_updated = git_changelog_updated(base, args.head)
        except subprocess.CalledProcessError:
            print("error: could not read the diff; check --base and --head", file=sys.stderr)
            return 2

    handoff = read_handoff(Path(args.handoff)) if args.handoff else []
    output = render(evaluate(changes, changelog_updated, labels, parse_gates(args.gate), handoff))
    sys.stdout.write(output)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if args.step_summary and summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("```text\n" + output + "```\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
