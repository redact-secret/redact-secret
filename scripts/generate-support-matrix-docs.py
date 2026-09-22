#!/usr/bin/env python3
"""Project the generated support matrix into docs, README, and release notes
(issue #510, A9; part of #500).

`redact-secret-benchmarks` owns evaluation truth and produces
`support-matrix.json` -- one status (`stable` / `provisional` / `pending` /
`unsupported`) per provider x credential-family taxonomy entry, generated
from benchmark evidence (that repository's #509/A8). Nothing here re-derives
or hand-adjusts a status. Because that artifact is a gitignored build output
in the benchmark repository, this repository keeps its own pinned, committed
copy -- `benchmarks/support-matrix.json` -- the same pattern already used for
`benchmarks/pin-manifest.json` (`scripts/check-benchmark-pins.py`; every
vendored file is listed in `benchmarks/README.md`). Refresh it
by regenerating `support-matrix.json` in a `redact-secret-benchmarks` checkout
(`npm run eval:classify && npm run eval:matrix`) and copying the result here,
then re-running this script.

This script has three outputs, all derived from that one pinned file so a
status change in the matrix reaches every surface without further editing:

  docs/support-matrix.md   The full per-family table, with what each status
                            means for a user, and unsupported families shown
                            with their reason (never silently absent).
  README.md                A short "Support status" summary, injected between
                            `<!-- support-matrix:start -->` /
                            `<!-- support-matrix:end -->` markers.
  --release-note            A Markdown fragment for the next release's
                            changelog entry: the status distribution and what
                            moved since a previous pinned matrix (`--previous`).

    python3 -B scripts/generate-support-matrix-docs.py --check
    python3 -B scripts/generate-support-matrix-docs.py
    python3 -B scripts/generate-support-matrix-docs.py --release-note \\
        --previous <(git show v0.1.0-beta.5:benchmarks/support-matrix.json)

Output is deterministic given its input: stable insertion order (the matrix's
own family order), no timestamps, no network access.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "benchmarks" / "support-matrix.json"
SCHEMA_PATH = ROOT / "benchmarks" / "support-matrix-schema.json"
DOC_PATH = ROOT / "docs" / "support-matrix.md"
README_PATH = ROOT / "README.md"

README_START = "<!-- support-matrix:start -->"
README_END = "<!-- support-matrix:end -->"

STATUS_ORDER = ("stable", "provisional", "pending", "unsupported")

STATUS_COPY = {
    "stable": (
        "Officially supported. Provider-documented (T1) contract, negative "
        "twins, benign controls, metamorphic and mutation evidence, with no "
        "unresolved critical disagreement. You can rely on this family's "
        "detection and its precision behavior."
    ),
    "provisional": (
        "Useful today, but the evidence behind it is incomplete -- typically "
        "a T2, tool-corroborated contract rather than a provider-documented "
        "(T1) one. Provisional is not \"almost stable\": it is a distinct, "
        "load-bearing evidence state that can persist indefinitely if a "
        "provider never publishes a documented format."
    ),
    "pending": (
        "No stable positive contract exists yet (T0): no fixture for this "
        "family has cleared review. Do not rely on this family's detection "
        "or its absence."
    ),
    "unsupported": (
        "This project explicitly does not detect this credential family. "
        "The reason is stated per family below -- a related family is "
        "covered instead, the shape has no reviewed contract, and so on -- "
        "rather than the family being silently absent from this document."
    ),
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_matrix(matrix: dict, schema: dict) -> list[str]:
    """Structural checks independent of `generate-support-matrix.ts`'s own
    guarantees: this is the second line of defense against a pinned copy that
    was hand-edited or copied from a stale/broken generator run."""
    errors: list[str] = []
    vocabulary = schema["properties"]["families"]["items"]["properties"]["status"]["enum"]
    distribution_keys = list(schema["properties"]["distribution"]["properties"])
    if sorted(vocabulary) != sorted(distribution_keys):
        errors.append(
            f"benchmarks/support-matrix-schema.json disagrees with itself: "
            f"status enum {sorted(vocabulary)} vs distribution keys {sorted(distribution_keys)}"
        )
    if sorted(vocabulary) != sorted(STATUS_ORDER):
        errors.append(
            f"benchmarks/support-matrix-schema.json vocabulary {sorted(vocabulary)} no longer "
            f"matches this script's STATUS_ORDER {sorted(STATUS_ORDER)}; STATUS_COPY needs updating"
        )

    families = matrix.get("families", [])
    for family in families:
        status = family.get("status")
        if status not in vocabulary:
            errors.append(f"{family.get('family', '<unknown>')}: status {status!r} is not in the matrix vocabulary")
        if status not in ("stable",) and not family.get("reason"):
            errors.append(f"{family.get('family', '<unknown>')}: status {status!r} carries no reason")

    if matrix.get("familyCount") != len(families):
        errors.append(f"familyCount {matrix.get('familyCount')} != {len(families)} families present")

    actual_distribution = {status: 0 for status in vocabulary}
    for family in families:
        if family.get("status") in actual_distribution:
            actual_distribution[family["status"]] += 1
    if matrix.get("distribution") != actual_distribution:
        errors.append(
            f"distribution {matrix.get('distribution')} does not match the families actually "
            f"present {actual_distribution}"
        )

    actual_providers = {family["provider"] for family in families if family.get("provider")}
    if matrix.get("providerCount") != len(actual_providers):
        errors.append(f"providerCount {matrix.get('providerCount')} != {len(actual_providers)} distinct providers")

    return errors


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_matrix_markdown(matrix: dict) -> str:
    families = matrix["families"]
    lines = [
        "# Support matrix",
        "",
        "Generated by `scripts/generate-support-matrix-docs.py` from the pinned "
        "`benchmarks/support-matrix.json` (issue #510, A9; part of #500). Do not edit by hand --",
        "regenerate with:",
        "",
        "```sh",
        "python3 -B scripts/generate-support-matrix-docs.py",
        "```",
        "",
        "`npm run ci` fails if this file, or the README support-status section, is out of date "
        "with `benchmarks/support-matrix.json`. That file is itself a pinned copy of "
        "`redact-secret-benchmarks`'s generated evidence "
        "([source revision](https://github.com/redact-secret/redact-secret-benchmarks/commit/"
        f"{matrix['sourceReport']['revision']})); see the module docstring for how to refresh it.",
        "",
        f"{matrix['providerCount']} providers, {matrix['familyCount']} credential families.",
        "",
        "## What each status means",
        "",
    ]
    distribution = matrix["distribution"]
    for status in STATUS_ORDER:
        lines.append(f"### `{status}` ({distribution.get(status, 0)})")
        lines.append("")
        lines.append(STATUS_COPY[status])
        lines.append("")

    by_status: dict[str, list[dict]] = {status: [] for status in STATUS_ORDER}
    for family in families:
        by_status.setdefault(family["status"], []).append(family)

    lines.append("## Families")
    lines.append("")
    for status in STATUS_ORDER:
        entries = sorted(by_status.get(status, []), key=lambda f: (f["provider"] or "", f["family"]))
        lines.append(f"### {status.capitalize()}")
        lines.append("")
        if not entries:
            lines.append("None.")
            lines.append("")
            continue
        rows = []
        for family in entries:
            rows.append(
                [
                    _escape_cell(family["provider"] or "(format)"),
                    _escape_cell(family["familyName"]),
                    _escape_cell(family["evidenceTier"] or "—"),
                    _escape_cell(", ".join(family["detectors"]) or "—"),
                    _escape_cell(family["reason"] or "—"),
                ]
            )
        lines.append(_markdown_table(["Provider", "Family", "Evidence tier", "Detector(s)", "Reason"], rows))
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def render_readme_fragment(matrix: dict) -> str:
    distribution = matrix["distribution"]
    counts = ", ".join(f"{status}: {distribution.get(status, 0)}" for status in STATUS_ORDER)
    lines = [
        README_START,
        f"**Support status** ({matrix['providerCount']} providers, {matrix['familyCount']} credential "
        f"families; {counts}) -- generated from evaluation evidence, never hand-written. "
        "`provisional` means useful but evidence-incomplete, not \"almost stable\"; unsupported "
        "families are listed with their reason. See the full "
        "[support matrix](docs/support-matrix.md).",
        README_END,
    ]
    return "\n".join(lines)


def inject_readme_fragment(readme_text: str, fragment: str) -> str:
    start = readme_text.find(README_START)
    end = readme_text.find(README_END)
    if start == -1 or end == -1:
        raise ValueError(
            f"README.md is missing the {README_START} / {README_END} markers; "
            "add them once under the 'Detection coverage' section, then regenerate"
        )
    end += len(README_END)
    return readme_text[:start] + fragment + readme_text[end:]


def render_release_note(matrix: dict, previous: dict | None) -> str:
    """A fragment meant for the dated `CHANGELOG.md` entry (this repository's
    release notes; see docs/releasing.md), not `docs/releases/<version>/README.md`,
    which records publication evidence rather than product-facing notes."""
    distribution = matrix["distribution"]
    lines = [
        "### Support status",
        "",
        f"{matrix['providerCount']} providers, {matrix['familyCount']} credential families: "
        + ", ".join(f"{status} {distribution.get(status, 0)}" for status in STATUS_ORDER)
        + ". See the [support matrix](docs/support-matrix.md).",
    ]
    if previous is None:
        lines.append("")
        lines.append("No previous pinned matrix was given to diff against.")
        return "\n".join(lines) + "\n"

    previous_by_family = {f["family"]: f["status"] for f in previous["families"]}
    current_by_family = {f["family"]: f["status"] for f in matrix["families"]}
    moved = sorted(
        (family, previous_by_family[family], current_by_family[family])
        for family in set(previous_by_family) & set(current_by_family)
        if previous_by_family[family] != current_by_family[family]
    )
    added = sorted(set(current_by_family) - set(previous_by_family))
    removed = sorted(set(previous_by_family) - set(current_by_family))

    lines.append("")
    if moved:
        lines.append("Moved since the previous release:")
        lines.extend(f"- `{family}`: {old} -> {new}" for family, old, new in moved)
    else:
        lines.append("No family's status moved since the previous release.")
    if added:
        lines.append("")
        lines.append("New families tracked: " + ", ".join(f"`{f}`" for f in added) + ".")
    if removed:
        lines.append("")
        lines.append("Families no longer tracked: " + ", ".join(f"`{f}`" for f in removed) + ".")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--doc-out", type=Path, default=DOC_PATH)
    parser.add_argument("--readme", type=Path, default=README_PATH)
    parser.add_argument("--check", action="store_true", help="fail if docs/support-matrix.md or README.md are out of date; write nothing")
    parser.add_argument("--release-note", action="store_true", help="print the release-note fragment to stdout instead of writing docs")
    parser.add_argument("--previous", type=Path, default=None, help="a previous support-matrix.json to diff against, for --release-note")
    args = parser.parse_args(argv)

    matrix = load_json(args.matrix)
    schema = load_json(args.schema)
    errors = validate_matrix(matrix, schema)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"\n{len(errors)} error(s) in {args.matrix}", file=sys.stderr)
        return 1

    if args.release_note:
        previous = load_json(args.previous) if args.previous is not None else None
        sys.stdout.write(render_release_note(matrix, previous))
        return 0

    doc_text = render_matrix_markdown(matrix)
    readme_text = args.readme.read_text(encoding="utf-8")
    fragment = render_readme_fragment(matrix)
    new_readme_text = inject_readme_fragment(readme_text, fragment)

    if args.check:
        problems = []
        if not args.doc_out.exists() or args.doc_out.read_text(encoding="utf-8") != doc_text:
            problems.append(
                f"{args.doc_out} is out of date; regenerate with "
                "`python3 -B scripts/generate-support-matrix-docs.py`"
            )
        if readme_text != new_readme_text:
            problems.append(
                f"{args.readme} support-status section is out of date; regenerate with "
                "`python3 -B scripts/generate-support-matrix-docs.py`"
            )
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        if problems:
            print(f"\n{len(problems)} error(s)", file=sys.stderr)
        return 1 if problems else 0

    args.doc_out.write_text(doc_text, encoding="utf-8")
    args.readme.write_text(new_readme_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
