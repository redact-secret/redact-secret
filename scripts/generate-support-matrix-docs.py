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
                            moved since a previous pinned matrix (`--previous`),
                            but only when that matrix is a like-for-like
                            baseline (see `baseline_problem`). Otherwise the
                            fragment says the baseline is not comparable.

`--check` also requires each committed `docs/releases/<version>/support-status.md`
fragment to equal the `### Support status` section of that version's CHANGELOG
entry (issue #724): the fragment is the source, the CHANGELOG copies it.

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
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "benchmarks" / "support-matrix.json"
SCHEMA_PATH = ROOT / "benchmarks" / "support-matrix-schema.json"
DOC_PATH = ROOT / "docs" / "support-matrix.md"
README_PATH = ROOT / "README.md"
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
RELEASES_DIR = ROOT / "docs" / "releases"
FRAGMENT_NAME = "support-status.md"

README_START = "<!-- support-matrix:start -->"
README_END = "<!-- support-matrix:end -->"

STATUS_ORDER = ("stable", "provisional", "pending", "unsupported")
EVIDENCE_TIER_ORDER = ("T1", "T2", "T3", "T0")
QUALIFICATION_PROFILE_ORDER = ("documented", "empirical")

# The evidence bases a T2 family may carry under the `empirical` qualification
# profile. redact-secret-benchmarks' decision
# `decision-qualify-empirical-stable-by-corroboration` (benchmarks e1ecb29)
# added the corroborated route beside the provider-issued observation route;
# the tier stays T2 either way.
EMPIRICAL_EVIDENCE_BASES = ("independently-corroborated", "empirically-observed")

EVIDENCE_BASIS_COPY = {
    "provider-documented": "Provider documentation",
    "independently-corroborated": "Independent tool/community corroboration",
    "empirically-observed": "Provider-issued observation",
    "project-policy": "Project policy",
    "none": "None",
}

STATUS_COPY = {
    "stable": (
        "Officially supported. The family qualified in one of two ways: its format is "
        "documented by the provider (`documented`), or several independent sources "
        "corroborate it or it was checked against keys the provider actually issued, "
        "with stricter test and behavior checks (`empirical`). "
        "An empirically qualified family is never described as provider-documented. You "
        "can rely on this family's detection and its precision behavior. Stable does not "
        "mean every historical or future variant of this credential is detected -- see "
        "each family's supported contexts and known limitations below."
    ),
    "provisional": (
        "Useful today, but the evidence behind it is incomplete -- usually the format "
        "is confirmed by other scanners or by public examples rather than by the "
        "provider's own documentation. Provisional is not \"almost stable\": it can "
        "stay this way indefinitely if a provider never publishes its format. The "
        "Reason column says what is still missing."
    ),
    "pending": (
        "No reviewed detection contract exists yet: nothing about this family's "
        "detection has been verified. Do not rely on this family's detection or its "
        "absence."
    ),
    "unsupported": (
        "This project explicitly does not detect this credential family. "
        "The reason is stated per family below -- a related family is "
        "covered instead, the shape has no reviewed contract, and so on -- "
        "rather than the family being silently absent from this document."
    ),
}

# Issue #723: each evaluator gate in a non-stable family's raw `reason`
# belongs to one user-facing group. The Markdown shows the groups; the raw
# reason stays unchanged in `benchmarks/support-matrix.json`.
REASON_GATE_GROUPS = {
    "empirical.evidenceBasis": "observations",
    "empirical.minimumObservations": "observations",
    "empirical.minimumSubjects": "observations",
    "empirical.minimumIssuanceDates": "observations",
    "empirical.minimumCorroborationClasses": "observations",
    "empirical.corroborated.minimumReferences": "corroboration",
    "empirical.corroborated.minimumOwners": "corroboration",
    "empirical.corroborated.minimumClasses": "corroboration",
    "empirical.unresolvedContradictions": "contradictions",
    "documented.providerSource": "source",
    "documented.minimumPositiveCases": "positives",
    "documented.minimumPositiveAxes": "positives",
    "empirical.minimumPositiveCases": "positives",
    "empirical.minimumPositiveAxes": "positives",
    "documented.minimumBenignCases": "controls",
    "documented.minimumControlAxes": "controls",
    "empirical.minimumBenignCases": "controls",
    "empirical.minimumControlAxes": "controls",
    "documented.minimumTwinPairs": "twins",
    "empirical.minimumTwinPairs": "twins",
    "empirical.contextConstrained.minimumContextTwinPairs": "twins",
    "empirical.contextConstrained.minimumConfusionAxes": "controls",
    "empirical.contextConstrained.minimumFixtures": "fixtures",
    "empirical.contextConstrained.supportsBareValues": "boundary",
    "empirical.supportedContexts": "boundary",
    "empirical.mode": "boundary",
    "empirical.uncertainty": "boundary",
    "qualificationProfile": "policy",
    "positiveContractTier": "no-contract",
}

# A `fixtureProfile <profile>: <actual> <cell> < <required> (<n> short)`
# segment names fixture-profile debt (redact-secret-benchmarks'
# `benchmarks/support/profiles.ts`); its cell label maps to a group here. Any
# other `fixtureProfile` segment is unmapped and fails like an unknown gate.
FIXTURE_PROFILE_DEBT = re.compile(
    r"^fixtureProfile [a-z-]+: \d+ (?P<cell>[a-z/ -]+?) < \d+ \(\d+ short\)$"
)
FIXTURE_PROFILE_CELL_GROUPS = {
    "total fixtures": "fixtures",
    "positive/context cases": "positives",
    "positive-context axes": "positives",
    "non-twin benign controls": "controls",
    "control axes": "controls",
    "confusion axes": "controls",
    "twin pairs": "twins",
}

# The user-facing text for each group, in rendering order. The corroborated
# and observed empirical routes are alternatives (benchmarks
# decision-qualify-empirical-stable-by-corroboration); when the corroborated
# route is short, `user_facing_reason` names both routes in one phrase instead
# of listing observations as a separate need.
REASON_GROUP_COPY = (
    ("corroboration", "independent corroboration of its format (several sources, or provider-issued keys)"),
    ("observations", "independent observations of provider-issued keys"),
    ("source", "a provider-documented source"),
    ("contradictions", "its conflicting format evidence settled"),
    ("positives", "broader positive test contexts"),
    ("controls", "more benign controls"),
    ("twins", "more near-miss twin pairs"),
    ("fixtures", "more test fixtures overall"),
    ("boundary", "a defined supported-context boundary with its uncertainty stated"),
)

# A raw reason segment that names an evaluator gate: `profile.gate: ...`,
# `qualificationProfile: ...` or `positiveContractTier T0 ...`.
GATE_SEGMENT = re.compile(r"^(?:(?P<dotted>[a-z][A-Za-z]*\.[A-Za-z.]+):|(?P<bare>[a-z][A-Za-z]+)(?=[: ]))")


def user_facing_reason(reason: str) -> str:
    """The concise Reason cell for a raw evaluator `reason` (issue #723).

    Gate segments (split on ` | `) are grouped through
    [`REASON_GATE_GROUPS`] into one sentence; free-text segments, such as an
    unsupported family's written reason, are kept verbatim. A gate
    identifier the table does not know raises `ValueError`, so evaluator
    syntax never leaks into published documentation unreviewed.
    """
    groups: list[str] = []
    free_text: list[str] = []
    for segment in (part.strip() for part in reason.split(" | ")):
        if segment.startswith("fixtureProfile "):
            debt = FIXTURE_PROFILE_DEBT.match(segment)
            group = debt and FIXTURE_PROFILE_CELL_GROUPS.get(debt.group("cell"))
            if not group:
                raise ValueError(
                    f"unmapped support-matrix gate {segment.split(':', 1)[0]!r}; add it to "
                    "FIXTURE_PROFILE_CELL_GROUPS in scripts/generate-support-matrix-docs.py"
                )
            if group not in groups:
                groups.append(group)
            continue
        match = GATE_SEGMENT.match(segment)
        gate = match and (match.group("dotted") or match.group("bare"))
        if gate and ("." in gate or gate in REASON_GATE_GROUPS or segment.startswith(gate + ":")):
            if gate not in REASON_GATE_GROUPS:
                raise ValueError(
                    f"unmapped support-matrix gate {gate!r}; add it to REASON_GATE_GROUPS in "
                    "scripts/generate-support-matrix-docs.py with a user-facing group"
                )
            group = REASON_GATE_GROUPS[gate]
            if group not in groups:
                groups.append(group)
        else:
            free_text.append(segment)

    if not groups:
        return reason
    sentences: list[str] = []
    if "no-contract" in groups:
        sentences.append("No reviewed detection contract is available yet.")
    if "policy" in groups:
        sentences.append(
            "Detected under project policy rather than a provider format, so it is not "
            "eligible for stable qualification."
        )
    if "corroboration" in groups and "observations" in groups:
        groups.remove("observations")
    needs = [copy for group, copy in REASON_GROUP_COPY if group in groups]
    if needs:
        listed = needs[0] if len(needs) == 1 else ", ".join(needs[:-1]) + " and " + needs[-1]
        sentences.append(f"Not yet stable: needs {listed}.")
    if free_text:
        sentences.append(" | ".join(free_text))
    return " ".join(sentences)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_matrix(matrix: dict, schema: dict) -> list[str]:
    """Structural checks independent of `generate-support-matrix.ts`'s own
    guarantees: this is the second line of defense against a pinned copy that
    was hand-edited or copied from a stale/broken generator run."""
    errors: list[str] = []
    family_properties = schema["properties"]["families"]["items"]["properties"]
    vocabulary = family_properties["status"]["enum"]
    evidence_tiers = family_properties["evidenceTier"]["enum"]
    evidence_bases = family_properties["evidenceBasis"]["enum"]
    qualification_profiles = family_properties["qualificationProfile"]["enum"]
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
        name = family.get("family", "<unknown>")
        status = family.get("status")
        if status not in vocabulary:
            errors.append(f"{name}: status {status!r} is not in the matrix vocabulary")
        if status not in ("stable",) and not family.get("reason"):
            errors.append(f"{name}: status {status!r} carries no reason")
        tier = family.get("evidenceTier")
        basis = family.get("evidenceBasis")
        profile = family.get("qualificationProfile")
        if tier not in evidence_tiers:
            errors.append(f"{name}: evidence tier {tier!r} is not in the matrix vocabulary")
        if basis not in evidence_bases:
            errors.append(f"{name}: evidence basis {basis!r} is not in the matrix vocabulary")
        if profile not in qualification_profiles:
            errors.append(f"{name}: qualification profile {profile!r} is not in the matrix vocabulary")
        if status == "stable" and profile is None:
            errors.append(f"{name}: stable carries no qualification profile")
        if status != "stable" and profile is not None:
            errors.append(f"{name}: {status!r} carries qualification profile {profile!r}")
        if profile == "documented" and (tier != "T1" or basis != "provider-documented"):
            errors.append(f"{name}: documented qualification must remain T1 provider-documented evidence")
        if profile == "empirical" and (tier != "T2" or basis not in EMPIRICAL_EVIDENCE_BASES):
            errors.append(
                f"{name}: empirical qualification must remain T2 independently-corroborated "
                "or empirically-observed evidence"
            )

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

    actual_stable_distribution = {
        profile: sum(
            family.get("status") == "stable" and family.get("qualificationProfile") == profile
            for family in families
        )
        for profile in QUALIFICATION_PROFILE_ORDER
    }
    if matrix.get("stableDistribution") != actual_stable_distribution:
        errors.append(
            f"stableDistribution {matrix.get('stableDistribution')} does not match the stable families actually "
            f"present {actual_stable_distribution}"
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


def _tier_counts(matrix: dict) -> dict[str, int]:
    counts = {tier: 0 for tier in EVIDENCE_TIER_ORDER}
    counts["none"] = 0
    for family in matrix["families"]:
        counts[family.get("evidenceTier") or "none"] += 1
    return counts


def _support_label(family: dict) -> str:
    status = family["status"]
    profile = family.get("qualificationProfile")
    basis = family.get("evidenceBasis")
    if status == "stable" and profile == "documented":
        return "Stable · Provider documented"
    if status == "stable" and profile == "empirical":
        return "Stable · Empirically qualified"
    if status == "provisional" and basis == "independently-corroborated":
        return "Provisional · Tool corroborated"
    if status == "provisional":
        return f"Provisional · {EVIDENCE_BASIS_COPY[basis]}"
    return status.capitalize()


def render_matrix_markdown(matrix: dict) -> str:
    families = matrix["families"]
    revision = matrix["sourceReport"]["revision"]
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
        f"{revision})); see the module docstring for how to refresh it.",
        "",
        f"{matrix['providerCount']} providers, {matrix['familyCount']} credential families.",
        "",
        "Support status, evidence provenance, and qualification are separate dimensions. "
        "In particular, a T2 family may be stable through the empirical profile without "
        "being described as provider-documented or rewritten as T1. User-facing labels combine "
        "the dimensions without conflating them: `Stable · Provider documented`, "
        "`Stable · Empirically qualified`, and `Provisional · Tool corroborated`.",
        "",
        "For the detailed measurement protocol behind these statuses -- evidence tiers, and "
        "the twin, benign, metamorphic, mutation, and differential criteria a family must clear "
        "-- see `redact-secret-benchmarks`'s "
        f"[support-status specification](https://github.com/redact-secret/redact-secret-benchmarks/blob/{revision}/docs/specs/support-status.md). "
        "You do not need to read it to use this table.",
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

    stable_distribution = matrix["stableDistribution"]
    tier_counts = _tier_counts(matrix)
    lines.extend(
        [
            "## Evidence and qualification counts",
            "",
            "Stable qualification profiles:",
            "",
            _markdown_table(
                ["Qualification profile", "Stable families"],
                [[profile.capitalize(), str(stable_distribution[profile])] for profile in QUALIFICATION_PROFILE_ORDER],
            ),
            "",
            "Evidence tiers across all families:",
            "",
            _markdown_table(
                ["Evidence tier", "Families"],
                [[tier, str(tier_counts[tier])] for tier in EVIDENCE_TIER_ORDER]
                + [["No reviewed tier", str(tier_counts["none"])]],
            ),
            "",
        ]
    )

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
                    _escape_cell(_support_label(family)),
                    _escape_cell(family["evidenceTier"] or "—"),
                    _escape_cell(EVIDENCE_BASIS_COPY[family["evidenceBasis"]]),
                    _escape_cell((family.get("qualificationProfile") or "—").capitalize()),
                    _escape_cell(", ".join(family["detectors"]) or "—"),
                    _escape_cell(_last_column(family, status)),
                ]
            )
        last_header = "Supported contexts & known limitations" if status == "stable" else "Reason"
        lines.append(
            _markdown_table(
                [
                    "Provider",
                    "Family",
                    "Support",
                    "Evidence tier",
                    "Evidence basis",
                    "Qualification profile",
                    "Detector(s)",
                    last_header,
                ],
                rows,
            )
        )
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _last_column(family: dict, status: str) -> str:
    """For `stable` families, the table's fifth column names supported
    contexts and known limitations instead of a reason (`stable` carries no
    `reason` -- see `validate_matrix`), drawn from the T1 `providerSource`
    evidence required to reach `stable` at all. Every other status shows its
    recorded `reason` through `user_facing_reason`."""
    if status != "stable":
        return user_facing_reason(family["reason"]) if family["reason"] else "—"
    provider_source = family.get("providerSource")
    if provider_source and provider_source.get("covers"):
        return provider_source["covers"]
    empirical = family.get("empiricalEvidence")
    if empirical:
        details = []
        if empirical.get("supportedContexts"):
            details.append("supported contexts: " + ", ".join(empirical["supportedContexts"]))
        if empirical.get("uncertainty"):
            details.append("uncertainty: " + empirical["uncertainty"])
        if details:
            return "; ".join(details)
    return "not recorded in the pinned evidence"


def render_readme_fragment(matrix: dict) -> str:
    distribution = matrix["distribution"]
    stable_distribution = matrix["stableDistribution"]
    tier_counts = _tier_counts(matrix)
    counts = ", ".join(f"{status}: {distribution.get(status, 0)}" for status in STATUS_ORDER)
    profile_counts = ", ".join(
        f"{profile}: {stable_distribution[profile]}" for profile in QUALIFICATION_PROFILE_ORDER
    )
    evidence_counts = ", ".join(f"{tier}: {tier_counts[tier]}" for tier in EVIDENCE_TIER_ORDER)
    lines = [
        README_START,
        f"**Support status** ({matrix['providerCount']} providers, {matrix['familyCount']} credential "
        f"families; {counts}; stable qualification: {profile_counts}; evidence tiers: {evidence_counts}) "
        "-- generated from evaluation evidence, never hand-written. Stable families are labeled "
        "`Stable · Provider documented` or `Stable · Empirically qualified`; empirical qualification remains T2. "
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


def _move_tag(old_status: str, new_status: str) -> str:
    """Labels a status move as a regression or improvement exactly when it
    crosses the `stable` boundary, matching `check-support-matrix-drift.py`'s
    own regression/improvement vocabulary so a reader sees the same word for
    the same kind of change in both places."""
    if old_status == "stable" and new_status != "stable":
        return " (regression)"
    if new_status == "stable" and old_status != "stable":
        return " (improvement)"
    return ""


def baseline_problem(matrix: dict, previous: dict) -> str | None:
    """Why `previous` is not a like-for-like baseline for `matrix`, or None.

    Like-for-like means the previous release's *published package* measured
    on the same corpus and scanner pins as `matrix`. Every measurement is
    keyed to one `redact-secret-benchmarks` revision, so a different
    `sourceReport.revision` is a different corpus/ledger/pin set, and a
    `sourceReport.product` block marks a candidate-build measurement rather
    than a published package. Either makes a status diff misleading (beta.6's
    3 stable were measured under an earlier corpus and ledger; the same
    package measured on beta.7's corpus is 43, #584)."""
    if "product" in previous["sourceReport"]:
        return "it measured a candidate build, not the published previous release"
    old, new = previous["sourceReport"]["revision"], matrix["sourceReport"]["revision"]
    if old != new:
        return (
            f"it was measured at benchmarks revision {old[:12]}, not the candidate's {new[:12]}, "
            "so corpus and scanner pins differ"
        )
    return None


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
        + ". See the [support matrix](/docs/support-matrix.md).",
        "",
        "Stable qualification: "
        + ", ".join(
            f"{profile} {matrix['stableDistribution'][profile]}" for profile in QUALIFICATION_PROFILE_ORDER
        )
        + ". Evidence tiers: "
        + ", ".join(f"{tier} {_tier_counts(matrix)[tier]}" for tier in EVIDENCE_TIER_ORDER)
        + ".",
    ]
    if previous is None:
        lines.append("")
        lines.append("No previous pinned matrix was given to diff against.")
        return "\n".join(lines) + "\n"

    problem = baseline_problem(matrix, previous)
    if problem is not None:
        lines.append("")
        lines.append(
            "The previous pinned matrix is not comparable, so no stable delta is stated: "
            f"{problem}."
        )
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

    previous_stable = previous["distribution"].get("stable", 0)
    current_stable = distribution.get("stable", 0)
    lines.append("")
    lines.append(
        "Baseline: the previous release's published package measured on this corpus and "
        f"scanner pins (benchmarks revision {matrix['sourceReport']['revision'][:12]})."
    )
    lines.append("")
    lines.append(
        f"Stable: {current_stable} ({current_stable - previous_stable:+d} from {previous_stable})."
    )

    lines.append("")
    if moved:
        lines.append("Moved since the previous release:")
        lines.extend(f"- `{family}`: {old} -> {new}{_move_tag(old, new)}" for family, old, new in moved)
    else:
        lines.append("No family's status moved since the previous release.")
    if added:
        lines.append("")
        lines.append("New families tracked: " + ", ".join(f"`{f}`" for f in added) + ".")
    if removed:
        lines.append("")
        lines.append("Families no longer tracked: " + ", ".join(f"`{f}`" for f in removed) + ".")
    return "\n".join(lines) + "\n"


def changelog_section(changelog: str, version: str) -> str | None:
    """The `### Support status` block of `## <version>` in the CHANGELOG, as
    text ending in one newline, or None when the version or block is absent."""
    entry = re.search(rf"^## {re.escape(version)}(?: .*)?$", changelog, re.M)
    if entry is None:
        return None
    rest = changelog[entry.end():]
    next_entry = re.search(r"^## ", rest, re.M)
    body = rest[: next_entry.start()] if next_entry else rest
    heading = re.search(r"^### Support status$", body, re.M)
    if heading is None:
        return None
    tail = body[heading.start():]
    following = re.search(r"^### ", tail[len("### Support status"):], re.M)
    block = tail[: len("### Support status") + following.start()] if following else tail
    return block.rstrip("\n") + "\n"


def check_changelog_fragments(changelog_path: Path, releases_dir: Path) -> list[str]:
    changelog = changelog_path.read_text(encoding="utf-8")
    problems = []
    for fragment_path in sorted(releases_dir.glob(f"*/{FRAGMENT_NAME}")):
        version = fragment_path.parent.name
        actual = changelog_section(changelog, version)
        if actual != fragment_path.read_text(encoding="utf-8"):
            problems.append(
                f"{changelog_path.name} `## {version}` support-status section differs from "
                f"{fragment_path.relative_to(ROOT) if fragment_path.is_relative_to(ROOT) else fragment_path}; "
                "the fragment is the source -- copy it into the CHANGELOG entry"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2] if __doc__ else "")
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--doc-out", type=Path, default=DOC_PATH)
    parser.add_argument("--readme", type=Path, default=README_PATH)
    parser.add_argument("--changelog", type=Path, default=CHANGELOG_PATH)
    parser.add_argument("--releases-dir", type=Path, default=RELEASES_DIR)
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
        problems.extend(check_changelog_fragments(args.changelog, args.releases_dir))
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
