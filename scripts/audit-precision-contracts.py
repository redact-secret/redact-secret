#!/usr/bin/env python3
"""Audit the reviewed precision contracts frozen by issue #367.

Issue #367 freezes, for seven provider families (OpenAI, DigitalOcean, Docker,
Slack, Hugging Face, Cloudflare, Linear), the reviewed lexical contract each
default detector must enforce, the beta.4 negative-twin baseline those
contracts were measured against, and an audit of every fixture this
repository already ships for those families. The contract text is a live
input CI reads on every run, so it lives outside the frozen-evidence archive
at ``docs/contracts/precision/precision-contracts.json``
(``decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement``);
this script derives the two evidence files still frozen under
``docs/audits/evidence/367/`` and keeps them honest:

``beta4-twin-baseline.json``
    The 24 must-not-flag twins and their 24 paired positives from the beta.4
    ``common-formats`` benchmark snapshot. Each fixture is frozen by its
    deterministic construction recipe (the benchmark generator's public
    SHA-256 seed formula), its content SHA-256 and byte length, its
    assessment, its expected ranges, and the ranges beta.4 actually
    produced (copied from the self-contained snapshots in issues #368-#374).
    The literal credential-shaped strings are deliberately not committed:
    they are reconstructed bit-for-bit from the recipe on demand
    (``--print-fixture``) so the repository never carries push-protected
    lookalikes, while ``--check`` still proves the recipe reproduces the
    recorded hashes and ranges.

``corpus-audit.json``
    Every fixture in ``conformance/fixtures/synchronous-corpus.json``,
    ``conformance/fixtures/incremental-corpus.json``,
    ``assessment/fixtures/accuracy-corpus.json`` and every
    ``reconciliationTrigger`` in ``docs/coverage/detector-inventory.json``
    that names one of the seven detectors, evaluated against the frozen
    contract: which positives survive unchanged, which broad-shape positives
    the child fixes must re-author or reclassify, and which negatives stay
    silent.

The contract grammars are reference oracles for review. They are not a
detector and never run inside a scan; the Rust core remains the only
authoritative implementation (``ARCHITECTURE.md``, deliberate exclusions).
Like the other coverage generators, the audit output never contains a
fixture's input or a matched value: only ids, kinds, tiers, contexts,
ranges, dispositions and hashes.

    python3 -B scripts/audit-precision-contracts.py --check
    python3 -B scripts/audit-precision-contracts.py --write
    python3 -B scripts/audit-precision-contracts.py --print-fixture openai-token-legacy-plain-twin
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "docs" / "contracts" / "precision"
CONTRACTS_PATH = CONTRACTS_DIR / "precision-contracts.json"
EVIDENCE_DIR = ROOT / "docs" / "audits" / "evidence" / "367"
BASELINE_PATH = EVIDENCE_DIR / "beta4-twin-baseline.json"
CORPUS_AUDIT_PATH = EVIDENCE_DIR / "corpus-audit.json"

SYNCHRONOUS_CORPUS = ROOT / "conformance" / "fixtures" / "synchronous-corpus.json"
INCREMENTAL_CORPUS = ROOT / "conformance" / "fixtures" / "incremental-corpus.json"
ACCURACY_CORPUS = ROOT / "assessment" / "fixtures" / "accuracy-corpus.json"
DETECTOR_INVENTORY = ROOT / "docs" / "coverage" / "detector-inventory.json"

BOUNDARY_CLASS = "[A-Za-z0-9_-]"

# The benchmark generator's public alphabets (redact-secret-benchmarks
# fixtures/generated/build.mjs and common-formats.mjs). Values built from
# them are synthetic by construction and were never provider-issued.
ALPHABETS = {
    "alnum": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "letters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "hex": "0123456789abcdef",
    "digits": "0123456789",
}
SEED_FORMAT = "secret-benchmark:never-issued:v2:{label}:{block}"
CONTEXTS = {
    "plain": {"before": "", "after": "\n"},
    "unicode-crlf": {"before": "# \U0001F511 reviewed format\r\n", "after": "\r\n"},
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# --- synthetic reconstruction -------------------------------------------------


def synthetic(label: str, length: int, alphabet: str = "alnum") -> str:
    """Port of the benchmark generator's ``synthetic(label, length, chars)``."""
    chars = ALPHABETS[alphabet]
    value = ""
    block = 0
    while len(value) < length:
        digest = hashlib.sha256(
            SEED_FORMAT.format(label=label, block=block).encode("utf-8")
        ).digest()
        value += "".join(chars[byte % len(chars)] for byte in digest)
        block += 1
    return value[:length]


def render_token(parts: list[dict]) -> str:
    rendered = []
    for part in parts:
        if "literal" in part:
            rendered.append(part["literal"])
            continue
        spec = part["synthetic"]
        value = synthetic(spec["label"], spec["length"], spec.get("alphabet", "alnum"))
        rendered.append(value[: spec["take"]] if "take" in spec else value)
    return "".join(rendered)


def render_fixture(construction: dict) -> tuple[str, int, int]:
    """Return ``(content, token_start, token_end)`` in UTF-8 byte offsets."""
    context = CONTEXTS[construction["context"]]
    token = render_token(construction["parts"])
    before = context["before"]
    content = before + token + "\n" + construction.get("extra", "") + context["after"]
    start = len(before.encode("utf-8"))
    return content, start, start + len(token.encode("utf-8"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- contract evaluation ------------------------------------------------------


def compile_family(family: dict) -> re.Pattern[str]:
    alternatives = []
    for variant in family["variants"]:
        alternatives.append(f"(?P<{variant['id'].replace('-', '_')}>{variant['grammar']})")
    body = "|".join(alternatives)
    return re.compile(f"(?<!{BOUNDARY_CLASS})(?:{body})(?!{BOUNDARY_CLASS})")


def find_contract_matches(text: str, pattern: re.Pattern[str]) -> list[dict]:
    """Every non-overlapping contract match as UTF-8 byte ranges."""
    matches = []
    for match in pattern.finditer(text):
        start = len(text[: match.start()].encode("utf-8"))
        end = start + len(match.group(0).encode("utf-8"))
        matches.append({"start": start, "end": end, "variant": match.lastgroup.replace("_", "-")})
    return matches


def family_patterns(contracts: dict) -> dict[str, re.Pattern[str]]:
    """One compiled pattern per family that has adopted at least one variant.

    A family with no `variants` (every class still `pending`, e.g.
    `vercel-token` per issue #516) has no reviewed grammar to check corpus
    fixtures against yet; it is omitted here rather than compiled into an
    empty alternation, which would match everywhere with no named group.
    """
    return {
        family["detector"]: compile_family(family)
        for family in contracts["families"]
        if family["variants"]
    }


# --- beta.4 twin baseline -----------------------------------------------------


def _fixture_view(fixture: dict) -> dict:
    content, start, end = render_fixture(fixture["construction"])
    return {
        "content": content,
        "contentSha256": sha256_hex(content),
        "contentBytes": len(content.encode("utf-8")),
        "tokenRange": {"start": start, "end": end},
    }


def derive_baseline(baseline: dict, contracts: dict) -> tuple[dict, list[str]]:
    """Fill in every derivable field of the baseline and report inconsistencies."""
    patterns = family_patterns(contracts)
    errors: list[str] = []
    derived = json.loads(json.dumps(baseline))
    mutations: dict[str, set[str]] = {}
    for pair in derived["pairs"]:
        family = pair["family"]
        pattern = patterns.get(family)
        if pattern is None:
            errors.append(f"{pair['negative']['id']}: no contract for family {family}")
            continue
        for role in ("positive", "negative"):
            fixture = pair[role]
            view = _fixture_view(fixture)
            fixture["contentSha256"] = view["contentSha256"]
            fixture["contentBytes"] = view["contentBytes"]
            matches = find_contract_matches(view["content"], pattern)
            token_range = view["tokenRange"]
            if role == "positive":
                expected_ranges = [{"start": e["start"], "end": e["end"]} for e in fixture["expected"]]
                if expected_ranges != [token_range]:
                    errors.append(
                        f"{fixture['id']}: expected range {expected_ranges} does not equal the constructed token range {token_range}"
                    )
                actual = [{"start": a["start"], "end": a["end"]} for a in fixture["actualBeta4"]]
                if actual != [token_range]:
                    errors.append(f"{fixture['id']}: recorded beta.4 range {actual} does not equal the constructed token range")
                pair["contractView"] = {
                    "positiveVariant": matches[0]["variant"] if len(matches) == 1 else None,
                    "positiveMatchesExpectedRange": [
                        {"start": m["start"], "end": m["end"]} for m in matches
                    ] == expected_ranges,
                }
            else:
                if fixture["expected"]:
                    errors.append(f"{fixture['id']}: a must-not-flag twin must expect no ranges")
                if not fixture["actualBeta4"]:
                    errors.append(f"{fixture['id']}: a beta.4 twin false alarm must record the beta.4 range")
                pair["contractView"]["twinFlaggedByContract"] = bool(matches)
                pair["contractView"]["twinMutationRetained"] = not matches
                if matches:
                    pair["contractView"]["twinContractMatches"] = matches
                else:
                    pair["contractView"].pop("twinContractMatches", None)
        mutations.setdefault(pair["mutation"], set()).add(pair["negative"]["id"])
    # Issue #367 counts "12 mutations, each in plain and Unicode/CRLF": one
    # mutation per (family, variant) twin, so the same description applied to
    # sibling prefixes (dop/doo/dor, proj/svcacct) counts once per variant.
    twin_variants = {(pair["family"], pair["variant"]) for pair in derived["pairs"]}
    derived["counts"] = {
        "pairs": len(derived["pairs"]),
        "twins": len(derived["pairs"]),
        "pairedPositives": len(derived["pairs"]),
        "uniqueMutations": len(twin_variants),
        "uniqueMutationDescriptions": len(mutations),
        "twinsFlaggedByBeta4": sum(1 for p in derived["pairs"] if p["negative"]["actualBeta4"]),
        "twinsFlaggedByContract": sum(1 for p in derived["pairs"] if p["contractView"]["twinFlaggedByContract"]),
        "positivesPreservedByContract": sum(
            1 for p in derived["pairs"] if p["contractView"]["positiveMatchesExpectedRange"]
        ),
        "perFamily": _per_family_counts(derived["pairs"]),
    }
    return derived, errors


def _per_family_counts(pairs: list[dict]) -> dict:
    counts: dict[str, dict] = {}
    for pair in pairs:
        row = counts.setdefault(pair["family"], {"twins": 0, "uniqueMutations": [], "twinsFlaggedByContract": 0})
        row["twins"] += 1
        if pair["mutation"] not in row["uniqueMutations"]:
            row["uniqueMutations"].append(pair["mutation"])
        if pair["contractView"]["twinFlaggedByContract"]:
            row["twinsFlaggedByContract"] += 1
    for row in counts.values():
        row["uniqueMutations"] = sorted(row["uniqueMutations"])
    return counts


# --- repository corpus audit --------------------------------------------------


def _expected_for(fixture: dict, detector: str) -> list[dict]:
    return [
        {"start": e["start"], "end": e["end"]}
        for e in fixture.get("expected", [])
        if e.get("detector") == detector
    ]


def audit_text(text: str, expected: list[dict], pattern: re.Pattern[str]) -> dict:
    matches = find_contract_matches(text, pattern)
    match_ranges = [{"start": m["start"], "end": m["end"]} for m in matches]
    retained = [e for e in expected if e in match_ranges]
    lost = [e for e in expected if e not in match_ranges]
    unexpected = [m for m in matches if {"start": m["start"], "end": m["end"]} not in expected]
    if expected and not lost and not unexpected:
        disposition = "retained"
    elif expected and lost and not unexpected:
        disposition = "broad-shape"
    elif not expected and not unexpected:
        disposition = "silent"
    else:
        disposition = "review"
    return {
        "disposition": disposition,
        "expectedRanges": expected,
        "retainedRanges": retained,
        "lostRanges": lost,
        "contractOnlyMatches": unexpected,
    }


def _audit_rows(fixtures: list[dict], corpus: str, patterns: dict[str, re.Pattern[str]], text_key: str) -> list[dict]:
    rows = []
    for fixture in fixtures:
        text = fixture[text_key]
        detectors = sorted(
            {fixture.get("detector")} & patterns.keys()
            | {e.get("detector") for e in fixture.get("expected", [])} & patterns.keys()
        )
        for detector in detectors:
            expected = _expected_for(fixture, detector)
            audit = audit_text(text, expected, patterns[detector])
            row = {
                "corpus": corpus,
                "id": fixture["id"],
                "detector": detector,
                "kind": fixture.get("kind"),
                "support": fixture.get("support"),
                "tier": fixture.get("tier"),
                "contexts": fixture.get("contexts") or ([fixture["category"]] if "category" in fixture else []),
                **audit,
            }
            if row["disposition"] != "retained" and row["disposition"] != "silent":
                row["policyOutcomes"] = sorted(
                    {e.get("policyOutcome") for e in fixture.get("expected", []) if e.get("policyOutcome")}
                )
            rows.append(row)
    return rows


def audit_corpora(contracts: dict) -> dict:
    patterns = family_patterns(contracts)
    rows: list[dict] = []
    rows += _audit_rows(load_json(SYNCHRONOUS_CORPUS)["fixtures"], "conformance/synchronous", patterns, "input")
    rows += _audit_rows(load_json(INCREMENTAL_CORPUS)["fixtures"], "conformance/incremental", patterns, "input")
    rows += _audit_rows(load_json(ACCURACY_CORPUS)["fixtures"], "assessment/accuracy", patterns, "input")

    inventory = load_json(DETECTOR_INVENTORY)
    for row in inventory["types"]:
        if row["detector"] not in patterns:
            continue
        trigger = row["reconciliationTrigger"]
        audit = audit_text(
            trigger,
            [{"start": 0, "end": len(trigger.encode("utf-8"))}],
            patterns[row["detector"]],
        )
        rows.append({
            "corpus": "docs/coverage/detector-inventory.json#reconciliationTrigger",
            "id": row["type"],
            "detector": row["detector"],
            "kind": "reconciliation-trigger",
            "support": None,
            "tier": None,
            "contexts": [],
            **audit,
        })

    rows.sort(key=lambda r: (r["corpus"], r["detector"], r["id"]))
    summary: dict[str, dict] = {}
    for row in rows:
        per = summary.setdefault(row["detector"], {"retained": 0, "broad-shape": 0, "silent": 0, "review": 0})
        per[row["disposition"]] += 1
    return {
        "schemaVersion": 1,
        "issue": contracts["issue"],
        "contracts": str(CONTRACTS_PATH.relative_to(ROOT)),
        "dispositions": {
            "retained": "every expected range for this detector is matched by the frozen contract at exactly the same bytes; the fixture survives the child fix unchanged",
            "broad-shape": "a positive expectation the frozen contract no longer matches; the child fix must re-author the value to the contract and keep the old input as an intentionally-unsupported boundary fixture rather than delete it",
            "silent": "no expectation for this detector and no contract match; the negative or boundary fixture survives unchanged",
            "review": "the contract matches a range the fixture does not expect; a human must decide whether the fixture or the contract is wrong",
        },
        "summary": summary,
        "rows": rows,
    }


# --- CLI -------------------------------------------------------------------------


def check(contracts: dict) -> list[str]:
    errors: list[str] = []
    baseline = load_json(BASELINE_PATH)
    derived, derive_errors = derive_baseline(baseline, contracts)
    errors += derive_errors
    if dump_json(derived) != BASELINE_PATH.read_text(encoding="utf-8"):
        errors.append(f"{BASELINE_PATH.relative_to(ROOT)}: derived fields are stale; run --write")
    audit = audit_corpora(contracts)
    if dump_json(audit) != CORPUS_AUDIT_PATH.read_text(encoding="utf-8"):
        errors.append(f"{CORPUS_AUDIT_PATH.relative_to(ROOT)}: stale; run --write")
    return errors


def write(contracts: dict) -> list[str]:
    baseline = load_json(BASELINE_PATH)
    derived, errors = derive_baseline(baseline, contracts)
    if errors:
        return errors
    BASELINE_PATH.write_text(dump_json(derived), encoding="utf-8")
    CORPUS_AUDIT_PATH.write_text(dump_json(audit_corpora(contracts)), encoding="utf-8")
    return []


def print_fixture(fixture_id: str) -> int:
    baseline = load_json(BASELINE_PATH)
    for pair in baseline["pairs"]:
        for role in ("positive", "negative"):
            fixture = pair[role]
            if fixture["id"] == fixture_id:
                content, start, end = render_fixture(fixture["construction"])
                sys.stdout.write(json.dumps({"id": fixture_id, "content": content, "tokenRange": {"start": start, "end": end}, "contentSha256": sha256_hex(content)}, ensure_ascii=False) + "\n")
                return 0
    sys.stderr.write(f"unknown fixture id {fixture_id}\n")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify the committed evidence files are consistent with the contracts (default)")
    mode.add_argument("--write", action="store_true", help="rewrite the derived evidence files")
    mode.add_argument("--print-fixture", metavar="ID", help="reconstruct one frozen fixture's literal content on stdout")
    args = parser.parse_args(argv)

    if args.print_fixture:
        return print_fixture(args.print_fixture)
    contracts = load_json(CONTRACTS_PATH)
    errors = write(contracts) if args.write else check(contracts)
    for error in errors:
        sys.stderr.write(f"error: {error}\n")
    if errors:
        return 1
    sys.stdout.write("Precision contract audit complete: 0 error(s)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
