#!/usr/bin/env python3
"""Validate pii-context/v2 semantics against its pinned Unicode inputs and fixtures."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path("docs/contracts/pii/pii-context-v2.json")
SCHEMA = Path("docs/contracts/pii/pii-context-v2.schema.json")
INVISIBLE_TABLE = Path("crates/secret-scan-core/src/invisible_table.rs")
UCD_DIR = Path("crates/secret-scan-core/ucd")
MARKER = re.compile(r"\{\{candidate:([a-z][a-z0-9-]*)\}\}")
SEPARATORS = re.compile(r"[\s_\-:=]+")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SCHEMA_SUPPORT = load_module("pii_context_schema_support", Path(__file__).with_name("check-scoring-artifact.py"))
_INVISIBLE_SUPPORT = load_module("pii_context_invisible_support", Path(__file__).with_name("generate-invisible-table.py"))
_TABLE_SUPPORT = load_module("pii_context_table_support", Path(__file__).with_name("generate-pii-context-table.py"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def governed_invisible_ranges(root: Path = ROOT) -> list[tuple[int, int]]:
    ucd = root / UCD_DIR
    return _INVISIBLE_SUPPORT.derive_ranges(
        (ucd / "DerivedCoreProperties.txt").read_text(encoding="utf-8"),
        (ucd / "UnicodeData.txt").read_text(encoding="utf-8"),
    )


def in_ranges(code_point: int, ranges: list[tuple[int, int]]) -> bool:
    return any(first <= code_point <= last for first, last in ranges)


def normalize(value: str, language: str, ranges: list[tuple[int, int]] | None = None) -> str:
    """Reference comparison view using the core's pinned governed invisible set."""
    ranges = governed_invisible_ranges() if ranges is None else ranges
    visible = "".join(character for character in value if not in_ranges(ord(character), ranges))
    value = unicodedata.normalize("NFC", visible)
    if language == "en":
        value = "".join(character.lower() if "A" <= character <= "Z" else character for character in value)
    return SEPARATORS.sub(" ", value).strip()


def line_views(fixture: dict, ranges: list[tuple[int, int]]) -> tuple[list[tuple[str, dict[str, int]]], list[str]]:
    """Return normalized line views and zero-width candidate positions."""
    errors: list[str] = []
    candidate_ids = [candidate["id"] for candidate in fixture["candidates"]]
    markers = MARKER.findall(fixture["template"])
    if sorted(markers) != sorted(candidate_ids) or len(markers) != len(set(markers)):
        errors.append("template markers must name every candidate exactly once")
        return [], errors
    marker_chars = {candidate_id: chr(0xE100 + index) for index, candidate_id in enumerate(candidate_ids)}
    marked = MARKER.sub(lambda match: marker_chars[match.group(1)], fixture["template"])
    views: list[tuple[str, dict[str, int]]] = []
    for raw_line in marked.splitlines() or [marked]:
        normalized = normalize(raw_line, fixture["language"], ranges)
        positions: dict[str, int] = {}
        clean: list[str] = []
        reverse = {marker: candidate_id for candidate_id, marker in marker_chars.items()}
        for character in normalized:
            if character in reverse:
                positions[reverse[character]] = len(clean)
            else:
                clean.append(character)
        views.append(("".join(clean), positions))
    return views, errors


def vocabulary_occurrences(contract: dict, language: str, view: str, domains: set[str], ranges: list[tuple[int, int]]) -> list[dict]:
    """Find and resolve overlapping vocabulary forms by declared precedence."""
    occurrences: list[dict] = []
    for entry in contract["entries"]:
        if entry["language"] != language or domains.isdisjoint(entry["domains"]):
            continue
        for form in entry["forms"]:
            normalized = normalize(form, language, ranges)
            boundary = r"[^\s\"']" if entry["kind"] == "field-label" else r"\S"
            pattern = re.compile(r"(?<!" + boundary + r")" + re.escape(normalized) + r"(?!" + boundary + r")")
            for match in pattern.finditer(view):
                occurrences.append({"start": match.start(), "end": match.end(), "entry": entry})

    strength = {"high-signal": 0, "ambiguous": 1}
    semantic = {"negative": 0, "positive": 1, "neutral": 2}
    occurrences.sort(
        key=lambda item: (
            -(item["end"] - item["start"]),
            strength[item["entry"]["strength"]],
            semantic[item["entry"]["class"]],
            item["entry"]["id"].encode("utf-8"),
        )
    )
    selected: list[dict] = []
    for occurrence in occurrences:
        if any(occurrence["start"] < kept["end"] and kept["start"] < occurrence["end"] for kept in selected):
            continue
        selected.append(occurrence)
    return sorted(selected, key=lambda item: (item["start"], item["end"], item["entry"]["id"]))


def occurrence_distance(occurrence: dict, candidate_position: int) -> int:
    if candidate_position <= occurrence["start"]:
        return occurrence["start"] - candidate_position
    if candidate_position >= occurrence["end"]:
        return candidate_position - occurrence["end"]
    return 0


def associate_occurrence(occurrence: dict, view: str, positions: dict[str, int], candidates: dict[str, dict]) -> str | None:
    """Honor domain, direction, bounds, intervening candidates, and ties."""
    entry = occurrence["entry"]
    limit = 16 if entry["kind"] == "field-label" else 64
    if entry["kind"] == "field-label":
        # A field label associates only forward, so only a candidate after it
        # can compete for it (pii-context/v2, issue #924).
        positions = {
            candidate_id: position for candidate_id, position in positions.items() if position >= occurrence["end"]
        }
    eligible: list[tuple[int, str]] = []
    for candidate_id, position in positions.items():
        if candidates[candidate_id]["domain"] not in entry["domains"]:
            continue
        if entry["kind"] == "field-label":
            if position < occurrence["end"]:
                continue
            gap = view[occurrence["end"] : position]
            if any(character not in " \"'" for character in gap):
                continue
        distance = occurrence_distance(occurrence, position)
        if distance > limit:
            continue
        if any(
            other_id != candidate_id and occurrence_distance(occurrence, other_position) < distance
            for other_id, other_position in positions.items()
        ):
            continue
        eligible.append((distance, candidate_id))
    if not eligible:
        return None
    nearest = min(distance for distance, _ in eligible)
    # Candidates at one position are one occurrence with several domain
    # interpretations; each position counts once (issue #922).
    if sum(occurrence_distance(occurrence, position) == nearest for position in set(positions.values())) > 1:
        return None
    winners = [candidate_id for distance, candidate_id in eligible if distance == nearest]
    return winners[0] if len(winners) == 1 else None


def expected_effect(entries: dict[str, dict], candidate: dict, matches: list[str]) -> str:
    if not candidate["identityEstablished"]:
        return "not-established-without-identity"
    if not matches:
        return "no-evidence"
    classes = {entries[entry_id]["class"] for entry_id in matches}
    if "negative" in classes:
        return "negative-evidence"
    if "positive" in classes:
        return "positive-evidence"
    return "neutral-evidence"


def fixture_associations(contract: dict, fixture: dict, ranges: list[tuple[int, int]]) -> tuple[dict[str, dict], list[str]]:
    candidates = {candidate["id"]: candidate for candidate in fixture["candidates"]}
    views, errors = line_views(fixture, ranges)
    matches: dict[str, set[str]] = {candidate_id: set() for candidate_id in candidates}
    for view, positions in views:
        domains = {candidates[candidate_id]["domain"] for candidate_id in positions}
        for occurrence in vocabulary_occurrences(contract, fixture["language"], view, domains, ranges):
            candidate_id = associate_occurrence(occurrence, view, positions, candidates)
            if candidate_id is not None:
                matches[candidate_id].add(occurrence["entry"]["id"])
    entries = {entry["id"]: entry for entry in contract["entries"]}
    return {
        candidate_id: {
            "matches": sorted(candidate_matches),
            "effect": expected_effect(entries, candidates[candidate_id], sorted(candidate_matches)),
        }
        for candidate_id, candidate_matches in matches.items()
    }, errors


def check_contract(contract: dict, ranges: list[tuple[int, int]]) -> list[str]:
    errors: list[str] = []
    if contract.get("languages") != ["en", "ko"]:
        errors.append(f"{ARTIFACT}: languages must be exactly ['en', 'ko']")
    if contract.get("precedence") != [
        "longest-token-span", "high-signal-first", "negative-positive-neutral", "entry-id-bytewise"
    ]:
        errors.append(f"{ARTIFACT}: precedence must be the reviewed deterministic order")

    entries = contract.get("entries", [])
    entry_ids = [entry.get("id") for entry in entries]
    if len(entry_ids) != len(set(entry_ids)):
        errors.append(f"{ARTIFACT}: entry ids must be unique")
    for language in ("en", "ko"):
        language_entries = [entry for entry in entries if entry.get("language") == language]
        classes = {entry.get("class") for entry in language_entries}
        if classes != {"positive", "neutral", "negative"}:
            errors.append(f"{ARTIFACT}: {language} must cover positive, neutral, and negative classes")
        if not any(entry.get("strength") == "ambiguous" for entry in language_entries):
            errors.append(f"{ARTIFACT}: {language} needs an ambiguous benign-control entry")

    fixture_ids: set[str] = set()
    for fixture in contract.get("fixtures", []):
        fixture_id = fixture.get("id")
        if fixture_id in fixture_ids:
            errors.append(f"{ARTIFACT}: duplicate fixture id {fixture_id}")
        fixture_ids.add(fixture_id)
        actual, fixture_errors = fixture_associations(contract, fixture, ranges)
        errors.extend(f"{ARTIFACT}: fixture {fixture_id}: {error}" for error in fixture_errors)
        expected = {
            association["candidate"]: {"matches": sorted(association["matches"]), "effect": association["effect"]}
            for association in fixture["expectedAssociations"]
        }
        if actual != expected:
            errors.append(f"{ARTIFACT}: fixture {fixture_id} yields {actual}, expected {expected}")
    return errors


def validate(root: Path = ROOT) -> list[str]:
    contract = load(root / ARTIFACT)
    schema = load(root / SCHEMA)
    errors = _SCHEMA_SUPPORT.validate_schema(contract, schema, schema)
    ranges = governed_invisible_ranges(root)
    expected_table = _INVISIBLE_SUPPORT.render_table(ranges, _INVISIBLE_SUPPORT.UCD_VERSION)
    if (root / INVISIBLE_TABLE).read_text(encoding="utf-8") != expected_table:
        errors.append(f"{INVISIBLE_TABLE}: differs from the pinned governed invisible set")
    expected_compiled = _TABLE_SUPPORT.render(contract)
    compiled_path = root / _TABLE_SUPPORT.OUTPUT
    if not compiled_path.is_file() or compiled_path.read_text(encoding="utf-8") != expected_compiled:
        errors.append(f"{_TABLE_SUPPORT.OUTPUT}: differs from the reviewed PII context contract")
    if not errors:
        errors.extend(check_contract(contract, ranges))
    return errors


def main() -> int:
    errors = validate()
    for error in errors:
        print(f"ERROR {error}")
    print(f"PII context contract check complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
