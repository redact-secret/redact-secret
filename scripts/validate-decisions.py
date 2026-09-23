#!/usr/bin/env python3
"""Validate project-wide ADRs stored under docs/decisions."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


DECISION_ID = re.compile(r"^decision-[a-z0-9]+(?:-[a-z0-9]+)*$")
DECISION_HEADING = re.compile(r"(?im)^#{1,6}\s+Decision(?:\s*:.*)?\s*$")
CURRENT_APPLICATION_HEADING = re.compile(r"(?im)^#{1,6}\s+Current application\b")
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
FULL_RECORD = re.compile(
    r"^https://github\.com/redact-secret/redact-secret/blob/[0-9a-f]{40}/.+$"
)
BLOB_PERMALINK = re.compile(r"https://github\.com/redact-secret/redact-secret/blob/[0-9a-f]{40}/\S+")
ID_WITH_MD_SUFFIX = re.compile(r"(?<![\w./-])(decision-[a-z0-9]+(?:-[a-z0-9]+)*)\.md\b")
VALID_STATUSES = {"proposed", "accepted", "rejected", "superseded"}
SPEC_NAMES = {
    "detector-families",
    "contextual-detection",
    "engine",
    "distribution",
    "evidence-and-gates",
}
SIZE_WARNING_BYTES = 12_000



def parse_frontmatter(path: Path) -> tuple[dict[str, str], str, list[str]]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}, text, [f"{path}: missing YAML frontmatter"]
    try:
        end = lines.index("---", 1)
    except ValueError:
        return {}, text, [f"{path}: missing YAML frontmatter closer"]

    fields: dict[str, str] = {}
    for number, line in enumerate(lines[1:end], 2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9_]*):\s*(.+)", line)
        if match is None:
            errors.append(f"{path}:{number}: unsupported frontmatter syntax")
            continue
        key, value = match.groups()
        if key in fields:
            errors.append(f"{path}:{number}: duplicate field {key}")
        fields[key] = value.strip().strip('"\'')
    return fields, "\n".join(lines[end + 1 :]), errors


def parse_spec_routing(root: Path) -> tuple[dict[str, set[Path]], list[str]]:
    """Map each spec file's bare name to the set of docs/decisions/*.md paths it links.

    Returns (routing, errors) where errors flags a spec file linking to a
    path that is not a real record under docs/decisions.
    """
    errors: list[str] = []
    specs_dir = root / "docs" / "specs"
    decision_dir = root / "docs" / "decisions"
    routing: dict[str, set[Path]] = {name: set() for name in SPEC_NAMES}
    if not specs_dir.is_dir():
        return routing, errors

    rules_heading = re.compile(r"(?im)^##\s+Rules\s*$")
    for spec_name in SPEC_NAMES:
        spec_file = specs_dir / f"{spec_name}.md"
        if not spec_file.is_file():
            errors.append(f"{spec_file}: missing spec file")
            continue
        text = spec_file.read_text(encoding="utf-8")
        match = rules_heading.search(text)
        if match is None:
            errors.append(f"{spec_file}: missing a '## Rules' section")
            continue
        # Only links in the Rules table are routing decisions -- a spec
        # file's intro prose may cite other ADRs or docs for context without
        # that counting as routing them from this spec.
        rules_text = text[match.end() :]
        for target in LINK.findall(rules_text):
            if re.match(r"^[a-z]+://", target):
                continue
            resolved = (spec_file.parent / target.split("#", 1)[0]).resolve()
            if resolved.suffix != ".md" or resolved.parent != decision_dir or resolved.name == "DECISIONS.md":
                errors.append(f"{spec_file}: Rules table links a non-ADR path {target}")
                continue
            routing[spec_name].add(resolved)
    return routing, errors


def check_spec_routing(
    root: Path, records: list[Path], fields_by_record: dict[Path, dict[str, str]]
) -> list[str]:
    errors: list[str] = []
    routing, routing_errors = parse_spec_routing(root)
    errors.extend(routing_errors)

    routed_from: dict[Path, list[str]] = {}
    for spec_name, paths in routing.items():
        for path in paths:
            routed_from.setdefault(path, []).append(spec_name)

    for record in records:
        fields = fields_by_record[record]
        declared_spec = fields.get("spec")
        resolved = record.resolve()
        routing_specs = routed_from.get(resolved, [])
        if len(routing_specs) != 1:
            errors.append(
                f"{record}: routed from {len(routing_specs)} spec file(s), expected exactly 1"
            )
        elif declared_spec and routing_specs[0] != declared_spec:
            errors.append(
                f"{record}: spec: {declared_spec} does not match the spec file that "
                f"routes it ({routing_specs[0]})"
            )
    return errors


def check_supersession(
    records: list[Path], fields_by_record: dict[Path, dict[str, str]], identities: dict[str, Path]
) -> list[str]:
    errors: list[str] = []
    for record in records:
        fields = fields_by_record[record]
        own_id = fields.get("decision_id", "")
        for direction, reverse in (("supersedes", "superseded_by"), ("superseded_by", "supersedes")):
            target_id = fields.get(direction)
            if not target_id:
                continue
            if not DECISION_ID.fullmatch(target_id):
                errors.append(f"{record}: invalid {direction} value {target_id!r}")
                continue
            target_record = identities.get(target_id)
            if target_record is None:
                errors.append(f"{record}: {direction} references unknown decision_id {target_id}")
                continue
            target_fields = fields_by_record[target_record]
            reverse_values = {
                value.strip() for value in target_fields.get(reverse, "").split(",") if value.strip()
            }
            if own_id not in reverse_values:
                errors.append(
                    f"{record}: {direction}: {target_id} is not reciprocated by "
                    f"{target_record}'s {reverse} field"
                )
    return errors


def check_aliases(records: list[Path], fields_by_record: dict[Path, dict[str, str]], identities: dict[str, Path]) -> list[str]:
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for record in records:
        fields = fields_by_record[record]
        raw = fields.get("aliases", "")
        for alias in (value.strip() for value in raw.split(",") if value.strip()):
            if not DECISION_ID.fullmatch(alias):
                errors.append(f"{record}: invalid alias {alias!r}")
                continue
            if alias in identities:
                errors.append(f"{record}: alias {alias} collides with a real decision_id")
                continue
            if alias in seen and seen[alias] != record:
                errors.append(f"{record}: alias {alias} is already used by {seen[alias]}")
                continue
            seen[alias] = record
    return errors


def alias_list(fields: dict[str, str]) -> list[str]:
    return [value.strip() for value in fields.get("aliases", "").split(",") if value.strip()]


def alias_permalinks(body: str) -> dict[str, str]:
    """Map each `decision_id` in a `Folded records` table row to that row's blob permalink."""
    permalinks: dict[str, str] = {}
    for line in body.splitlines():
        row = re.match(r"^\|\s*`(decision-[a-z0-9-]+)`\s*\|", line)
        link = BLOB_PERMALINK.search(line)
        if row is not None and link is not None:
            permalinks[row.group(1)] = link.group(0).rstrip(")")
    return permalinks


def check_folded_permalinks(
    records: list[Path], fields_by_record: dict[Path, dict[str, str]], bodies: dict[Path, str]
) -> list[str]:
    """A record that folds others must carry a permalink to each folded record's last text."""
    errors: list[str] = []
    for record in records:
        aliases = alias_list(fields_by_record[record])
        if not aliases:
            continue
        permalinks = alias_permalinks(bodies[record])
        for alias in aliases:
            if alias not in permalinks:
                errors.append(
                    f"{record}: folded alias {alias} has no `Folded records` row with a full-record permalink"
                )
    return errors


def markdown_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.md"], capture_output=True, check=False
    )
    if result.returncode == 0 and result.stdout:
        return [root / name for name in result.stdout.decode("utf-8").split("\0") if name]
    return sorted((root / "docs").rglob("*.md"))


def check_id_md_citations(root: Path, known_ids: set[str]) -> list[str]:
    """A decision id cited with a `.md` suffix names no file; cite the id or the record's path."""
    errors: list[str] = []
    for path in markdown_files(root):
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in ID_WITH_MD_SUFFIX.finditer(line):
                if match.group(1) in known_ids:
                    errors.append(
                        f"{path}:{number}: {match.group(1)}.md cites a decision id with a .md suffix, "
                        "which resolves to no file"
                    )
    return errors


def validate(root: Path) -> tuple[list[str], list[str]]:
    root = root.resolve()
    decision_dir = root / "docs" / "decisions"
    legacy_workspace_dir = root / "_notes" / "decisions"
    errors: list[str] = []
    warnings: list[str] = []

    if legacy_workspace_dir.is_dir() and decision_dir.is_dir():
        errors.append(
            "multiple workspace decision locations exist; use docs/decisions only"
        )
    if not decision_dir.is_dir():
        return errors, warnings

    index = decision_dir / "DECISIONS.md"
    records = sorted(
        path for path in decision_dir.glob("*.md") if path.name != "DECISIONS.md"
    )
    if records and not index.is_file():
        errors.append(f"{index}: missing decision index")
        return errors, warnings

    identities: dict[str, Path] = {}
    fields_by_record: dict[Path, dict[str, str]] = {}
    bodies: dict[Path, str] = {}
    for record in records:
        fields, body, record_errors = parse_frontmatter(record)
        bodies[record] = body
        errors.extend(record_errors)
        fields_by_record[record] = fields
        for required in ("decision_id", "status", "scope", "spec"):
            if required not in fields:
                errors.append(f"{record}: missing required field {required}")
        identity = fields.get("decision_id", "")
        if not DECISION_ID.fullmatch(identity):
            errors.append(f"{record}: invalid decision_id")
        elif identity in identities:
            errors.append(f"{record}: duplicate decision_id {identity}")
        else:
            identities[identity] = record
        status = fields.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{record}: invalid status")
        if fields.get("scope") != "workspace":
            errors.append(f"{record}: docs/decisions records must use workspace scope")
        if status == "accepted" and not DECISION_HEADING.search(body):
            errors.append(f"{record}: accepted decision requires a Decision heading")
        spec = fields.get("spec")
        if spec is not None and spec not in SPEC_NAMES:
            errors.append(f"{record}: spec: {spec} is not one of {sorted(SPEC_NAMES)}")
        full_record = fields.get("full_record")
        if full_record is not None and not FULL_RECORD.fullmatch(full_record):
            errors.append(f"{record}: full_record is not a main-commit blob permalink")

        if CURRENT_APPLICATION_HEADING.search(body):
            errors.append(
                f"{record}: '## Current application' appendices are rejected; "
                "use supersession or a spec-file row instead"
            )

        size = record.stat().st_size
        if size > SIZE_WARNING_BYTES:
            warnings.append(f"{record}: {size} bytes, exceeds the {SIZE_WARNING_BYTES}-byte guideline")

    errors.extend(check_supersession(records, fields_by_record, identities))
    errors.extend(check_aliases(records, fields_by_record, identities))
    errors.extend(check_folded_permalinks(records, fields_by_record, bodies))
    known_ids = set(identities) | {alias for record in records for alias in alias_list(fields_by_record[record])}
    errors.extend(check_id_md_citations(root, known_ids))
    errors.extend(check_spec_routing(root, records, fields_by_record))

    if not index.is_file():
        return errors, warnings
    resolved: list[Path] = []
    for target in LINK.findall(index.read_text(encoding="utf-8")):
        if re.match(r"^[a-z]+://", target) or target.startswith("#"):
            continue
        resolved_target = (index.parent / target.split("#", 1)[0]).resolve()
        resolved.append(resolved_target)
        if not resolved_target.exists():
            errors.append(f"{index}: broken decision link {target}")
        elif resolved_target.parent != decision_dir:
            errors.append(f"{index}: decision link leaves docs/decisions: {target}")

    for record in records:
        count = resolved.count(record.resolve())
        if count != 1:
            errors.append(f"{index}: {record.name} is indexed {count} times")
    return errors, warnings


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    errors, warnings = validate(root)
    for warning in warnings:
        print(f"WARNING {warning}")
    for error in errors:
        print(f"ERROR {error}")
    print(f"Decision validation complete: {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
