#!/usr/bin/env python3
"""Generate the core's invisible-code-point table from a pinned UCD snapshot.

`decision-normalize-invisible-characters-before-detection` fixes the removed
set as ``Default_Ignorable_Code_Point ∪ Cf`` derived from a pinned Unicode
Character Database version, not an enumerated list. The core crate has
``allowed-dependencies = []`` (`scripts/check-rust-workspace.py`), so the set
ships as generated data checked into the crate:

    crates/secret-scan-core/src/invisible_table.rs

The derivation is two offline steps, so a UCD bump is a reviewable diff at
each one and the everyday check needs neither the network nor 3 MB of UCD in
the repository:

1. ``--refresh-ucd DIR`` reads the full ``DerivedCoreProperties.txt`` and
   ``UnicodeData.txt`` from ``DIR``, verifies each against the SHA-256 pinned
   below, and writes *verbatim line extracts* — only the
   ``Default_Ignorable_Code_Point`` property lines and the ``Cf`` records —
   to ``crates/secret-scan-core/ucd/``. Obtain the inputs from
   ``https://www.unicode.org/Public/<version>/ucd/``. Nothing in this script
   touches the network.
2. With no mode flag, the script regenerates the Rust table from those
   checked-in extracts. ``--check`` does the same in memory and fails when
   the checked-in table differs, which is what ``npm run rust:check`` runs.
   ``crates/secret-scan-core/tests/invisible_table.rs`` re-derives the set
   from the same extracts independently, so ``cargo test`` asserts it too.

To bump the UCD: change ``UCD_VERSION`` and both SHA-256 pins, run
``--refresh-ucd``, run the script, and review all three diffs.

    python3 -B scripts/generate-invisible-table.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "secret-scan-core"
EXTRACT_DIR = CORE / "ucd"
TABLE = CORE / "src" / "invisible_table.rs"

UCD_VERSION = "17.0.0"
UCD_SHA256 = {
    "DerivedCoreProperties.txt": "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
    "UnicodeData.txt": "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
}

PROPERTY = "Default_Ignorable_Code_Point"
CATEGORY = "Cf"
MAX_CODE_POINT = 0x10FFFF

EXTRACT_HEADER = """\
# Verbatim line extract of {name} from the Unicode Character Database {version}.
# Source: https://www.unicode.org/Public/{version}/ucd/{name}
# Source SHA-256: {sha256}
# Kept lines: {kept}
# Written by scripts/generate-invisible-table.py --refresh-ucd; never hand-edited.
# Copyright (c) Unicode, Inc. Distributed under the Unicode License v3,
# https://www.unicode.org/license.txt
"""


class TableError(Exception):
    """A malformed or mismatched input. The message never carries scanned text."""


def parse_code_point(text: str) -> int:
    value = int(text, 16)
    if not 0 <= value <= MAX_CODE_POINT:
        raise TableError(f"code point out of range: {text}")
    return value


def is_property_line(line: str) -> bool:
    """Whether `line` is a DerivedCoreProperties record for ``PROPERTY``."""
    fields = line.split("#", 1)[0].split(";")
    return len(fields) >= 2 and fields[1].strip() == PROPERTY


def is_category_line(line: str) -> bool:
    """Whether `line` is a UnicodeData record whose General_Category is ``CATEGORY``."""
    fields = line.split(";")
    return len(fields) >= 3 and fields[2] == CATEGORY


def property_ranges(text: str) -> list[tuple[int, int]]:
    """Inclusive ranges of every ``PROPERTY`` record in DerivedCoreProperties text."""
    ranges = []
    for line in text.splitlines():
        if not is_property_line(line):
            continue
        span = line.split(";", 1)[0].strip()
        first, _, last = span.partition("..")
        ranges.append((parse_code_point(first), parse_code_point(last or first)))
    return ranges


def category_ranges(text: str) -> list[tuple[int, int]]:
    """Inclusive ranges of every ``CATEGORY`` record in UnicodeData text.

    UnicodeData compresses large blocks into a ``<Name, First>`` /
    ``<Name, Last>`` record pair; both forms are handled.
    """
    ranges = []
    open_first: int | None = None
    for line in text.splitlines():
        if line.startswith("#") or not is_category_line(line):
            continue
        fields = line.split(";")
        code_point = parse_code_point(fields[0])
        name = fields[1]
        if name.endswith(", First>"):
            open_first = code_point
        elif name.endswith(", Last>"):
            if open_first is None:
                raise TableError("UnicodeData range end without a start")
            ranges.append((open_first, code_point))
            open_first = None
        else:
            ranges.append((code_point, code_point))
    if open_first is not None:
        raise TableError("UnicodeData range start without an end")
    return ranges


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sorted, disjoint, non-adjacent inclusive ranges covering the same set."""
    merged: list[tuple[int, int]] = []
    for first, last in sorted(ranges):
        if first > last:
            raise TableError("inverted range")
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def derive_ranges(derived_core_properties: str, unicode_data: str) -> list[tuple[int, int]]:
    ranges = merge_ranges(property_ranges(derived_core_properties) + category_ranges(unicode_data))
    if not ranges:
        raise TableError("derived set is empty")
    if ranges[0][0] < 0x80:
        # The pipeline's `is_ascii()` fast path depends on this.
        raise TableError("derived set contains an ASCII code point")
    return ranges


def render_table(ranges: list[tuple[int, int]], version: str) -> str:
    count = sum(last - first + 1 for first, last in ranges)
    lines = [
        "//! Generated by `scripts/generate-invisible-table.py`; do not edit by hand.",
        "//!",
        f"//! `{PROPERTY} ∪ {CATEGORY}` from the pinned Unicode Character Database",
        "//! snapshot extracted under `crates/secret-scan-core/ucd/`",
        "//! (`decision-normalize-invisible-characters-before-detection`).",
        f"//! {len(ranges)} ranges, {count} code points.",
        "",
        "/// The Unicode Character Database version the table was derived from.",
        "#[cfg(test)]",
        f'pub(crate) const UCD_VERSION: &str = "{version}";',
        "",
        "/// Sorted, disjoint, non-adjacent inclusive code-point ranges. None is",
        "/// ASCII; the generator rejects a snapshot that would make one so.",
        "#[rustfmt::skip]",
        "pub(crate) const INVISIBLE_RANGES: &[(u32, u32)] = &[",
    ]
    lines.extend(f"    (0x{first:04X}, 0x{last:04X})," for first, last in ranges)
    lines.append("];")
    return "\n".join(lines) + "\n"


def extract(name: str, text: str, keep, kept_description: str) -> str:
    header = EXTRACT_HEADER.format(
        name=name, version=UCD_VERSION, sha256=UCD_SHA256[name], kept=kept_description
    )
    kept = [line for line in text.splitlines() if keep(line)]
    if not kept:
        raise TableError(f"{name}: no matching lines")
    return header + "\n".join(kept) + "\n"


def refresh_ucd(source: Path) -> None:
    texts = {}
    for name, expected in UCD_SHA256.items():
        data = (source / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise TableError(f"{name}: SHA-256 {actual} does not match the pinned {expected}")
        texts[name] = data.decode("utf-8")
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    (EXTRACT_DIR / "DerivedCoreProperties.txt").write_text(
        extract(
            "DerivedCoreProperties.txt",
            texts["DerivedCoreProperties.txt"],
            is_property_line,
            f"every `{PROPERTY}` property record",
        ),
        encoding="utf-8",
    )
    (EXTRACT_DIR / "UnicodeData.txt").write_text(
        extract(
            "UnicodeData.txt",
            texts["UnicodeData.txt"],
            is_category_line,
            f"every record whose General_Category is `{CATEGORY}`",
        ),
        encoding="utf-8",
    )


def generated_table() -> str:
    ranges = derive_ranges(
        (EXTRACT_DIR / "DerivedCoreProperties.txt").read_text(encoding="utf-8"),
        (EXTRACT_DIR / "UnicodeData.txt").read_text(encoding="utf-8"),
    )
    return render_table(ranges, UCD_VERSION)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail when the checked-in table is stale")
    mode.add_argument(
        "--refresh-ucd",
        metavar="DIR",
        type=Path,
        help="rewrite the checked-in extracts from the full pinned UCD files in DIR",
    )
    options = parser.parse_args(argv)
    try:
        if options.refresh_ucd is not None:
            refresh_ucd(options.refresh_ucd)
            return 0
        table = generated_table()
        if options.check:
            if TABLE.read_text(encoding="utf-8") != table:
                print(
                    f"{TABLE.relative_to(ROOT)} is stale; run scripts/generate-invisible-table.py",
                    file=sys.stderr,
                )
                return 1
            return 0
        TABLE.write_text(table, encoding="utf-8")
        return 0
    except (OSError, TableError, ValueError) as error:
        print(f"generate-invisible-table: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
