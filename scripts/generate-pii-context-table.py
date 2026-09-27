#!/usr/bin/env python3
"""Generate the core's compiled pii-context/v1 vocabulary table."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = Path("docs/contracts/pii/pii-context-v1.json")
OUTPUT = Path("crates/secret-scan-core/src/pii_context_table.rs")

DOMAIN = {
    "email": "Email",
    "payment-card": "PaymentCard",
    "network-address": "NetworkAddress",
    "iban": "Iban",
    "phone": "Phone",
    "national-id": "NationalId",
}
KIND = {"field-label": "FieldLabel", "natural-language-label": "NaturalLanguageLabel"}
CLASS = {"positive": "Positive", "neutral": "Neutral", "negative": "Negative"}
STRENGTH = {"high-signal": "HighSignal", "ambiguous": "Ambiguous"}
LANGUAGE = {"en": "English", "ko": "Korean"}


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render(contract: dict) -> str:
    lines = [
        "//! Generated `pii-context/v1` vocabulary. Do not edit by hand.",
        "",
        "use super::{",
        "    ContextClass, ContextEntry, ContextKind, ContextLanguage, ContextStrength, IdentityDomain,",
        "};",
        "",
        'pub(super) const CONTEXT_VERSION: &str = "pii-context/v1";',
        "",
        "#[rustfmt::skip]",
        "pub(super) const CONTEXT_ENTRIES: &[ContextEntry] = &[",
    ]
    for entry in contract["entries"]:
        domains = (
            "IdentityDomain::ALL"
            if entry["domains"] == list(DOMAIN)
            else "&[" + ", ".join(f"IdentityDomain::{DOMAIN[item]}" for item in entry["domains"]) + "]"
        )
        forms = "&[" + ", ".join(rust_string(item) for item in entry["forms"]) + "]"
        lines.append(
            "    ContextEntry::new("
            f"{rust_string(entry['id'])}, ContextLanguage::{LANGUAGE[entry['language']]}, "
            f"ContextKind::{KIND[entry['kind']]}, "
            f"ContextClass::{CLASS[entry['class']]}, ContextStrength::{STRENGTH[entry['strength']]}, "
            f"{domains}, {forms}),"
        )
    lines.extend(["];", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(json.loads((ROOT / CONTRACT).read_text(encoding="utf-8")))
    path = ROOT / OUTPUT
    if args.check:
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            print(f"{OUTPUT}: generated PII context table is stale", flush=True)
            return 1
        return 0
    path.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
