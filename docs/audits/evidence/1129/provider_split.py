#!/usr/bin/env python3
"""Split the provider-only module code of the `full` WASM into detect impls and helpers.

Usage: provider_split.py <full.csv> <common.csv>
Inputs are `twiggy top --format csv` outputs. Engine and common-pack modules are
excluded, so the remainder is code written per provider.
"""
import csv, re, sys

def load(p):
    with open(p, newline="") as fh:
        return {r["Name"]: int(r["ShallowSize"]) for r in csv.DictReader(fh)}

full, common = load(sys.argv[1]), load(sys.argv[2])
MOD = re.compile(r"redact_secret\[[0-9a-f]+\]::detectors::([a-z0-9_]+)")
SHARED = {"pattern", "text", "prefilter", "ruleset_adapter", "additional_providers",
          "sort_candidates_by_start", "generic_token", "connection_string",
          "bearer_token", "jwt", "otpauth", "private_key", "keyword_gated_keys"}
tot = det = n = nd = 0
for k, v in full.items():
    m = MOD.search(k)
    if not m or m.group(1) in SHARED or k in common:
        continue
    tot += v; n += 1
    if " as redact_secret" in k and "Detector>::detect" in k:
        det += v; nd += 1
print(f"per-provider module code: {tot} B in {n} functions")
print(f"  bespoke Detector::detect impls: {det} B in {nd}")
print(f"  helpers / post-checks / closures: {tot - det} B in {n - nd}")
