#!/usr/bin/env python3
"""Aggregate `twiggy top --format csv` shallow bytes by detector module.

Usage: attribute_twiggy.py <twiggy.csv> [top_n]
Reads only symbol names and sizes from a build artifact; no input text.
"""
import csv, re, sys, collections

MOD = re.compile(r"redact_secret\[[0-9a-f]+\]::detectors::([a-z0-9_]+)")
CORE = re.compile(r"redact_secret\[[0-9a-f]+\]::([a-z0-9_]+)")

def classify(name):
    m = MOD.search(name)
    if m:
        return "detectors::" + m.group(1)
    if name.startswith('"function names"') or name.startswith('""function names'):
        return "<name section>"
    if name.startswith('data segment') or name.startswith('"data segment'):
        return "<data " + name.split('"')[-2] + ">" if '"' in name else "<data>"
    m = CORE.search(name)
    if m:
        return "core::" + m.group(1)
    if name.startswith("core[") or "core[" in name[:12]:
        return "std::core"
    if "alloc[" in name[:14]:
        return "std::alloc"
    return "other"

def main():
    path = sys.argv[1]
    top = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    agg = collections.Counter(); cnt = collections.Counter()
    total = 0
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            size = int(row["ShallowSize"]); total += size
            k = classify(row["Name"]); agg[k] += size; cnt[k] += 1
    print(f"total {total}")
    for k, v in agg.most_common(top):
        print(f"{v:8d} {100*v/total:5.2f}% n={cnt[k]:4d} {k}")
    prov = sum(v for k, v in agg.items() if k.startswith("detectors::"))
    print(f"detectors::* total {prov} ({100*prov/total:.1f}%)")

main()
