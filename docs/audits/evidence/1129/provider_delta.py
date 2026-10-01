#!/usr/bin/env python3
"""Rank the code only the `full` WASM links (full minus common) by module and by symbol.

Usage: provider_delta.py <full.csv> <common.csv> [top_n]
Inputs are `twiggy top --format csv` outputs. Symbols are matched by name, so
LLVM-merged bodies that keep one name are counted once, where the linker kept them.
"""
import csv, re, sys, collections
MOD = re.compile(r"redact_secret\[[0-9a-f]+\]::detectors::([a-z0-9_]+)")
def load(p):
    d = collections.Counter()
    with open(p, newline="") as fh:
        for r in csv.DictReader(fh):
            d[r["Name"]] += int(r["ShallowSize"])
    return d
full, common = load(sys.argv[1]), load(sys.argv[2])
top = int(sys.argv[3]) if len(sys.argv) > 3 else 30
only = {k: v for k, v in full.items() if k not in common}
grown = {k: full[k] - common[k] for k in full if k in common and full[k] != common[k]}
print(f"full total {sum(full.values())}  common total {sum(common.values())}  delta {sum(full.values())-sum(common.values())}")
print(f"symbols only in full: {len(only)} bytes {sum(only.values())}; shared-name symbols that differ: {len(grown)} net {sum(grown.values())}")
bymod = collections.Counter(); n = collections.Counter()
for k, v in only.items():
    m = MOD.search(k); key = m.group(1) if m else "(non-detector)"
    bymod[key] += v; n[key] += 1
print("-- by module (only-in-full)")
for k, v in bymod.most_common(top): print(f"{v:7d} n={n[k]:3d} {k}")
print("-- largest symbols only in full")
for k, v in sorted(only.items(), key=lambda kv: -kv[1])[:top]:
    print(f"{v:7d} {re.sub(r'redact_secret\[[0-9a-f]+\]::', '', k)[:150]}")
print("-- shared-name symbols that grew in full")
for k, v in sorted(grown.items(), key=lambda kv: -abs(kv[1]))[:10]:
    print(f"{v:7d} {re.sub(r'redact_secret\[[0-9a-f]+\]::', '', k)[:150]}")
