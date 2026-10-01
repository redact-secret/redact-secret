#!/usr/bin/env python3
"""Attribute a native Mach-O/ELF binary's __text bytes to detector modules.

Usage: native_attribution.py <binary> [top_n]
Sizes are address deltas between consecutive `nm -n` text symbols (an upper bound
per symbol: padding and local-symbol gaps fall to the preceding symbol).
Only symbol names are read; no input text.
"""
import re, subprocess, sys, collections

binary = sys.argv[1]
top = int(sys.argv[2]) if len(sys.argv) > 2 else 25
out = subprocess.run(["nm", "-n", binary], capture_output=True, text=True, check=True).stdout
syms = []
for line in out.splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[1] in ("t", "T"):
        syms.append((int(parts[0], 16), parts[2]))
agg = collections.Counter(); cnt = collections.Counter(); total = 0
for (addr, name), (nxt, _) in zip(syms, syms[1:]):
    size = nxt - addr; total += size
    # Legacy Rust mangling: ...9detectors5slack...
    m = re.search(r"9detectors(\d+)([a-z_0-9]+)", name)
    key = "other"
    if m:
        n = int(m.group(1)); key = "detectors::" + m.group(2)[:n]
    agg[key] += size; cnt[key] += 1
print(f"text bytes (sum of deltas) {total}")
for k, v in agg.most_common(top):
    print(f"{v:8d} {100*v/total:5.2f}% n={cnt[k]:4d} {k}")
det = sum(v for k, v in agg.items() if k.startswith("detectors::"))
print(f"detectors::* {det} ({100*det/total:.1f}%)")
