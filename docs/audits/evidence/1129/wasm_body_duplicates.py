#!/usr/bin/env python3
"""Count byte-identical and near-identical function bodies in a WebAssembly module.

Usage: wasm_body_duplicates.py <module.wasm>
`exact` hashes the body bytes. Only byte-identical bodies are counted; near-identical bodies are not detected.
Reads names from the name section when present (function names only).
"""
import sys, hashlib, collections

def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80: return r, i

def main():
    b = open(sys.argv[1], "rb").read()
    i = 8; code = None; names = {}; nimp = 0
    while i < len(b):
        sid = b[i]; i += 1; n, i = leb(b, i); end = i + n
        if sid == 2:
            c, j = leb(b, i)
            for _ in range(c):
                for _ in range(2):
                    l, j = leb(b, j); j += l
                kind = b[j]; j += 1
                if kind == 0: nimp += 1; _, j = leb(b, j)
                elif kind == 1: j += 1; f = b[j]; j += 1; _, j = leb(b, j); (_, j) = leb(b, j) if f & 1 else (0, j)
                elif kind == 2: f = b[j]; j += 1; _, j = leb(b, j); (_, j) = leb(b, j) if f & 1 else (0, j)
                else: j += 2
        if sid == 10: code = (i, end)
        if sid == 0:
            j = i; l, j = leb(b, j); nm = b[j:j+l].decode(); j += l
            if nm == "name":
                while j < end:
                    sub = b[j]; j += 1; sl, j = leb(b, j); se = j + sl
                    if sub == 1:
                        cnt, k = leb(b, j)
                        for _ in range(cnt):
                            idx, k = leb(b, k); ln, k = leb(b, k)
                            names[idx] = b[k:k+ln].decode(errors="replace"); k += ln
                    j = se
        i = end
    i, end = code; cnt, i = leb(b, i)
    bodies = []
    for _ in range(cnt):
        sz, i = leb(b, i); bodies.append(b[i:i+sz]); i += sz
    total = sum(len(x) for x in bodies)
    ex = collections.defaultdict(list)
    for k, x in enumerate(bodies): ex[hashlib.sha1(x).hexdigest()].append(k)
    dup = {h: v for h, v in ex.items() if len(v) > 1}
    waste = sum(len(bodies[v[0]]) * (len(v) - 1) for v in dup.values())
    print(f"functions {cnt} code bytes {total}")
    print(f"exact-duplicate groups {len(dup)} redundant bytes {waste} ({100*waste/total:.2f}% of code)")
    for h, v in sorted(dup.items(), key=lambda kv: -len(bodies[kv[1][0]]) * (len(kv[1]) - 1))[:10]:
        print(f"  {len(bodies[v[0]])}B x{len(v)}: " + " | ".join(names.get(k + nimp, "?")[:60] for k in v[:3]))
main()
