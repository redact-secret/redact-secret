#!/usr/bin/env python3
"""Write a copy of a wasm module without its `name` custom section (measurement only).

Usage: wasm_strip_names.py <in.wasm> <out.wasm>
Prints the removed section's raw size. The copy is never shipped.
"""
import sys
def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80: return r, i
b = open(sys.argv[1], "rb").read(); out = bytearray(b[:8]); i = 8; removed = 0
while i < len(b):
    start = i; sid = b[i]; i += 1; n, i = leb(b, i); end = i + n
    keep = True
    if sid == 0:
        l, j = leb(b, i)
        if b[j:j+l] == b"name": keep = False; removed += end - start
    if keep: out += b[start:end]
    i = end
open(sys.argv[2], "wb").write(out)
print(f"removed name section {removed} B")
