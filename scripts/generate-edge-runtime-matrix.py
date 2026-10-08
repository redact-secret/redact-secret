#!/usr/bin/env python3
"""Render the declared, evidence-scoped edge matrix; --check detects drift."""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render(data):
    statuses = data["statuses"]
    lines = [
        "# Edge runtime support matrix",
        "",
        "Generated from `docs/reference/edge-runtime-matrix.json` by",
        "`python3 -B scripts/generate-edge-runtime-matrix.py`. The initial target is",
        "Cloudflare Workers; other runtimes need their own observed consumer artifact.",
        "",
        "| Runtime | Status | Qualification scope | Evidence and limits |",
        "| --- | --- | --- | --- |",
    ]
    for runtime in data["runtimes"]:
        if runtime["status"] not in statuses:
            raise ValueError("unknown edge runtime status")
        identity = f" Source `{runtime['sourceCommit']}`." if runtime.get("sourceCommit") else ""
        lines.append(
            f"| {runtime['name']} | `{runtime['status']}` | {runtime['scope']} | {runtime['evidence']}.{identity} {runtime['limits']} |"
        )
    lines += ["", "## Status meanings", ""]
    for status, meaning in statuses.items():
        lines += [f"**`{status}`**: {meaning}", ""]
    lines += [
        "## Reproduction and measurement boundary",
        "",
        "See [qualification](qualification.md#cloudflare-workers-and-vercel-edge-decision-verify-edge-runtimes)",
        "for packing, installation, and the four real-workerd checks. Every new full",
        "qualification inventory requires matching source, tool versions, package digests,",
        "and selected WASM digests. Browser success alone does not qualify an edge runtime.",
        "",
        "Reports include selected WASM raw/gzip size, first initialization wall time, and",
        "21 warm batches of 100 `scanAndRedact` calls, normalized per call, on the named",
        "synthetic fixture, with exact UTF-8",
        "byte and UTF-16 code-unit sizes. Zero timing samples may be below clock resolution.",
        "Offline Wrangler dry-run records the qualification worker's JS/WASM module hashes",
        "and raw/gzip sums, including smoke-check code. These are raw observations, not",
        "every consumer's bundle, cold process startup, CPU budgets, or memory measurements.",
        "Timers describe local Wrangler, not deployed CPU time (deployed timers advance",
        "after I/O). Workerd exposes",
        "no worker memory counter; memory remains unavailable. Bundle/startup/scan budget",
        "judgements and retained measurement evidence belong in `redact-secret-benchmarks`.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render(json.loads((ROOT / "docs/reference/edge-runtime-matrix.json").read_text()))
    target = ROOT / "docs/edge-runtime-matrix.md"
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit("edge runtime matrix is stale; regenerate it")
    else:
        target.write_text(content)
