---
name: dependency-audit
description: Scan this repository's dependencies across Rust, npm, and PyPI for known vulnerabilities and registry-signature problems with cargo-deny, OSV-Scanner, and npm audit signatures, separating what ships in a published artifact from dev-only tooling. Use when asked to audit dependencies, before a release, or for "dependency-audit", "/dependency-audit". Report-only.
---

# dependency-audit

Answer one question: does any dependency we ship or build with have a known vulnerability, a yanked version, or a bad registry signature?

## Run

1. **Rust workspace (covers the core, the CLI, and all three bindings crates in one pass — `deny.toml` is workspace-wide):**
   `cargo deny check` (advisories against `RustSec`, plus the license gate). Record the advisory database's fetch time.
2. **JavaScript (root lockfile covers `packages/javascript` and every dev tool together):**
   `npm ci` from a clean tree, then `osv-scanner scan source -L package-lock.json --format json`. Record the OSV-Scanner version and scan time.
3. `npm audit signatures` — verifies registry signatures and provenance attestations for every installed npm package.
4. **Python:** confirm `bindings/python/pyproject.toml` still declares `dependencies = []` (the shipped wheel is a compiled extension with no runtime Python dependencies). If it does, state that explicitly and skip a Python SCA tool — there is nothing for one to scan. If it no longer does, treat that as a finding on its own (an unreviewed new runtime dependency) before running anything further.
5. **Published-artifact integrity**, using this repository's own verification scripts rather than re-deriving the check: `python3 scripts/verify-crate-digest.py` (crates.io), `python3 scripts/verify-python-digest.py` (PyPI wheel), `node scripts/verify-registry-install.mjs` (npm). Report whether each currently passes against the pinned release manifest; do not reimplement their hashing.

## Classify every hit

- **Shipped, third-party:** currently only the Rust crate graph — `unicode-normalization` (core), plus `napi`/`napi-derive` (Node binding), `wasm-bindgen`/`js-sys` (wasm binding), `pyo3` (Python binding), all covered by `cargo deny check`.
- **Shipped, first-party:** `@redact-secret/core`'s only runtime/optional dependencies are this repository's own published packages (`@redact-secret/wasm`, the eight `@redact-secret/node-*` platform packages). A vulnerability here means a hole in this repository's own release, not a third-party supply-chain issue — treat it with the same urgency as a core defect, not a dependency bump.
- **Build/test only:** the root `package.json` devDependencies (TypeScript, Vitest, etc.), Rust `dev-dependencies` (`serde_json`, `wasm-bindgen-test`), the Python `test` extra (`pytest`), and the `maturin` build backend. None of these reach a published artifact.
- **Reachable?** State whether the vulnerable function is used by our code or tests. Say "not assessed" when unsure; never guess "not reachable".

## Output

| Class | Package@version | Advisory (RustSec/OSV/GHSA/CVE) | Severity | Fixed in | Reachable | Action |
| --- | --- | --- | --- | --- | --- | --- |

Then: the `cargo deny check` advisory/license summary, the `npm audit signatures` summary (verified, missing, invalid), and whether each of the three published-artifact integrity scripts currently passes. Verdict: `no known vulnerabilities in shipped dependencies` or the counts.

## Rules

- Do not upgrade anything. A dependency version bump that changes the crate/package graph needs its own reviewed change (and, for the Rust core, may need a new qualification run) — propose it instead of applying it.
- Never paste tokens. If a registry call needs auth, stop and say so.
