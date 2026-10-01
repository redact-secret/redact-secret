---
name: invariant-fuzz
description: Property-based fuzzing of the redact-secret core's security invariants with fast-check against the built @redact-secret/core package. Generates random text, policy configuration, and chunk partitions and reports any counterexample with its seed. Use when asked to fuzz the core or check its invariants ("invariant-fuzz", "/invariant-fuzz 20000", "fuzz the incremental sanitizer").
---

# invariant-fuzz

Break the core's security invariants with generated inputs. Report counterexamples, not opinions.

## Setup

- Build first: `npm run js:build`. Test `packages/javascript`'s built output through the public API only (`scan`, `scanAndRedact`, `redact`, the incremental sanitizer, `initialize`) — never an internal module path.
- Properties live in the committed `packages/javascript/test/fuzz.test.ts` (vitest; it runs inside `npm run js:test`). It is deterministic: fixed seed `1143`, 2000 runs per property (about 5 seconds). `fast-check` is an exact-pinned root devDependency.
- It needs a real engine: the N-API addon or the WebAssembly artifact. A source checkout has neither, so the suite is skipped (visibly) there; set `REDACT_SECRET_FUZZ_REQUIRE_ARTIFACT=1` to make a missing artifact a failure. Build the addon locally with `cd bindings/node && npm ci --ignore-scripts && npx napi build --platform --release`, then link it as `packages/javascript/node_modules/@redact-secret/node-<platform>` (what `scripts/qualify-node-addon.mjs` does).
- Run: `npm run js:build && npx vitest run --root packages/javascript test/fuzz.test.ts`. For a manual large run set `REDACT_SECRET_FUZZ_RUNS=20000` and/or `REDACT_SECRET_FUZZ_SEED=<int>` (the count applies per property; 20000 runs takes about 40 seconds).
- A known violation is kept as an `it.fails` test, which passes while the violation exists and goes red once the core is fixed. Do not weaken the property.

## Invariants

Generators: text mixing conformance-style fixtures (`ghp_SYNTHETICxREVOKEDxTESTx0000000000000`, `AKIASYNTHETIC0TEST00`, `password=SYNTH_REVOKED_42`), adversarial Unicode (unpaired surrogates, ZWJ emoji, RTL/bidi control characters, combining marks), oversized and many-candidate input, `$`-replacement-pattern-looking strings, random policy/action selection per family (`redact`/`warn`/`allow`), random chunk partitions of the same input for the incremental sanitizer, and `finding` objects fed directly into `redact` — some genuine `scan` output, some forged (altered range, classification, or action).

1. **No plaintext leakage.** No matched candidate substring appears in a finding's fields, a thrown error (message, stack, JSON, own properties), or anywhere in output text the selected action was supposed to replace.
2. **Placeholder boundary.** Every placeholder inserted for a `redact`-selected finding is at most 256 UTF-8 bytes and can never itself contain a replaced matched range, including ranges shorter than four native range units.
3. **Action gate.** A `redact`-policy finding never leaves matched text in the output. `warn`/`allow` leaves the original matched text in the output unchanged, byte-for-byte, and the result's pass-through accounting reflects it.
4. **Determinism.** The same input and configuration, scanned any number of times, produce identical findings and output — across repeated calls in one process.
5. **Incremental / whole-input equivalence.** For any chunk partition of the same input pushed through the incremental sanitizer, the concatenated output and the finding set equal the whole-input `scanAndRedact` result for that input. (This is the same class of invariant the Rust core already unit-tests for specific registries; this fuzzer checks it black-box against the built JS/wasm package across hundreds of random partitions instead of one fixed case.)
6. **Range validity.** Every finding's range lies within the input's bounds in its declared native range unit, and no range splits a UTF-8/UTF-16 code unit.
7. **Findings-supplied-to-`redact` validation.** A forged, out-of-range, or malformed `finding` object passed directly to `redact` is always rejected with a fixed error — never an out-of-bounds panic, an out-of-bounds slice, or a silent redaction at the wrong range.
8. **No implicit persistence.** No network, filesystem, storage, or console access occurs during a fuzz run (spot-check once via the packed artifact per `SECURITY.md`, not on every run).

## Output

For each violated invariant: the invariant, the fast-check seed and path, the shrunk counterexample with plaintext values replaced by fixture names, and the observed vs expected result. End with `N runs, seed S: all invariants held` or the violation count.

## Rules

- Synthetic values only. Never print plaintext from a failing case; name the fixture instead.
- Do not change product code. Propose a conformance case (`conformance/fixtures/`) for each confirmed violation.
