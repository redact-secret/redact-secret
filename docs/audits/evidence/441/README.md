# Issue #441 — declarative ruleset parser WebAssembly size increment

[Audit archive](../README.md) · [Issue #441](https://github.com/redact-secret/redact-secret/issues/441)

Measured 2026-09-19 at commit `341c34413d7246bec4037c9969368f2478dd1bbf`
(`workbench/441-declarative-rulesets`, branched from `main`), working tree
otherwise clean. This is the "First task, before the ADR is written"
measurement #441 asks for: the real compiled WebAssembly size cost of adding
a minimal, representative "the core parses the declarative ruleset format
itself" parser (option A, `decision-declarative-detector-ruleset-contract`),
so the ADR carries a measured number instead of an estimate. It changes no
shipped detector, no public API, and ships no artifact.

## Files

| File | Contents |
| --- | --- |
| [`artifact-sizes.json`](artifact-sizes.json) | Before/after WASM raw, gzip, brotli, and JS-glue sizes, the delta, and the #378 reference baseline. |
| [`ruleset_prototype.rs`](ruleset_prototype.rs) | The exact 371-line prototype parser module that was measured. |
| [`scaffold.diff`](scaffold.diff) | The two-file wiring diff (`crates/secret-scan-core/src/lib.rs`, `bindings/wasm/src/lib.rs`) that made the prototype reachable under LTO. |

Both `ruleset_prototype.rs` and `scaffold.diff` are captured for
reproducibility only. Neither ever reached `main`; both were reverted with
`git checkout --` and `rm` immediately after this measurement, the same
discipline `scripts/measure-detector-cost.mjs` uses for its own patches
(see `docs/audits/evidence/378/README.md`).

## What was measured

`scripts/measure-detector-cost.mjs` itself measures detector-composition
variants by commenting out `built_in_detectors()` entries; it has no
"add a new module" mode, so this measurement reused its size-measurement
primitives directly (`gzipSize`, `brotliSize`, both imported from the
script unmodified) around the same build path it calls
(`scripts/build-browser-artifact.mjs`, i.e. `cargo build --release --target
wasm32-unknown-unknown` + `wasm-bindgen 0.2.128`, matching the pinned CLI
version), rather than its variant-patching mechanism.

1. **Before:** built the unmodified tree.
2. **After:** added `crates/secret-scan-core/src/ruleset_prototype.rs` (a
   hand-written, dependency-free, `unsafe`-free line-oriented tokenizer —
   `allowed-dependencies` stays `[]`, consistent with option A's constraint)
   and wired one call to it from `bindings/wasm/src/lib.rs::initialize()`
   through `std::hint::black_box` on both the input and the result, so LTO
   cannot prove the call has no externally observable effect and strip it,
   while `initialize()`'s own behavior is unchanged (the wired sample always
   parses successfully). Built again.
3. Reverted both files and deleted the new module; confirmed `git status
   --porcelain` clean before writing this evidence.

The prototype is deliberately representative of the shape issue #441
settles, not a preview of the real implementation:

- fixed closed enums for the alphabet name (mirroring
  `crates/secret-scan-core/src/detectors/pattern.rs`'s existing `Alphabet`
  set) and a single-member placeholder validator enum;
- a `ruleset-revision` check that rejects any value but `"1"`;
- fail-closed, input-free rejection of an unknown field, alphabet, validator,
  or specificity claim, an out-of-bounds run length, a too-short prefix, a
  duplicate detector id, or too many detectors in one ruleset, each as a
  fixed enum variant with no rejected content carried in it;
- no partial load: the whole input is validated before any detector spec is
  returned (7 unit tests in the module cover the valid-parse and each
  rejection-class path; all pass: `cargo test -p redact-secret --lib
  ruleset_prototype`).

It does **not** implement the real cost bounds, the specificity cap, or the
final fixed error catalog — those are the ADR's job and a follow-up
implementation issue's job, not this measurement's. The measured number is
therefore a representative floor for "parser code of roughly this shape and
complexity," not a final number for the shipped parser.

## Result

| | WASM raw | WASM gzip | WASM brotli | JS glue raw |
| --- | --- | --- | --- | --- |
| Before | 289,029 B | 99,463 B | 80,014 B | 31,344 B |
| After | 295,802 B | 102,331 B | 82,344 B | 31,344 B |
| Delta | +6,773 B | +2,868 B | +2,330 B | +0 B |
| Delta, % of before | +2.34% | +2.88% | +2.91% | — |

For comparison, `docs/audits/evidence/378/README.md` measured `full` at
281,346 B raw / 77,407 B brotli at an earlier commit; the 289,029 B / 80,014
B "before" figure above reflects unrelated size growth in the tree since
then (more detector precision fixes, the invisible-normalization work, and
other changes outside this measurement's scope), not anything this
measurement changed. The delta is computed against this measurement's own
before/after pair, built back to back from the same toolchain and commit,
which is the only comparison that isolates the parser's cost.

## Reading the number

A ~2.9% brotli increment for a 371-line prototype that covers only a subset
of the real design's validation surface (no cost-bound enforcement beyond
one run-length cap, no ordering/specificity-cap machinery, no fixed public
error catalog) is a reasonable proxy for "this lands in the low single-digit
percent of `full`'s WASM size," consistent with the issue's framing that the
parser is real but bounded cost, not a second detection engine. It is paid
once, by every consumer's compiled artifact regardless of detector profile
or of whether that consumer ever supplies a ruleset — the same "engine
floor" property `decision-define-detector-profile-and-pack-contract`
measured for the base pipeline/registry code. The ADR should treat this as
a lower bound: the real implementation adds more validation (full cost
bounds, the closed validator enum's real membership, ordering enforcement)
that this prototype only partially represents.
