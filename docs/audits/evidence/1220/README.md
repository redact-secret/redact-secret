---
owner: #1220
reviewed_source: db0e5c8ddf706988967e971593f509daf460c222
status: deferred
retire_on: after-issue:#1220
---

# Evidence: #1220, WebAssembly size of the comparison, and JavaScript conformance coverage

Measurement record for
[#1220](https://github.com/redact-secret/redact-secret/issues/1220) (epic
[#1216](https://github.com/redact-secret/redact-secret/issues/1216)). The
decision
[`decision-explain-and-compare-action-policies-over-one-detection-pass`](../../../decisions/2026-10-06-explain-and-compare-action-policies-over-one-detection-pass.md)
puts the comparison and the SHA-256 in the Rust core, so every WebAssembly
artifact links them once a binding exports the comparison, and left the brotli
increment to the binding track. This record freezes that measurement and states
what the JavaScript conformance run does and does not reach. All inputs are
synthetic.

## Identity of what was built

| Item | Value |
| --- | --- |
| Baseline | the branch head `c709ce2f` (the Rust core and CLI part of #1220 on top of #1219): the core already holds the comparison and the SHA-256, and no binding exports the comparison, so the comparison is present and unlinked |
| Candidate | the #1220 JavaScript change on top of the baseline: the `compareActionPolicies` exports of `bindings/node` and `bindings/wasm` and the package |
| Build | `node scripts/build-browser-artifact.mjs --detector-profile full` and `--detector-profile common`, release profile, `wasm-bindgen` 0.2.128, no `wasm-opt`, both built in the same worktree path so embedded source paths do not differ |
| Size | brotli quality 11 of each `*_bg.wasm`, through Node `zlib`, the call `scripts/measure-detector-cost.mjs` (`brotliSize`) makes |
| Host | macOS 26 (Darwin 25.5.0), arm64, Node v22.16.0 |

## Result

| Artifact | Baseline brotli (raw) | Candidate brotli (raw) | Brotli increase |
| --- | --- | --- | --- |
| `full` | 171,919 (643,946) | 176,282 (660,659) | +4,363, 2.54% of the baseline `full` |
| `common` | 123,785 (444,308) | 128,114 (461,053) | +4,329, 3.50% of `common`, 2.52% of baseline `full` |
| `full` + `pii` | 270,450 (942,512) | 274,706 (959,270) | +4,256, 2.48% of baseline `full` |
| `common` + `pii` | 220,910 (743,054) | 225,522 (759,831) | +4,612, 2.68% of baseline `full` |

Against the [#1219 record](../1219/README.md) the `full` figure moved from
170,442 (the parser, no digest, no comparison) to 171,919 at the baseline (the
core change since: the digest computed at every policy load among it) to 176,282
here. Against the `db0e5c8d` build of `main` the parser, the digest and the
comparison together add 11,493 bytes to `full` (164,789 to 176,282, 7.0%).

The decision set no stop gate for the binding track; the cost is accepted as long
as it is recorded. The increment is above 2% of `full` on top of the #1219
parser, so it is reported here rather than absorbed, and the cheap reductions
below were tried before accepting it.

## Where the bytes are

`full` only, brotli, each row a diagnostic build of an earlier revision of the
same branch with one change (the baseline is 171,919). That revision's
flat-array build was 176,348, 66 bytes above the final 176,282 as the source
moved around it, so the rows are read against their own flat-array row:

| Build | Brotli | Over the baseline |
| --- | --- | --- |
| the export takes and validates its arguments (`plan_sides`, the argument glue) and returns a number without running anything | 172,832 | +913 |
| as above, and runs the core comparison and the callback adapters, returning a number | 175,426 | +3,507 |
| the flat-array build of that revision: also flattens the result into one array | 176,348 | +4,429 |
| a nested object result (one property write and one key string per field) instead of the flat array | 177,229 | +5,310 |
| the flat-array build with the side kinds passed as codes (`Vec<u8>`) instead of strings | 176,230 | +4,311 |

So about 900 bytes are the argument glue, about 2,600 the core comparison and its
call, and about 900 the flat result. Two reductions were evaluated:

- **Flat result array: taken, -881.** The WebAssembly artifact returns one flat
  array of strings, numbers, booleans and `null`; `decodeComparison` in
  `runtime/wasm-binding.ts` rebuilds the nested shape the Node addon returns, and
  `bindings/wasm/src/compare.rs` documents the layout. A second, independent
  decoder in `scripts/lib/action-policy-compare-reference.mjs` checks it against
  the real artifact, so a drift in either shows as a disagreement.
- **Side kinds as numeric codes: rejected, -118.** It is less self-describing for
  118 bytes (0.07% of `full`), so the strings stay.

Not linking the comparison into paths that do not use it is already the case:
`compareActionPolicies` is the only export that reaches the comparison, and the
baseline measures the comparison unlinked. Nothing else shrinks it without
changing the core's accepted API. The figures differ by a few hundred bytes
between builds of the same source state, so a re-measurement should expect that
spread.

## JavaScript conformance coverage

`conformance/fixtures/action-policy-compare-v1.json` runs through
`scripts/lib/action-policy-compare-reference.mjs`, called from
`scripts/qualify-node-addon.mjs` (both profiles) and
`scripts/qualify-node-wasm-fallback.mjs` (both profiles), against the real built
addon and the real built WebAssembly artifacts. Each runs the fixture twice:
once against the raw exports (UTF-16 offsets, the parallel `kinds`, `documents`
and `callbacks` arguments) and once through the published package
(`@redact-secret/core`, `@redact-secret/core/common`), resolved as an installed
consumer resolves it.

| Fixture part | JavaScript run |
| --- | --- |
| 8 cases | all, on `full`: per finding the action, basis, rule id, rule index and `differs`, the per-side counts, kinds and document digests, the changed count and the callback call sequence; the `base` sentinel is resolved from the surface's own no-policy `scan` of the same input, so no default is copied. On `common` the cases whose input does not yield the fixture's findings (6 of 8: the GitHub token is a `full` provider detector) skip the fixture's own expectations, counted, and keep every check that does not depend on them |
| 7 error cases | all: the code, the exact callback call sequence, and that a failed comparison returns no result, including both bounds failing before any callback |
| 4 digests | all: the fixture's digest, this runtime's own SHA-256 of the same bytes (Node `crypto`), and that whitespace changes it |
| 8 host obligations | 7 run. `detection-runs-once` is not observable through a JavaScript surface (a callback sees findings, never detector calls) and is reported as such, not skipped silently; the package also runs the object form of `digest-is-over-the-exact-document-bytes`, the raw surfaces only the bytes form |
| enforcement parity | for every case, each declarative side's action equals what `scan` with that document returns for the same finding, and the default side equals `scan`'s default; the comparison leaves a `scanAndRedact` output and a callback's `scan` call log unchanged when it runs between two enforcement calls, and a one-side callback comparison has `scan`'s exact call sequence |
| callback failures | a throw is `POLICY_FAILURE`, a string outside the four names is `INVALID_POLICY_ACTION` and a non-string or `undefined` return is `POLICY_FAILURE`, in `scan` and in the comparison, identically on both runtimes, with the calls stopping at the failing finding |
| no plaintext | on every case the serialized result holds neither the input nor any 12-code-unit window of a matched span |
| incremental and stream | no export of the addon, the glue or the package mentions a comparison other than the whole-input function, an incremental session exposes no comparison member, a chunk array, bytes or an async iterable as input is `INVALID_INPUT`, and an `incremental`, `stream`, `chunks` or incremental-limit key, an unknown side kind and a field of another kind are `INVALID_OPTIONS` |
| public shape (package only) | the result is frozen all the way down, survives `structuredClone` and JSON unchanged, names `mode: "preview"`, `enforced: false`, its range unit and package version, and labels the sides `baseline`, `candidate-1`, ... |

Each run computes a SHA-256 over the canonical result of every case, error and
digest. The addon run and the WebAssembly run of the same profile print the same
value, and each package run must equal its raw run:

| Profile | Result digest (both runtimes) |
| --- | --- |
| `full` | `3208d6b05e291a1ba51255c9b68696bf7b6ccdf43ae8c0bc384d6c29031f16dc` |
| `common` | `bdecf38ffd9a9f5593190658baafbd9e93a93105d3c48c6d48a77dd2228c2d28` |

The browser-package harness (Chromium, Firefox and WebKit pages) and the workerd
qualification each gain one check that compares a default, a document and a
callback side through the public package on the real artifact. The comparison
glue is the same generated JavaScript in every engine, so the Node runs above
carry the semantics and these two carry the loading.

The gap: a JavaScript surface cannot construct a finding without scanning, so the
fixture's `base` can only be resolved on inputs the surface detects (every `full`
case; two of the eight `common` cases). The Rust core runs every case for
semantics.
