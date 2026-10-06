# Evidence: #1219, WebAssembly size of the action policy parser, and JavaScript conformance coverage

Measurement record for
[#1219](https://github.com/redact-secret/redact-secret/issues/1219) (epic
[#1216](https://github.com/redact-secret/redact-secret/issues/1216)). The
decision
[`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](../../../decisions/2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md)
puts the parser in the Rust core, so every WebAssembly artifact links it, and
asked #1219 to measure the brotli increment. This record freezes that
measurement and states what the JavaScript conformance run does and does not
reach. All inputs are synthetic.

## Identity of what was built

| Item | Value |
| --- | --- |
| Baseline | `db0e5c8d` (`main`, `0.1.0-beta.13`), built in the same worktree path as the candidate so embedded source paths do not differ |
| Candidate | the #1219 JavaScript change on top of the Rust core and CLI commit `84998559` |
| Build | `node scripts/build-browser-artifact.mjs --detector-profile full` and `--detector-profile common`, release profile, `wasm-bindgen` 0.2.128, no `wasm-opt` |
| Size | brotli quality 11 of each `*_bg.wasm`, through Node `zlib`, the call `scripts/measure-detector-cost.mjs` (`brotliSize`) makes and `scripts/measure-wasm-profiles.mjs` uses |
| Host | macOS 26 (Darwin 25.5.0), arm64, Node v22.16.0 |

The baseline `full` figure, 164,789, equals the figure the
[#1221 evidence](../1221/README.md) records for the same commit.

## Result

| Artifact | `db0e5c8d` brotli (raw) | Candidate brotli (raw) | Brotli increase |
| --- | --- | --- | --- |
| `full` | 164,789 (618,395) | 170,442 (639,432) | +5,653, 3.43% of `full` |
| `common` | 116,647 (418,579) | 122,535 (439,801) | +5,888, 3.57% of `full`, 5.05% of `common` |
| `full` + `pii` | 262,175 (917,156) | 268,265 (938,177) | +6,090, 3.70% of `full` |
| `common` + `pii` | 214,169 (717,495) | 219,420 (738,725) | +5,251, 3.19% of `full` |

The decision first proposed 3% of `full` as a stop point and #1219 stopped at
it. That figure was an estimate with no repository budget behind it, so the
decision now records these increments as the accepted cost and replaces the
stop with a regression note: later growth of the parser re-measures against
this table.

## Where the bytes are

Diagnostic builds of an earlier revision of the same branch, in a scratch copy
of the repository (a different path, which moved the control by 25 bytes),
`full` only, brotli:

| Build | Brotli | Over `db0e5c8d` (164,789) |
| --- | --- | --- |
| `db0e5c8d` WebAssembly binding sources against the candidate core (the parser present and unlinked) | 164,814 | +25, the path difference |
| the full change | 170,789 | +6,000 |
| without the `defaultPolicy` export | 170,004 | +5,215 |
| without it, and with a class-only rejection message (no rule index) | 169,853 | +5,064, 3.07% |

The parser, not the binding glue, is the cost: removing both optional extras
leaves it above 3%. The figures differ by a few hundred bytes between builds of
the same source tree state (`full` was 170,789 and then 170,442 as unrelated
code around it changed), so a re-measurement should expect that spread. The
`defaultPolicy` export costs roughly 800 bytes. It calls the core's public
`DefaultPolicy` over a finding the core validates; the default table itself is
crate-private, so a cheaper exact route would need a new core API.

## JavaScript conformance coverage

`conformance/fixtures/action-policy-v1.json` runs through
`scripts/lib/action-policy-reference.mjs`, called from
`scripts/qualify-node-addon.mjs` (both profiles) and
`scripts/qualify-node-wasm-fallback.mjs` (both profiles), against the real
built addon and the real built WebAssembly artifacts. Each runs the fixture
twice, once against the raw exports (UTF-16 offsets, the fixed class and rule
index parsed from the error message) and once through the published package
(`@redact-secret/core`, `@redact-secret/core/common`), resolved as an installed
consumer resolves it.

| Fixture part | JavaScript run |
| --- | --- |
| 17 first rejections and 41 additional rejections | all, as `INVALID_ACTION_POLICY`; the raw exports also compare the exact class and rule index; the package compares the code and the one fixed message, and both whole-input and session construction must agree |
| 11 named policies and 7 accepted edge documents (bounds) | all load, including the 65,536-byte document, 128 rules and 256-member sets |
| 5 end-to-end cases | all on `full`; on `common` the cases whose no-policy scan does not reproduce the fixture finding are skipped and counted; whole input and `scanAndRedact` text against an independent reference redaction |
| incremental sessions (`alsoIncremental`) | every split into two chunks, a sample of three-way splits, and one chunk per code unit |
| 7 host obligations | all, including `legacy-callback-invalid-action`, `callback-and-action-policy-together` (whole input and session, with a document that would also be rejected), `session-binds-policy-at-construction` and `no-process-global-policy-slot` in both construction orders |
| 7 base anchors | all, through the raw `defaultPolicy` and the package's `defaultPolicy.evaluate` |
| 37 evaluations | the evaluations whose finding a synthetic input produces; the rest are the gap below |

The gap: a JavaScript surface cannot construct a finding without scanning, and
no synthetic input produces `jwt-medium`, `contextual-low`, the unknown type and
detector findings, or the not-yet-emitted names. 14 of the 37 evaluations are
therefore not run in JavaScript and are counted as such in the run output; the
Rust core runs all 37 for semantics. `expectedRule` is not observable on any
surface until #1220, so only the resulting action is compared.

The run also found that a whole-input WebAssembly policy callback returning a
string outside the four action names reported `POLICY_FAILURE` while the Node
addon and the incremental WebAssembly session reported `INVALID_POLICY_ACTION`.
The fixture's host obligation names the latter, and the WebAssembly call now
reports it (a thrown exception and a non-string return stay `POLICY_FAILURE`
everywhere).
