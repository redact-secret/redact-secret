# #1164 - exact `eyJ` discovery in the JWT detector

Product judgement. Final record for
[#1164](https://github.com/redact-secret/redact-secret/issues/1164) (parent
#1068, epic #1065). Verdict: **adopted**, behavior-preserving, with a
dense-input check that the issue's own numbers left open. Baseline:
`origin/main` at `a2b2aa6c`, which already carries #1132 (streaming Supabase
payload check); this change builds on it and leaves that code and its oracle
tests (`oracle_is_supabase_legacy_anon_claim`, the `streaming_check_*` tests)
untouched and passing. All inputs are synthetic; no value is printed.

## Change

`crates/secret-scan-core/src/detectors/jwt.rs`: `JwtDetector::detect` tested
the three lead bytes at every offset. It now jumps to the next exact `eyJ`.
Everything after discovery is unchanged: `match_jwt_at` (segment floors,
alphabet), the token-boundary check, the Supabase anon exception, failure
cursor +1, and resumption at the raw match end even when the match was blocked.

`crates/secret-scan-core/src/detectors/pattern.rs`: `find_literal` now
delegates to a new `find_literal_with(lead, bytes, needle, from)` that takes
the prebuilt `LeadBytes`. `find_literal`'s behavior and all its other callers
are unchanged. `detect` builds the `eyJ` lead table once per call instead of
once per search.

Why the second step: the first prototype called `find_literal` per search,
which rebuilds the 256-entry lead table each time. That was neutral on dense
input in later runs but regressed prefix noise by +7% to +11% in all three runs (variant A below); its very first, loaded run (`raw-stage-variantA-first-run.txt`) also read dense +9.2% and +13.2% (A/A +2.0% and +0.6%), which later quiet runs did not reproduce.
Building the table once removes that regression (-2% to -4%).

The jump is exact because `eyJ` cannot overlap itself (`y` is not `e`): the
per-byte scan with a +1 miss cursor visits precisely the offsets the search
returns. No unsafe, dependency, allocation or public API change.

## Equivalence

The pre-change loop is kept in the `jwt.rs` test module as
`detect_per_byte_oracle` (using the unchanged production helpers). Tests:

- `named_shapes_match_the_per_byte_scan`: over 30 shapes (empty, prefix-only,
  glued before and after, `.`/`-` neighbours, blocked then valid, short
  segments and signature at the 16/15 floor, multi-byte neighbours, Supabase
  anon and `service_role` tokens, repeated and nested `eyJ`);
- `a_blocked_match_still_resumes_at_its_raw_end`;
- `generated_inputs_and_every_window_match_the_per_byte_scan`: 4,000 seeded
  inputs from 22 pieces (must reach more than 100 real candidates) plus every
  char-boundary window of one dense input;
- `long_and_dense_inputs_match_the_per_byte_scan`: 100,000-byte run, 5,000 `eyJ`
  prefixes, 500 tokens, 2,000 failing prefixes before a token;
- public surface `tests/jwt_discovery_1164.rs`: pinned whole-input ranges, every
  UTF-8 byte partition and the one-byte partition of 11 shapes reproduce the
  whole-input text and findings, and sparse/dense/prefix-noise/malformed inputs
  at chunk sizes 1, 7, 64 and 4,096.

Mutation check: advancing the failure cursor by 5 instead of 1 fails the
generated-input test. Resuming at `at + 3` instead of the raw end is an
equivalent mutant (an inner `eyJ` after a dot is always blocked), noted for
honesty.

## Measurement

Stage (`timing-harness.rs.txt`, whole `JwtDetector::detect`, ns; old per-byte
scan vs variant A vs shipped variant B, plus an A/A control, 31-round
alternating medians, release `lto = "fat"`, Apple M-series arm64). Runs 2 and 3
(`raw-stage-final-run2.txt`, `-run3.txt`) were on a quieter host (A/A within
1.1%); run 1 (`-run1.txt`) was heavily loaded and is kept for completeness.

| Workload (bytes) | B vs old, run 2 | run 3 | run 1 (loaded) | A (per-search table) run 2 |
|---|---|---|---|---|
| sparse ASCII (72,050) | -55.2% | -54.9% | -62.6% | -55.4% |
| sparse Unicode (40,550) | -29.1% | -28.3% | -44.4% | -28.8% |
| dense, one token per 50 bytes (75,000) | +0.7% | +1.5% | +1.6% | -3.3% |
| dense, space-separated | +5.3% | -3.5% | +0.4% | -0.1% |
| prefix noise `eyJ eyJ. eyJabc.eyJ` (60,000) | -2.0% | -2.2% | -3.7% | +7.9% |
| `eyJTYNTH.` repeated (72,000) | -9.7% | -10.2% | -7.5% | -9.7% |
| no `eyJ` match (72,000) | -55.1% | -55.4% | -63.7% | -55.2% |
| one 100,000-byte base64url run | -37.5% | -37.3% | -36.5% | -37.4% |

Dense input is neutral within about 1.5%, with one 5.3% outlier row that the
next run reverses (-3.5%): the issue's "dense -2.8%" is not a gain to rely on,
and none is claimed. The gate is therefore met on the issue's terms (sparse
discovery gain, no dense or noise regression beyond the A/A band), with the
sparse figures as the benefit.

Whole scan (`whole-scan-harness.rs.txt`, public `scan`, default registry;
`raw-whole-scan-final.txt` for B, `raw-whole-scan-variantA.txt` for A): **not
resolved on this host**. The base-versus-second-base A/A control moved -4% to
-17% by itself, larger than the effect; the JWT rows read -22%/-22%/-17%/-14%
for variant A (A/A -14% to -18%) and -3.5%/+12%/+21%/+13% for B (A/A -16%,
-8%, -4%, -4%), i.e. inconsistent in sign. No whole-scan claim, and the dense
whole-scan reading of B should be re-qualified on the measurement engine
(`redact-secret-benchmarks#608`) before any whole-scan statement. A scan
reaches this detector only after the shared `eyJ` prefilter, so the stage
sparse gain applies to inputs that contain `eyJ` but few tokens.

Not measured: WASM, binary size, allocation counts (none added or removed).

## Disposition

Adopted. Behavior-preserving internals: no consumer-observable change, so no
`CHANGELOG.md` entry (needs the `no-changelog` label).

## Temporary in-repo measurement

No measurement file remains in the product tree (tracked in #1152; the
measurement moves to the measurement engine before the beta.13 release, and
`redact-secret-benchmarks#608` is the benchmarks-side reference). Used only
temporarily in the working copy, kept here as inert `.txt`, never built by
Cargo:

- `timing-harness.rs.txt`: a `#[cfg(test)]` module appended to
  `detectors/jwt.rs` that times old, variant A, shipped B and an A/A control
  (uses `std::time`, forbidden under `src/` by `scripts/check-rust-workspace.py`,
  so removed before commit);
- `whole-scan-harness.rs.txt`: temporary integration test
  `tests/zz_whole_scan_1162.rs` using the public `scan`, built against the base
  and the change (shared with #1162);
- raw outputs `raw-*.txt`. `examples/alloc_attribution.rs` was not used or
  changed.
