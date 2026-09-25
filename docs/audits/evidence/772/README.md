# Evidence: #772, qualifying the beta.9 shadow evidence scorer

**Result:** the shadow scorer's integer scores and bands are byte-identical on
Linux x86_64, macOS arm64, Windows x86_64 and `wasm32` for the conformance
corpora and a hostile battery (0 cross-runtime mismatches). Whole-input and
incremental comparisons are equal (0 mismatches). Hostile maximum-length and
periodic inputs stay within the scorer's stated bounds. The public path's
findings and allocations are unchanged from beta.8. The first candidate,
`d4bab4e`, linked the unreachable scorer into every shipped artifact and
breached the size budget (full WebAssembly +8.2% gzip). This pull request
removes it from non-test builds, and the fixed commit is back to beta.8's
size.

Issue [#772](https://github.com/redact-secret/redact-secret/issues/772),
parent epic [#767](https://github.com/redact-secret/redact-secret/issues/767).
The contract is
[`decision-freeze-the-shadow-evidence-score-and-confidence-contract`](../../../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md)
(sections 5 and 7). The permanent checks are described in
[`docs/specs/engine.md`, "Shadow scorer qualification"](../../../specs/engine.md#shadow-scorer-qualification).

This folder is the product judgement. Performance and size results, and the
judgement against the reviewed regression budgets, are benchmark measurement
and live in redact-secret-benchmarks
([#143](https://github.com/redact-secret/redact-secret-benchmarks/issues/143),
`evidence/772/`), per
[`decision-move-performance-results-criteria-and-judgement-to-benchmarks`](../../../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md).
The figures below are only the ones this judgement rests on.

## Source revisions

| Item | Identity |
| --- | --- |
| beta.8 baseline | tag `v0.1.0-beta.8` (`5639a0ea02e0eefbd1533bea23a05c749b529bef`); the benchmark baseline is its release source `3144bb32c6ebf8f1eefa2cbbad7d431d1d6e8c4c` |
| Parent of #769 | `0e3ba95` (core source identical to beta.8 under `crates/`) |
| First beta.9 candidate | `d4bab4ede21cae2b25f03a40f466b52dceadfda2` (#771 merged) |
| Fixed candidate | this pull request's head |
| Scoring artifact | revision 2, model `evidence-aggregation/v1` over `evidence-features/v1`, fingerprint `bf2ed67db72dabe69b97d248e547aa1e942cf98991a6b712dc6285629662afa9`; unchanged by this pull request (`npm run scoring-artifact:check`, also with `--base origin/main`) |

## 1. Size: the scorer was linked into shipped builds

`IncrementalSanitizer` held `shadow: Option<Vec<ShadowComparison>>` in every
build and called `detect` with it. The compiler could not prove the field is
always `None`, so the scorer and everything it reaches stayed in the library,
and so in every binding, the CLI and the WebAssembly module, with no public
caller. The `d4bab4e` WebAssembly module's name section held
`redact_secret::evidence::*` symbols; beta.8's held none.

The fix puts the field, its initializer, the `detect` call with a sink and
the recording block under `cfg(test)`, and outside tests the session calls
`run_detector_pipeline`. Shipped builds then contain no scorer. The
maintainer-local `shadow_evaluation` example and the unit tests still compile
and run it. Its output over the input set below is byte-identical before and
after the fix.

| Local build (macOS arm64, release) | `0e3ba95` | `d4bab4e` | fixed |
| --- | ---: | ---: | ---: |
| `redact_secret_wasm.wasm` before `wasm-bindgen`, raw bytes | 865,853 | 892,999 | 864,756 |
| same, gzip -9 | 229,178 | 240,175 | 228,951 |
| strings naming `evidence` | 0 | present | 0 |
| `redact-secret` CLI bytes | 762,560 | 798,144 | 762,464 |

The budget verdicts for both commits, with the original `d4bab4e` breach
kept, are in the benchmarks record.

## 2. Cross-runtime determinism

The input set is `node scripts/shadow-determinism.mjs inputs`: every fixture
of `conformance/fixtures/synchronous-corpus.json` (2,078),
`incremental-corpus.json` (97) and `unicode-conversion-corpus.json` (9), and
54 generated hostile inputs, 2,238 lines in all. The `shadow_evaluation`
example evaluates it on each host, for the `full` and `common` profiles.

| Host | How | Result |
| --- | --- | --- |
| Linux x86_64 (`ubuntu-latest`) | CI `rust-native`, release build | identical |
| macOS arm64 (`macos-latest`) | CI `rust-native`, release build | identical |
| Windows x86_64 (`windows-latest`) | CI `rust-native`, release build | identical |
| `wasm32-wasip1` on V8 (Node 24 WASI) | CI `rust-wasm`, release build | identical |
| macOS arm64 workstation, and `wasm32-wasip1` on Node 22.16 | local | identical |

CI job `shadow-determinism`: RUN_PLACEHOLDER. `full`: 3,834 comparisons, 1,217 of
them statistical, sha256
`78b07b9a40721d63904a0e42eebb9595760b0e9dec32883f5c9e71866e748952`.
`common`: 1,492 comparisons, 1,351 statistical, sha256
`8edc30ff72f563ea6d4bb1ae4e2e6a0d3d866610cb14f5476cdad4bce2e51d38`.
Statistical bands in `full`: 3 `none`, 46 `low`, 44 `medium`, 1,124 `high`.

The shipped `wasm32-unknown-unknown` binding cannot reach the scorer, which is
crate-internal. The `wasm32-wasip1` build compiles the same source with the
same wasm32 code generator, and the two differ only in the operating-system
layer, which the scorer does not use. On `wasm32-wasip1` the core's 1,280
unit tests, which include the evidence golden vectors, the artifact drift
test and the hostile-input tests, pass, and so does the canonical corpus
test. Locally, every other core integration test passes there too.

The Node addon, the Python wheels and the WebAssembly binding do not expose
the scorer. For them parity means that legacy outcomes are unchanged:

- A digest of every finding's detector, type, `Confidence`, range and action
  over the 2,238 inputs is equal at beta.8, `0e3ba95`, `d4bab4e` and the fix
  (3,834 findings each).
- The artifact-qualification runs replay the conformance corpora through
  every addon triple, every wheel, the browser engines and the CLI.
- No scorer source outside tests names floating point (new
  `scripts/check-rust-workspace.py` check 11).

**Finding outside this change.** On Node 22.23.2, the Node WASI host crashes
with SIGSEGV in the core's unit-test module. The crash comes in the test that
follows `the_evaluation_path_applies_the_default_whole_input_limits`, which
grows the module's memory past 64 MiB. Each test passes alone, and Node 22.16
and 24.21 run the whole module cleanly. CI therefore runs the WASI host on
Node 24. The shipped WebAssembly binding does not use WASI, and this change
does not show whether its memory growth is affected on that Node release.

## 3. Whole-input and incremental parity

0 mismatches:

- `evidence/shadow/tests.rs` (#771) compares every comparison of its battery
  at chunk sizes 1, 3, 7, 64 and whole.
- `evidence/qualification_tests.rs` (this change) does the same for the
  hostile values in three credential-bearing contexts, an input with 16
  maximum-length candidates and one with 128 periodic candidates, at chunk
  sizes 7, 64, 4,095, 4,096, 4,097 and whole.
- Both run on every native CI host and on `wasm32-wasip1`.

## 4. Hostile and periodic worst cases

A contextual value is at most 4,096 bytes, and a 4,097-byte one is not a
candidate. Feature extraction reads at most 256 scalar values and is bounded
by `256²` comparisons. The exclusion grammar reads the whole value once.

The tests pin the feature vectors of each feature function's worst case:

- period 32, the largest autocorrelation lag;
- period 33;
- 255 equal symbols then a break, the latest smallest-period failure;
- a de Bruijn sequence with no repeated bigram;
- one repeated symbol;
- 256 distinct astral symbols, the longest histogram scan;
- a random maximum-length value.

They also check that a 1 MiB value is described by its first 256 symbols
alone. There is no runtime model file, no network access and no
platform-specific learned artifact: the core's source boundary and dependency
checks (checks 1 and 7) forbid them, and the scorer's constants are Rust
source.

Maintainer-local cost, at the fixed commit on a shared, loaded macOS arm64
workstation (Apple M4), as medians. This is indicative only, because the
official timing profile is the benchmarks' Linux paired run.

| Measurement | Result |
| --- | --- |
| `extract_features`, worst of the pinned cases (256 distinct astral symbols) | 25.9 µs |
| `extract_features`, 1 MiB value | 5.4 µs |
| exclusion grammar on a 4,096-byte value | 2.7–5.1 µs |
| exclusion grammar on 1 MiB (never a candidate) | 691 µs |
| shadow path added to `detect`, 1 MiB with 2,893 contextual candidates | +5.6 ms on 98.6 ms (1.9 µs each) |
| shadow path added, 64 maximum-length candidates | +1.2 ms on 32.7 ms (19 µs each) |
| shadow path added, 672 periodic 4 KiB candidates | +1.0 ms on 270 ms |

The shadow path runs only in the maintainer-local evaluation example. The
public path does no scorer work.

## 5. Public-path throughput and allocations

The measurement is an A/B harness over the public API, built once against
each revision with the workspace release profile. It ran 6 interleaved rounds
per revision, each round the median of 9 timed runs, for `scan`,
`scan_and_redact` and 4 KiB incremental. The workloads were 1 MiB of logs,
1 MiB with contextual assignments, and 64 maximum-length candidates.

- Allocation counts and bytes are identical at beta.8, `0e3ba95`, `d4bab4e`
  and the fix for every workload and operation. This confirms the public
  path adds only an `Option` check before the fix and nothing after it.
- Timing differences stay within the workstation's noise. beta.8 and
  `0e3ba95` have identical core code, yet they differed by up to 33% between
  runs, so the table is not a budget input. The benchmarks' paired Linux run
  judges latency.

## 6. Q5 values for the #257 promotion contract

| Gate | Metric | Value |
| --- | --- | --- |
| `q5-cross-runtime-equality` | `runtime.crossRuntimeMismatches` | `0` (Linux, macOS, Windows, wasm32; `full` and `common`) |
| `q5-incremental-equality` | `runtime.wholeVsIncrementalMismatches` | `0` |
| `q5-bounded-worst-case` | `runtime.hostileInputsWithinCriteria` | `true` |
| `q5-performance-budgets`, `q5-size-budget` | `performance.budgetOutcome`, `size.budgetOutcome` | from the #143 verdict in redact-secret-benchmarks `evidence/772/` |

## Reproduce

```sh
rustup target add wasm32-wasip1
node scripts/shadow-determinism.mjs inputs > inputs.jsonl
cargo run --release --locked -p redact-secret --example shadow_evaluation < inputs.jsonl > native.jsonl
cargo build --release --locked -p redact-secret --example shadow_evaluation --target wasm32-wasip1
node --no-warnings scripts/wasi-run.mjs \
  target/wasm32-wasip1/release/examples/shadow_evaluation.wasm < inputs.jsonl > wasm32.jsonl
node scripts/shadow-determinism.mjs compare native=native.jsonl wasm32=wasm32.jsonl
CARGO_TARGET_WASM32_WASIP1_RUNNER="node --no-warnings $PWD/scripts/wasi-run.mjs" \
  cargo test -p redact-secret --target wasm32-wasip1 --locked --lib --test canonical_corpus
```
