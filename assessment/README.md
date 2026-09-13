# Cross-language evaluation protocol

This directory defines the language-neutral evaluation protocol described by
[`decision-define-cross-language-evaluation-protocol`](../docs/decisions/2026-09-12-define-cross-language-evaluation-protocol.md):
a synthetic assessment corpus, a set of named workload profiles, and a common
result contract that every supported surface — the Rust core, Python, Node,
the browser WebAssembly artifact, and the CLI — reports through.

It is not the behavioral contract. [`conformance/`](../conformance/README.md)
remains the single executable contract every binding must pass to release.
This directory measures accuracy and performance against a shared contract
and is never itself a release gate; a low score here is a finding to act on,
not a build failure.

## Files

- [`schema.ts`](./schema.ts) — the canonical `AssessmentFixture`,
  `AssessmentWorkloadProfile`, and `AssessmentResult` types, plus
  `validateAssessmentFixtures`, `validateAssessmentWorkloadProfiles`, and
  `validateAssessmentResults`: pure-data validators with input-free
  diagnostics (failures report only a record identity and a stable code,
  never a fixture's `input` or any matched substring). Tested by
  [`schema.test.ts`](./schema.test.ts)
  (`npx vitest run assessment/schema.test.ts`), which also validates every
  file below against this schema.
- [`schema.json`](./schema.json) — the same shapes as a JSON Schema
  (draft 2020-12) document, for a validator in Rust, Python, or any other
  language without a TypeScript toolchain. It documents, but cannot itself
  enforce, the cross-field invariants `schema.ts` checks (accuracy/scale
  profile size and chunking rules, at-least-one-metrics-kind on a result); a
  conforming validator in any language must check both.
- [`generate.ts`](./generate.ts) — the deterministic, pure generator for a
  scale workload profile's input text. Nothing about a generated input is
  stored as data; a profile is its own complete, reproducible provenance
  (see [Deterministic workload generation](#deterministic-workload-generation)).
- [`fixtures/accuracy-corpus.json`](./fixtures/accuracy-corpus.json) — the
  reviewed synthetic accuracy corpus: hand-authored `logs`, `code`, `chat`,
  and `negative-text` fixtures, each with reviewed expected findings, UTF-8
  byte ranges, and the policy-aware outcome (`block`, `redact`, `warn`, or
  `allow`) the shipped default policy applies.
- [`fixtures/workload-profiles.json`](./fixtures/workload-profiles.json) —
  named workload profiles spanning both purposes
  (see [Accuracy is not scale](#accuracy-is-not-scale)), every category, a
  range of target input sizes and densities, every chunk profile, and both
  ASCII and non-ASCII filler mixes.
- [`fixtures/result-contract-examples.json`](./fixtures/result-contract-examples.json) —
  tiny known-answer example result records, one per surface plus one
  performance example, proving the result contract round-trips through the
  schema. These are illustrative shapes, not real measurements.

## UTF-8 byte offset model

`fixtures[].expected[].start`/`end` are **UTF-8 byte offsets** into `input`,
on the same terms as [`conformance/README.md`'s UTF-8 byte offset
model](../conformance/README.md#utf-8-byte-offset-model). A runner comparing
its own native offsets against this corpus normalizes both sides to UTF-8
byte ranges first, then verifies the converted span selects the same
original substring in its own native units. `fixtures/accuracy-corpus.json`'s
`logs-unicode-astral-boundary` fixture places an astral character immediately
before a finding — the case where UTF-16 and UTF-8 offsets diverge most, the
same boundary `conformance/fixtures/unicode-astral.source.ts` exercises.

## Safe expectations

An `AssessmentExpectation` carries only `detector`, `type`, `confidence`,
`specificity`, `start`, `end`, and `policyOutcome` — no field for the matched
value. Both validators (`schema.ts`'s closed key check and `schema.json`'s
`additionalProperties: false` on `#/$defs/expectation`) reject any expectation
object with an extra key. Every fixture `input` is unmistakably synthetic or
revoked; the corpus's only synthetic secret shape is
`token=ghp_ASSESSMENTSYNTHETIC0000000000000000`, distinct from any string used
in `conformance/`, on the same [fixture safety review](../conformance/README.md#fixture-safety-review)
terms.

## Accuracy is not scale

Every workload profile declares a `purpose`: `"accuracy"` or `"scale"`.
`validateAssessmentWorkloadProfiles` enforces the separation `schema.ts`
documents: an accuracy profile stays at or under `ACCURACY_MAX_INPUT_BYTES`
(4096 bytes) and is always fed as a single `"whole"` call, so measuring
accuracy never contends with, or is distorted by, chunking or timing
overhead. A scale profile is always larger, and exists to measure
initialization, processing time, throughput, repeated-run variance, and peak
memory — never to also serve as an accuracy sample. This keeps the two kinds
of measurement from contaminating each other, per
[the governing decision](../docs/decisions/2026-09-12-define-cross-language-evaluation-protocol.md).

## Deterministic workload generation

A scale workload profile's input text is never committed as data — only the
profile's parameters (`category`, `targetInputBytes`, `targetDensityPerKiB`,
`unicodeMix`, `generatorAlgorithm`) are. `generateWorkloadInput` is a pure
function of exactly those fields: constant filler lines per category (ASCII
or non-ASCII, selected by `unicodeMix`), with the one constant synthetic
secret line inserted every N lines to approximate the target density.
`schema.test.ts` proves this two ways:

- **Determinism**: regenerating any committed profile's input twice produces
  a byte-identical string, and its size meets the profile's declared target.
- **Known-answer cases**: a zero-density profile emits only the filler line
  used, and an overwhelming-density profile emits only the synthetic secret
  line — both spelled out verbatim in `schema.test.ts` so a reviewer can
  confirm the generator's exact output by eye without running it.

Every committed scale profile in `fixtures/workload-profiles.json` targets at
most 1 MiB, so regenerating and asserting on every profile completes in a
fraction of a second; there is currently no profile a reviewer needs to
inspect before running because none is close to taking five minutes to
generate or check. A future profile that would take that long must be
inspected before it is proposed, on the terms `AGENTS.md` sets for any
command expected to run that long.

`chunkProfile` (`"whole"`, `"fixed-1024"`, `"fixed-4096"`, `"fixed-65536"`, or
`"utf16-boundary"`) is not applied by the generator — a runner partitions the
generated text itself when it drives a streaming or incremental API, the
same way `conformance/README.md`'s
[Partition invariance](../conformance/README.md#partition-invariance) section
keeps partitioning out of stored fixture data.

## Common result contract

`AssessmentResult` is the one shape all five surfaces report through:
`schemaVersion`, `surface`, the `profileId` it ran, either `accuracy`
(`truePositives`, `falsePositives`, `falseNegatives`, `policyMismatches`) or
`performance` (raw initialization, processing, and throughput samples with
min/median/p95/max/mean/population-standard-deviation summaries, plus separate
memory categories with baseline/maximum-observed samples or an unavailable
reason) — or both — and a `provenance` block recording exactly
what produced the number: `commit` (full source SHA), `artifactIdentity`
(the exact built artifact, e.g. a package name and version), `corpusVersion`
and `corpusHash` (which revision of this corpus ran), `os`, `cpu`, `runtime`,
and the exact `command` invoked. Schema version 3 adds `pythonHeap` and the
non-Node `processRss` category; Node-specific, browser, Wasm, Python,
native-process, and streaming-buffer observations remain separate and must not
be summed. A result with no reproducible provenance is not evidence.

## Node and browser accuracy runners

- [`adapters/scoring.ts`](./adapters/scoring.ts) — pure accuracy scoring:
  `scoreFixture` compares one fixture's real findings against its reviewed
  `expected` array and returns `AssessmentAccuracyMetrics` plus safe,
  fixture-id-keyed `AccuracyMismatch` diagnostics (`missing`, `extra`, or
  `policy-mismatch`; a wrong-range finding surfaces as one of each rather
  than needing special handling). `aggregateAccuracyMetrics` sums per-fixture
  metrics across the corpus, and `runAccuracyFixtures` drives a `scan`
  function over every fixture — the one corpus-iteration path every
  surface's runner shares, so "what counts as a match" cannot drift between
  them. A `scan` rejection propagates out rather than being absorbed into a
  zero-finding result, so an evaluation that could not finish is never
  reported as one that finished and found nothing. Tested by
  [`adapters/scoring.test.ts`](./adapters/scoring.test.ts) with tiny fixtures
  exercising each kind of mismatch, every policy action, and UTF-8/UTF-16
  Unicode normalization.
- [`adapters/report.ts`](./adapters/report.ts) — renders one surface's
  `AssessmentResult` and its mismatches as Markdown, the common
  human-readable counterpart to the JSON result contract. Never receives a
  fixture's `input`, so it is safe to print or write to a file unmodified.
- [`../scripts/assessment-run.mjs`](../scripts/assessment-run.mjs) —
  command-line runnable: evaluates the real, installed `@redact-secret/core`
  package on Node against `fixtures/accuracy-corpus.json` and emits a
  conforming `"node"`-surface `AssessmentResult` (`node scripts/assessment-run.mjs`,
  or `npm run assessment:node`). It drives the package's public API the same
  way `scripts/qualify-node-addon.mjs`'s `integrateWithPackage` pass does,
  and does no building or linking of its own — a missing package build or
  native addon fails loudly (a distinct, non-zero exit) rather than reporting
  a false zero-finding success.
- [`../scripts/assessment-browser-run.mjs`](../scripts/assessment-browser-run.mjs) —
  the same evaluation against the real browser WebAssembly artifact in a
  real engine (`node scripts/assessment-browser-run.mjs [--engine chromium|firefox|webkit]`,
  or `npm run assessment:browser`), staged and served the same way
  `scripts/qualify-browser-artifact.mjs` qualifies the artifact.
  [`../scripts/assessment-browser-harness.mjs`](../scripts/assessment-browser-harness.mjs)
  is the in-page module it bundles with the published package aliased to the
  real artifact, on the same terms `scripts/browser-package-harness.mjs`
  does for conformance.
- Both runners accept `--json-out <path>` (default: stdout),
  `--markdown-out <path>`, and `--mismatches-out <path>` (the safe mismatch
  list, omitted by default), and `--strict` to exit non-zero when any
  mismatch is found — off by default, since a low score here is a finding to
  act on, per [Common result contract](#common-result-contract), not a
  build failure. Every fixture is synthetic or explicitly revoked, and
  neither runner's output carries a fixture's `input` or a matched value.

## Node and browser performance runners

`npm run assessment:node:performance -- --profile <scale-id> --runs <2-100>` and
`npm run assessment:browser:performance -- --profile <scale-id> --runs <2-100>`
measure real built artifacts. Add `--json-out <path>` and `--markdown-out <path>`
to retain inspectable raw data and summaries. The Node command accepts
`--addon-dir`; the browser command accepts `--engine` and `--artifact-dir`.

Each repetition uses a fresh process (Node) or browser context (WASM). Module
import, profile validation, deterministic input generation, chunk partitioning,
warmup, sink checks, aggregation, and report rendering occur outside the timers.
Initialization times only `initialize()`; processing times only a steady-state
whole-input operation or incremental session. Throughput is generated UTF-8
bytes divided by processing duration.

Memory is sampled immediately before and after processing. A reported maximum
is therefore a maximum observed at sample boundaries, never a guaranteed true
peak. Node heap, RSS, and external memory are separate, potentially overlapping
categories and must not be summed. Browser JavaScript heap is reported only when
the engine exposes non-standard `performance.memory.usedJSHeapSize`. The package
intentionally exposes neither its private `WebAssembly.Memory` handle nor
retained incremental plaintext bytes; those metrics carry unavailable reasons
instead of motivating public instrumentation APIs or invented estimates.

Before repetitions begin, each runner validates the complete profile document,
checks its declared count, selects one known `purpose: "scale"` profile, and
bounds repetitions to 100. The default 64 KiB profile with `--runs 2` is the
minimal known workload and bounded real-artifact smoke measurement.

## Installed Python package runner

`npm run assessment:python -- --python <installed-python>` evaluates the real
`redact-secret` distribution installed in that interpreter. The shared
TypeScript layer still validates and scores `accuracy-corpus.json` and emits
the common JSON, Markdown, and safe mismatch formats. The narrow
[`../scripts/assessment-python-worker.py`](../scripts/assessment-python-worker.py)
adapter only imports the installed distribution, calls its public API, and
normalizes Python Unicode-code-point ranges to canonical UTF-8 byte spans. For
every accuracy fixture it compares `scan_and_redact` with a code-point-chunked
`IncrementalSanitizer` run before returning safe metadata. A conversion error,
incremental disagreement, exception, or incomplete fixture count fails the
evaluation instead of becoming a zero-finding result.

`npm run assessment:python:performance -- --python <installed-python>
--profile <scale-id> --runs <2-100>` uses the common generated profiles and
chunk partitioner. A fresh Python process is used per repetition.
Initialization measures importing the installed package, including loading its
native extension. Processing measures only a warmed whole-input or incremental
operation. Process startup, JSON transport, profile validation, generation,
partitioning, warmup, memory sampling, aggregation, and rendering are outside
those timers.

Python memory is collected in a separate untimed pass. `pythonHeap` is
`tracemalloc` activity after tracing starts, so it excludes the interpreter's
pre-existing heap and native Rust allocations. `processRss` is the Unix
`ru_maxrss` high-water mark and includes the interpreter, extension, allocator,
and earlier process activity, so it cannot isolate Rust-only memory; it is
unavailable where that portable facility is absent. The retained incremental
buffer remains unavailable because the public package deliberately exposes no
plaintext-buffer instrumentation. None of these overlapping categories may be
summed or interpreted as a guaranteed operation-local peak.

Run `<installed-python> scripts/assessment-python-worker.py self-test` for the
real package's tiny Unicode, failure, and aborted-session known answers. The
repository's `assessment:check` command also runs fake-host cases for Unicode
normalization, whole/incremental disagreement, sanitized package failure, and
incomplete evaluation handling.

The first bounded installed-wheel baseline is recorded under
[`results/python/`](./results/python/): accuracy against `accuracy-corpus`, plus
`scale-logs-small-whole` with two runs. Its README records the exact build,
no-index installation, and evaluation commands.

## Rust library runner

`npm run assessment:rust -- --json-out <path> --markdown-out <path>
--mismatches-out <path>` evaluates the real Rust library crate through its
public API and emits the same `"rust-core"` `AssessmentResult` contract as
the JavaScript runners. The adapter is
[`../crates/secret-scan-core/examples/assessment_adapter.rs`](../crates/secret-scan-core/examples/assessment_adapter.rs)
so it can run from the checkout without entering the published library
package contents. It constructs `DetectorRegistry::with_built_in`, calls
`scan` for accuracy, and reports the crate's canonical UTF-8 byte ranges
directly; it does not duplicate detector logic.

`npm run assessment:rust:performance -- --profile <scale-id> --runs <2-100>`
measures the same generated scale profiles. Whole profiles call
`scan_and_redact`; chunked profiles call `IncrementalSanitizer` with explicit
byte limits. The adapter records initialization, steady-state processing,
throughput, `processRss` on macOS and Linux, unavailable RSS on other operating
systems, unavailable Node/browser/Wasm/Python memory categories, and the unavailable
retained-buffer metric with the same limitation text as the other public
surfaces. `npm run assessment:rust:self-test` runs tiny
known-answer checks for UTF-8 Unicode ranges, incremental incomplete-run
behavior, and sanitized failure handling.

The first bounded Rust baseline is recorded under
[`results/rust-core/`](./results/rust-core/): accuracy against
`accuracy-corpus`, plus `scale-logs-small-whole` with two runs. These files
are inspectable evidence for this surface, not a release gate.

## CLI runner

`npm run assessment:cli -- --binary <path>` evaluates the real, built
`redact-secret` CLI binary
([`crates/secret-scan-cli`](../crates/secret-scan-cli)) against
`fixtures/accuracy-corpus.json` and emits the same `"cli"`-surface
`AssessmentResult` contract every other runner does. The narrow
[`../scripts/lib/assessment-cli.mjs`](../scripts/lib/assessment-cli.mjs)
adapter only spawns the binary, feeds standard input, and reads the CLI's
documented `--json` report and exit codes
(`crates/secret-scan-cli/src/main.rs`); it never inspects detector or policy
logic. `--binary` defaults to `target/release/redact-secret` — build it first
with `cargo build --release -p redact-secret-cli`.

Beyond scoring every fixture, one run also validates the parts of the public
CLI contract the corpus alone cannot exercise: the documented exit codes (0
clean, 1 findings, 2 usage or decoding failure), a malformed standard-input
decode failure reported as `NOT_UTF8` and failing closed rather than becoming
a false zero-finding success, a multi-file `--` run checked byte-for-byte
against the same fixtures' standard-input results (file and standard-input
parity), and `--redact` mode against every fixture with a `redact`/`block`
finding, checked byte-for-byte against the placeholder text its own reported
findings imply. Any of these failing aborts the run before an
`AssessmentResult` is emitted.

`npm run assessment:cli:self-test` runs tiny known-answer checks — a UTF-8
byte range spanning an astral character, redaction, a decode failure, and a
usage failure — through `cargo run -p redact-secret-cli --`, so they need no
prebuilt release artifact. `assessment:check`'s vitest run exercises the same
self-test via
[`adapters/cli-adapter.test.ts`](./adapters/cli-adapter.test.ts), on the same
terms `adapters/rust-adapter.test.ts` exercises the Rust adapter's self-test.

`npm run assessment:cli:performance -- --profile <scale-id> --runs <2-100>`
measures the same generated scale profiles. A profile's `chunkProfile` governs
how an in-process streaming or incremental API is called, which does not
apply across a subprocess boundary — the CLI's public host contract is one
standard-input stream per process, so every profile's generated input is fed
as a single write regardless of `chunkProfile`; the CLI's own incremental
core still streams it internally. Each repetition spawns two fresh
processes: one running `--version` alone, timed as `initialization` (process
startup, argument parsing, and exit — nothing else), and one running `--json`
against the generated input, timed as `processing`. Unlike the in-process
Node, Python, and Rust runners, a CLI `processing` sample is necessarily
*process-inclusive*: it still contains the same process-startup cost
`initialization` measures on its own, because a subprocess boundary offers no
way to time only the library work inside it without the product exposing new
instrumentation. `processing` here must not be read as, or compared directly
against, another surface's steady-state processing number.

Process memory (`processRss`) is sampled in a separate, untimed repetition of
the same `--json` invocation wrapped by `/usr/bin/time -l` (macOS) or
`/usr/bin/time -v` (Linux) — the whole child process's maximum resident set
size, on the same "separate untimed pass" terms
[Installed Python package runner](#installed-python-package-runner) samples
`pythonHeap` and `processRss`, and unavailable where no such portable wrapper
exists (including Windows). It includes process startup, the Rust runtime,
and the entire scan, and cannot isolate steady-state or Rust-only memory.
Node, browser, Wasm, and Python heap categories, and the retained incremental
buffer, are unavailable on this surface for the same reasons documented for
the Rust library runner above.

## What this directory is not (yet)

This item defines the schema, the corpus, the workload profiles, and the
result contract — the common language every surface's evaluation reports
through. The Node, browser WebAssembly, Rust library, installed Python, and
CLI runners above execute profiles, collect real `accuracy` or `performance`
metrics, and emit a conforming `AssessmentResult`. This directory adds no
runtime instrumentation, telemetry, or public API to any product surface;
`secret-scan-core` stays side-effect free.

## Out of scope

Per the governing decision: a web UI for browsing results, comparisons
against competing products, new language bindings, and any release,
versioning, or publication action. Producing or reporting a result is not a
release gate and does not by itself authorize any release action; see
`AGENTS.md`'s release authority section.
