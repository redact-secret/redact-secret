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
revoked, one shape per finding type the corpus scores — for example
`token=ghp_ASSESSMENTSYNTHETIC0000000000000000` for `github_token` and
`sk-ant-api03-SYNTHETIC_REVOKED_ANTHROPIC_1` for `anthropic_api_key` — each
distinct from any string used in `conformance/`, on the same
[fixture safety review](../conformance/README.md#fixture-safety-review) terms.

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

## Complete reproducible evaluation

After building the real Node addon, browser Wasm artifact, installed Python
wheel, and CLI binary, one command evaluates every supported product surface
and writes the raw per-run JSON, per-run Markdown, safe mismatch files, a
machine-readable rollup, and a consolidated baseline report:

```bash
npm run assessment:all -- --python .venv/bin/python --output-dir assessment-output
```

The default bounded suite runs `accuracy-corpus`,
`scale-logs-small-whole`, and `scale-logs-medium-fixed4096` twice on each of
Rust, Python, Node, browser WebAssembly (Chromium by default), and CLI. The two
scale profiles deliberately cover a whole-input path and an incremental path.
The CLI receives both through standard input because that is its public
streaming boundary; its accuracy runner additionally verifies check mode over
standard input and files, JSON output, redact mode, exit codes, and malformed
input failure.

`assessment-output/summary.json` embeds every conforming `AssessmentResult`,
including raw timing and memory samples. `assessment-output/baseline.md` links
the individual reports and records every unavailable memory category and its
sampling limitation. Timing values may vary between executions. The aggregate
instead verifies that every result has the same source commit, every accuracy
run has the same corpus version and SHA-256, every performance run has the same
workload-profile version and SHA-256, and every performance distribution has
the requested repetition count.

The command continues after a runner failure so it can emit inspectable
incomplete evidence, then exits non-zero. A missing adapter, missing result,
invalid result, skipped surface, identity mismatch, or incomplete repetition
count therefore cannot produce a `"status": "complete"` rollup. The output
directory must not already exist, preventing a failed run from inheriting
stale evidence.

The manually triggered
[`Complete assessment`](../.github/workflows/complete-assessment.yml) workflow
builds and installs the real artifacts, runs this command, places the Markdown
baseline in the workflow summary, and uploads the complete output directory.
It publishes nothing and is not a release gate.

## Fixed RC performance and resource acceptance

[`acceptance-criteria.json`](./acceptance-criteria.json) fixes the RC
criteria before candidate measurement. Its performance and resource
thresholds were derived once, from the first complete baseline at commit
`a356e702e59b03cf297e0af15ba0423bc8466d48`, and have not changed since. Its
`baseline` pointer and pinned accuracy counts are re-pinned whenever the
accuracy corpus moves to a new reviewed revision, so a candidate built from
the current corpus is not rejected on a stale identity mismatch before any
timing threshold is even checked; the criteria currently point at the
five-repetition run at commit `944341903d5b85686a056d3218f4c33110d7d57b`
(accuracy corpus version `3`, hash
`438df062ddde47dcb32ae0aefc4297ed8b8c9e2c3270778c2b1f8809e40bd0dd`),
committed under [`results/complete-v4/`](./results/complete-v4/). The prior
pin, at commit `9359f59596f03443254f662db60d553b0610809e` (accuracy corpus
hash `cc4cb42028fd700bc98dd06dacebe421c5462dd59a46cf013154a4d185849979`), was
pruned by [#594](https://github.com/redact-secret/redact-secret/issues/594)
and remains as historical evidence at
[`results/complete-v3/`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-v3)
(the fixed 15-run macOS baseline that `complete-v4` re-pinned).
`results/complete-v4/` re-pins the accuracy identity only, after the beta.5
precision gate ([#376](https://github.com/redact-secret/redact-secret/issues/376))
corrected four accuracy-corpus fixtures to the seven provider contracts
frozen by [#367](https://github.com/redact-secret/redact-secret/issues/367);
see [`results/complete-v4/README.md`](./results/complete-v4/README.md) for
why its own performance/resource acceptance intentionally still reports
`rejected` in that directory's committed evidence, and why the performance
thresholds below are unchanged by that gate. They cover the two
representative log-processing profiles: 64 KiB whole-input and 256 KiB
fixed-4096 incremental input (standard input for the CLI). Five repetitions
are required so a two-sample exploratory baseline cannot be mistaken for
formal acceptance evidence.

The environment profile is deliberately narrow: macOS on arm64/aarch64, Node
22, Chromium, CPython 3, and the host Rust toolchain. This is the environment
the first measurements characterize. Evidence from another OS, architecture,
Node major, or browser engine remains useful assessment evidence, but it cannot
silently claim these host-qualified thresholds. Add and baseline a separately
reviewed environment profile before accepting one.

Timing ceilings are approximately twice the first observed p95, rounded upward
to stable operational values; throughput floors are approximately half the
first observed minimum, rounded downward. The margin accommodates ordinary
host jitter while still detecting a material regression. Memory caps likewise
round upward from observed maxima with category-specific headroom. Only a
category the surface can observe is capped: Rust and CLI process RSS, Python
allocator plus process RSS, Node heap/RSS/external memory, and Chromium's
coarsened JavaScript heap observation. These categories can overlap and must
not be summed. WebAssembly linear memory and retained streaming buffers remain
unobservable without widening the product contract, so their explicit
unavailability is preserved rather than converted to a zero or an invented
limit.

The accuracy counts are pinned to the first baseline only as a no-drift check
across all five artifacts. This performance/resource decision does not convert
the assessment corpus into a conformance gate or approve its known accuracy
mismatches.

After producing a fresh five-repetition complete assessment from one candidate
revision, evaluate it with:

```bash
npm run assessment:acceptance -- \
  --summary assessment-output/summary.json \
  --json-out assessment-output/acceptance.json \
  --markdown-out assessment-output/acceptance.md
```

The command validates completeness, repetitions, corpus identities, the host
profile, accuracy parity, timing, throughput, and observable memory. It writes
machine-readable and Markdown evidence before exiting non-zero on rejection.
The manually triggered workflow runs the same command and uploads both the raw
assessment and acceptance result. This readiness evidence does not select a
version or authorize tagging, publication, deployment, or release.

The first formal candidate evaluation used the already-fixed criteria from
commit `054076f` and five repetitions, with all 46 timing, throughput, and
observable-memory checks passing. It was committed under
`results/acceptance/`, linking its complete machine-readable summary and all
15 per-surface raw results and reports;
[#594](https://github.com/redact-secret/redact-secret/issues/594) pruned that
directory, which remains as historical evidence at
[`results/acceptance/`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/acceptance).

The first durable run of that command was committed as
`results/complete/baseline.md` and `results/complete/summary.json`; #594
pruned it too, and it remains as historical evidence at
[`results/complete/`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete).
The criteria file's baseline was later re-pinned to the five-repetition run
under `results/complete-v3/` (also pruned; see above), then to the current
`results/complete-v4/` pin described above. Use a new output directory when
reproducing so stale files cannot satisfy a run.

To choose another bounded profile, repeat `--profile`; include at least one
`whole` and one non-`whole` profile or the rollup is incomplete. Other useful
adapter-level reproduction commands are:

```bash
npm run assessment:node
npm run assessment:browser -- --engine chromium
npm run assessment:rust
npm run assessment:python -- --python .venv/bin/python
npm run assessment:cli -- --binary target/release/redact-secret
npm run assessment:node:performance -- --profile scale-logs-small-whole --runs 2
npm run assessment:browser:performance -- --profile scale-logs-medium-fixed4096 --runs 2
npm run assessment:rust:performance -- --profile scale-logs-medium-fixed4096 --runs 2
npm run assessment:python:performance -- --python .venv/bin/python --profile scale-logs-medium-fixed4096 --runs 2
npm run assessment:cli:performance -- --binary target/release/redact-secret --profile scale-logs-medium-fixed4096 --runs 2
```

### A second environment profile: Linux x86_64

`AcceptanceCriteria.environment` is a single, criteria-file-scoped block, so a
second host is added as a second, independently loaded criteria document
rather than by widening that type into a multi-profile lookup: this can never
silently overwrite or ambiguate the macOS profile's already-fixed values, and
`assessment-acceptance.mjs` already accepted `--criteria <path>` before this
profile existed.

[`acceptance-criteria-linux-x64.json`](./acceptance-criteria-linux-x64.json)
fixes RC criteria for Linux x86_64 — the other host the release actually
ships (npm and the CLI target Linux glibc, macOS, and Windows) — from a
complete, five-repetition run captured by the
[`Complete assessment`](../.github/workflows/complete-assessment.yml)
workflow's `ubuntu-latest` runner at commit
`9ff702001342ff84acdde8ad9acdec396572a15e`, committed under
`results/complete-linux-x64/`;
[#594](https://github.com/redact-secret/redact-secret/issues/594) pruned that
directory, which remains as historical evidence at
[`results/complete-linux-x64/`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-linux-x64).
Its performance and resource thresholds were derived once, from
that run, and have not changed since. The criteria file's `baseline` pointer
and pinned accuracy counts re-pin the same way as the macOS profile's above;
they currently point at the later five-repetition `ubuntu-latest` run at
commit
`944341903d5b85686a056d3218f4c33110d7d57b` (accuracy corpus version `3`,
hash `438df062ddde47dcb32ae0aefc4297ed8b8c9e2c3270778c2b1f8809e40bd0dd`),
committed under
[`results/complete-linux-x64-v4/`](./results/complete-linux-x64-v4/) and
evaluated as `accepted` in
[`results/complete-linux-x64-v4/acceptance.md`](./results/complete-linux-x64-v4/acceptance.md),
dispatched from the beta.5 precision gate
([#376](https://github.com/redact-secret/redact-secret/issues/376)) after it
corrected four accuracy-corpus fixtures to the seven provider contracts
frozen by [#367](https://github.com/redact-secret/redact-secret/issues/367);
see [`results/complete-linux-x64-v4/README.md`](./results/complete-linux-x64-v4/README.md).
The prior pin, at commit `9359f59596f03443254f662db60d553b0610809e` (accuracy
corpus hash `cc4cb42028fd700bc98dd06dacebe421c5462dd59a46cf013154a4d185849979`),
was pruned by #594 and remains as historical evidence at
[`results/complete-linux-x64-v3/`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-linux-x64-v3)
(the fixed 15-run Linux x86_64 baseline that `complete-linux-x64-v4` re-pinned).
Both v3 and v4 pin the same workload-profiles
identity as the macOS profile, since that corpus is unchanged, and unlike the
macOS profile's `complete-v4`, this Linux x86_64 evidence is fully `accepted`
— performance thresholds pass cleanly on the qualified `ubuntu-latest` host.

The environment profile is `linux-x64-node22-chromium`: Linux on x86_64, Node
22, Chromium, CPython 3, and the host Rust toolchain — otherwise the same
scope as the macOS profile, just the other shipped host. Timing ceilings are
twice the observed p95, rounded up to the nearest whole millisecond below 10
and to the nearest 5/50/100 above that; throughput floors are half the
observed minimum, rounded down to the nearest 10,000 (or 100,000 above 1
million) bytes per second; memory caps are 2.5x the observed maximum, rounded
up to the nearest mebibyte — the same "generous, stable, rounded" intent as
the macOS profile's hand-fixed values, applied as an explicit rule since this
is a fresh profile rather than a reproduction of the first one. As with the
macOS profile, Rust, Python, and CLI share one memory cap across both
performance profiles per category; Node and browser WebAssembly fix a cap per
profile (Node's external-memory category is shared, since the two profiles'
observations were nearly identical).

The [`Complete assessment`](../.github/workflows/complete-assessment.yml)
workflow runs on `ubuntu-latest`, so its "Evaluate the fixed RC acceptance
criteria" step passes `--criteria assessment/acceptance-criteria-linux-x64.json`
and is evaluated against this profile, not the macOS one.

Evaluate a Linux x86_64 candidate the same way as the macOS profile, pointing
`--criteria` at the Linux document:

```bash
npm run assessment:acceptance -- \
  --criteria assessment/acceptance-criteria-linux-x64.json \
  --summary assessment-output-linux-x64/summary.json \
  --json-out assessment-output-linux-x64/acceptance.json \
  --markdown-out assessment-output-linux-x64/acceptance.md
```

The [acceptance evaluation](https://github.com/redact-secret/redact-secret/blob/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-linux-x64/acceptance.md)
of that same baseline run against its own freshly fixed criteria reported
`accepted` with all 46 checks passing and no `environment-*-mismatch`
failure, by construction: the thresholds were fixed from this run's own
observations. (`results/complete-linux-x64/` was pruned by #594; see above.)

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

The first bounded installed-wheel baseline — accuracy against
`accuracy-corpus`, plus `scale-logs-small-whole` with two runs, with its
README recording the exact build, no-index installation, and evaluation
commands — was recorded under `results/python/`;
[#594](https://github.com/redact-secret/redact-secret/issues/594) pruned it,
and it remains as historical evidence at
[`results/python/`](https://github.com/redact-secret/redact-secret/tree/3ca61a9085d074c102fa9b3e9f937c3d4cf76a9c/assessment/results/python).

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

The first bounded Rust baseline — accuracy against `accuracy-corpus`, plus
`scale-logs-small-whole` with two runs, inspectable evidence for this surface
rather than a release gate — was recorded under `results/rust-core/`;
[#594](https://github.com/redact-secret/redact-secret/issues/594) pruned it,
and it remains as historical evidence at
[`results/rust-core/`](https://github.com/redact-secret/redact-secret/tree/3ca61a9085d074c102fa9b3e9f937c3d4cf76a9c/assessment/results/rust-core).

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

`npm run assessment:cli:self-test` builds the debug CLI once and runs tiny
known-answer checks directly against that binary — a UTF-8 byte range spanning
an astral character, redaction, a decode failure, and a usage failure — so they
need no prebuilt release artifact. `assessment:check`'s vitest run exercises
the same self-test via
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

## Beta.2 detection assessment

[`results/beta.2/`](./results/beta.2/) records the fixed-corpus assessment for
issue #191 against locally built, digest-identified Node and browser WebAssembly
candidate artifacts. Its JSON rollup and Markdown report state dataset scope
and denominators, distinguish a range mismatch from ordinary-negative false
positives, preserve the reviewed labels, and link every mismatch to its
detector-contract disposition. The result is readiness evidence, not a
conformance gate or release authorization.

## What this directory is not (yet)

This directory defines the schema, the corpus, the workload profiles, and the
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

Discovery fixtures, generated variants, differential and holdout evaluation,
known-gap lifecycle, raw evidence, and fixed-candidate revalidation belong to
[`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
under
[`decision-govern-benchmark-regression-promotion`](../docs/decisions/2026-09-18-govern-benchmark-regression-promotion.md).
Do not copy them here: `assessment/` remains the bounded cross-language protocol
above and must not become a second discovery benchmark.

## Performance build correction

The historical Rust timings in
[`complete`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete)
and
[`complete-v3`](https://github.com/redact-secret/redact-secret/tree/6cd5f2c58e527396563d86d8caba98104a93a17c/assessment/results/complete-v3)
(pruned by [#594](https://github.com/redact-secret/redact-secret/issues/594))
were collected without `--release`; their raw evidence is retained at those
permalinks but does not support optimized cross-runtime comparisons. The
corrected [release-profile run](results/release-profile/baseline.md) uses
release builds.
The Rust runner now rejects debug performance execution, records its actual
executable argv and build profile, and aggregation requires release provenance.
Build time is outside the measured processing interval. CLI check-mode timings
remain distinct from the other surfaces' scan-and-redact timings.

Previously stored acceptance statuses are historical. Both complete aggregation
and acceptance evaluation now reject Rust performance without explicit release
provenance. Existing fixed thresholds are retained as historical budgets, not
recalibrated from debug timings or claimed as release-performance targets.
