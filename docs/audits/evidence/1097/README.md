# Evidence: #1097, a reusable compiled sanitizer configuration

**Result:** do not build a new type now. The per-call work a compiled
configuration could amortize is one built-in `DetectorRegistry` construction,
about 18 microseconds and 119 allocations (23.4 KB) on this machine. That
cost is real for strings under about 1 KiB and negligible from 64 KiB up. It
is already avoidable today by holding a registry and calling
`scan_and_redact`, which is what the CLI and every binding do. A wrapper
type (option B) would add a public type to the 0.1.x freeze for no speed the
existing API lacks. The one option that adds speed for callers who use the
one-shot `sanitize` function as documented is an internal per-thread cache
(option C). It costs no public surface, but it reverses a sentence in the
#1078 design notes, so it waits for caller evidence. Criteria are in
[Recommendation](#recommendation).

Issue [#1097](https://github.com/redact-secret/redact-secret/issues/1097).
Kind per
[DS0](../../../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md):
product judgement, a design record. Documentation only: no product code,
dependency, threshold or detector changed. Measured on `origin/main` at
`cfa87360d439` (2026-09-30), which does **not** contain #1093 (the
`LiteralMatcher` dedup work is not merged; see
[Reuse boundary today](#1-reuse-boundary-today)). Every input is synthetic.

## 1. Reuse boundary today

Line numbers are at `cfa87360`.

| Layer | What is reused | What is rebuilt | Where |
| --- | --- | --- | --- |
| `DetectorRegistry` | The value itself: ordered, duplicate-free, validated once at registration. `scan`/`scan_and_redact` take `&DetectorRegistry`, so one registry serves any number of calls. | Nothing, if the caller keeps it. | `registry.rs:113` (struct), `pipeline.rs:750` (`scan_and_redact`) |
| Built-in entries | A built-in is a reference into a static table (`Held::BuiltIn`), so a built-in registry allocates no per-detector object (#1043). | The `Vec<RegisteredDetector>` and each id `String`. | `registry.rs:97-101` |
| Exact `LiteralMatcher` prefilter (#1057) | Compiled once per profile in a `static OnceLock` (`FULL_PREFILTER`, `COMMON_PREFILTER`) and shared by every registry of that profile. | Nothing. A PII or custom registry still reuses the credential matcher. | `registry.rs:187`, `registry.rs:228`, `registry.rs:342` |
| #1093 matcher dedup | Not on `origin/main`; it would change the steady-state scan cost of short inputs (raising the relative share of registry construction), not the construction cost. | n/a | issue #1093 |
| Python binding (#1059) | A `thread_local!` `RegistryCache` holds the built-in registry and the last ruleset's registry, tagged by PII epoch. | On PII re-initialization or a different ruleset. Errors are never cached. | `bindings/python/src/lib.rs:883-925` |
| Node binding | `thread_local!` `OnceCell` per profile, independent, plus the PII selection. | Nothing after first use. | `bindings/node/src/lib.rs:150-191` |
| WASM binding | `thread_local!` `OnceCell` registry built by idempotent `initialize`; one ruleset registry cached by `Rc`. | Nothing after `initialize`. | `bindings/wasm/src/lifecycle.rs:148`, `:253-256` |
| CLI | One registry per run, built lazily and reused for every file. | Nothing. | `crates/secret-scan-cli/src/modes.rs:36`, `:80` |
| `sanitize` / `sanitize_with_profile` (#1078) | Policy and formatter are unit values. | **The whole registry, on every call.** Documented as stateless: "nothing is cached and no hidden global exists". | `pipeline.rs:834`, `:862-874`, design note at `:818-824` |
| `IncrementalSanitizer` | Policy and formatter are owned boxes. | The registry, **per session**: the struct owns `registry: DetectorRegistry` by value and the constructors build one. | `incremental.rs:538-539`, `:633` |

Why the host caches are `thread_local!`: `trait Detector` has no `Send` or
`Sync` bound (`types.rs:438`), so `DetectorRegistry` is neither `Send` nor
`Sync`. No process-wide `static` registry is possible without a contract
change to that trait. Only the matcher, which holds no trait object, is a
process-wide static.

So the gap is narrow: **Rust callers of the one-shot `sanitize*` functions
and of `IncrementalSanitizer::new*`**. The hosts and the CLI already
amortize.

## 2. What Flare's `Policy::compile` does, and what to copy

Read at the linked revision
[`c652ea7`, `sdk/rust/src/engine.rs` lines 50-125](https://github.com/flare-collection/flare-redact/blob/c652ea7946028b70527069d7c282752b8a0ccee3/sdk/rust/src/engine.rs#L50-L125).
`Policy::compile(options)` does, once:

1. takes the detector pack (`Arc<Pack>`, shared) and resolves which detectors
   run, from `only` / `enable` / `disable` selectors and each detector's
   `default_on`, into a `selected: Vec<usize>` of indices;
2. builds a custom-terms detector;
3. rejects an unusable mode (`Hash`, `Pseudonym`, `Surrogate` without a
   secret) at compile time, "rather than on the first value";
4. precomputes `has_prefilter`, the allow set (`HashSet<String>` of raw
   values), lower-cased key names, and the length and finding limits.

The returned `Policy` is documented as shared across the logger, HTTP layer
and prompt path so "sensitive" means the same thing in all three.

| Part | Copy? | Why |
| --- | --- | --- |
| Resolve selection once, validate at construction, fail there | **Yes.** It is the reuse boundary. | Here it is `DetectorRegistry`: the profile, PII slot, custom detectors and ruleset are resolved and checked (`InvalidDetector`) at construction. |
| Shared immutable pack separate from per-policy selection | **Yes, as an idea.** | Here the matcher `static` is the shared part and the registry is the selection. |
| One value shared by every call site | **Yes.** | Options A and C. |
| Detector selection inside a thing called "policy" | **No.** | `Policy` here only chooses an action per finding (`types.rs:745`). A `Policy::compile` would suggest policy decides which detectors run. Detection stays in the registry. |
| Raw-value allow set | **No.** | Forbidden by the issue: no new raw-secret allow set. |
| `transform_secret`, hash / pseudonym / surrogate modes | **No.** | Forbidden: no hashing or pseudonym vault. |
| Terms detector, key-name redaction | **No.** | Policy semantics and scope outside this issue. |

Conclusion: Flare's compile step is what `DetectorRegistry::with_*` already
is. What Flare has and this crate lacks is a one-call way to hold that value
for the default configuration. That is a convenience question, answered in
section 4.

## 3. Measured cost of the work a compiled configuration could amortize

### Method

- Build: `cargo build --release` (workspace `lto = "fat"`, `codegen-units =
  1`), rustc 1.98.1, Apple M4, base `cfa87360d439`. No product code was
  edited. The probe is an uncommitted example linking the public API only
  (`sanitize`, `sanitize_with_profile`, `scan_and_redact`,
  `DetectorRegistry::with_*`). Its counting allocator needs `unsafe`, which the
  workspace forbids, so it was built with `RUSTFLAGS=--cap-lints warn` into a
  scratch target directory; nothing built that way is shipped.
- Seven inputs, all synthetic: a log-line repeat (`... INFO request id=42 ...`)
  at 11 B, 64 B, 1 KiB and 64 KiB, each clean, plus 64 B, 1 KiB and 64 KiB
  containing 1, 1 and 8 copies of the documented synthetic token shape
  `API_KEY=ghp_SYNTHETICREVOKED...`.
- Variants run **interleaved** (one batch of each per round, 31 rounds) after
  the matcher is warm: `fresh-full` (`sanitize`), `reused-full` (one registry,
  `scan_and_redact`), `fresh-common` / `reused-common`
  (`Profile::Common`), `fresh-pii` / `reused-pii`
  (`with_built_in_and_pii(["pii"])`), and `build-full` (construction alone).
  Batch sizes scale so a sample is about 200 microseconds of work or more.
- Instructions and cycles come from `/usr/bin/time -l` over 100,000 calls of a
  single variant, minus a 0-call run for process start.
- **Caveat:** the machine was loaded (load average 16 to 18 on the run).
  Median and minimum are both given; the ratios are stable, the absolute
  microseconds are not a benchmark claim. Final benchmark evidence belongs in
  `redact-secret-benchmarks`, not here.

### Construction, first call, steady state

| Measurement | Value |
| --- | --- |
| First `with_built_in([])` in the process (compiles the `LiteralMatcher`) | 168 us |
| Second construction (matcher cached) | 59 us (cold caches) |
| Steady-state `with_built_in([])` | 16 to 19 us median (`build-full`, all inputs: 12.6 to 18.6), 119 allocations, 23,447 bytes |
| Steady-state `with_common_built_in([])` | about 0.7 us (`fresh-common` minus `reused-common`), 11 allocations |
| Steady-state `with_built_in_and_pii(["pii"])` | about 20 us (`fresh-pii` minus `reused-pii`), about 144 allocations |
| Live heap with the matcher and one registry | 226,679 bytes total process heap at that point; a registry is 23.4 KB of it |

The `registry-build` bench (`benches/scan_cost.rs:618`, #1059) measures these
constructors alone, and agrees with the order of magnitude recorded in the
`sanitize` docs (about 18 us).

### Per call, median us (min in parentheses), `fresh` includes construction

| Input | fresh-full | reused-full | ratio | fresh-common | reused-common | ratio | fresh-pii | reused-pii | ratio |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 11 B clean | 19.94 (17.91) | 1.40 (1.37) | 14.2x | 1.13 | 0.47 | 2.4x | 21.94 | 1.52 | 14.4x |
| 64 B clean | 21.24 (18.14) | 2.53 (2.23) | 8.4x | 1.74 | 1.08 | 1.6x | 23.35 | 3.11 | 7.5x |
| 64 B + 1 secret | 22.37 | 5.92 | 3.8x | 4.04 | 3.43 | 1.2x | 24.01 | 6.30 | 3.8x |
| 1 KiB clean | 37.76 (33.30) | 21.25 (18.81) | 1.78x | 12.28 | 11.74 | 1.05x | 46.75 | 28.66 | 1.63x |
| 1 KiB + 1 secret | 39.74 | 24.94 | 1.59x | 13.38 | 13.23 | 1.01x | 46.60 | 31.41 | 1.48x |
| 64 KiB clean | 1052.92 | 1037.47 | 1.015x | 597.18 | 596.39 | 1.001x | 1442.07 | 1424.62 | 1.012x |
| 64 KiB + 8 secrets | 1073.58 | 1056.00 | 1.017x | 568.75 | 566.61 | 1.004x | 1411.17 | 1391.97 | 1.014x |

Allocations per call (full): 123 fresh versus 4 reused on a 64 B clean input
(3,016 B reused versus 26,463 B fresh); on 64 KiB with 8 secrets, 360 versus
241. Reused allocations are the output `String`, findings and scratch, not the
registry.

### Instructions, 64 B clean input, 100,000 calls

| Variant | Instructions per call | Cycles per call |
| --- | --- | --- |
| fresh-full | 221,000 | 44,900 |
| reused-full | 32,400 | 5,700 |
| fresh-common | 23,300 | 3,800 |
| reused-common | 15,200 | 2,300 |

The avoidable work on the full profile is about 189,000 instructions per call.
On `common` it is about 8,000.

### Does it matter for realistic call patterns?

- **Many short strings** (log lines, chat messages, header values, typically 40
  to 200 bytes) on the `full` profile: yes. Construction is 3x to 14x the scan
  and caps a one-shot `sanitize` loop near 50,000 calls per second per core
  (1 / 18 us) while the same loop over a reused registry on a 64 B input runs
  near 400,000.
- **Per-request bodies** (1 KiB to 64 KiB): no. 1.6x at 1 KiB, 1.5% at 64 KiB.
  The crossover where construction equals the scan is about 1 KiB of clean
  text.
- **`common` profile**: nearly no. Its construction is sub-microsecond.
- **Hosts and the CLI**: already amortized by their caches, so this measures
  nothing for them. WASM init time and raw/gzip size were **not** measured
  here; options A and C change neither (no new code path in the WASM crate),
  and B adds a native-only type that the bindings would not export. #1043,
  #1084 and #1068 own the size budgets.
- `IncrementalSanitizer` pays the same construction once per **session**, not
  per chunk. That matters only for a workload of many short-lived sessions.

## 4. API candidates

Shared design decisions, each option answered against the issue's list:

| Decision | Answer common to all options |
| --- | --- |
| Immutable configuration versus scratch | Configuration is an immutable registry (plus unit policy and formatter). There is no scratch object: a scan allocates and frees its own buffers. Nothing retains caller plaintext or completed results; no scratch pool. |
| Rulesets and custom detectors | Validated once, at registry construction, in stable registration order and identity (`InvalidDetector`). A scan never re-parses. A caller change means building a new registry: there is no mutation path that keeps a "compiled" claim (`register` already clears `profile()`). No global cache keyed by ruleset. |
| Detector, policy and formatter errors | Stay at scan time, as today. Only registry-construction errors move to construction. |
| PII-off linkage | PII stays a registry constructor choice (`with_built_in_and_pii` versus `with_built_in`), so a PII-off build links no PII machinery through a runtime branch. No option adds a flag that would. |
| Forbidden additions | None of the options adds a raw-secret allow set, a hash or pseudonym vault, I/O, shadow controls or telemetry. |

### Option A: document reuse, add no API

Keep `sanitize*` as the one-shot function. Document the reuse recipe and the
measured break-even next to it, and in the crate README.

```rust
// before: rebuilds the registry on every call
for line in lines { let r = redact_secret::sanitize(line)?; }

// after: one registry, same output
let registry = DetectorRegistry::with_built_in([])?;
for line in lines {
    let r = scan_and_redact(line, &registry, &DefaultPolicy, &default_placeholder_formatter)?;
}
```

- **Public surface cost:** none. Nothing is added to `core-public-api`
  (`Cargo.toml:96`), which already pins `sanitize`, `sanitize_with_profile`,
  `scan_and_redact`, `DetectorRegistry`.
- **Detection versus policy:** unchanged; the recipe passes them as separate
  arguments.
- **Incremental:** not affected. The docs must say that session construction
  also builds a registry, and that `IncrementalSanitizer` supports no custom
  detectors, so reuse advice for whole-input scanning must not be read as
  applying to custom detectors there.
- **Determinism / threads / memory:** identical to today. The caller owns the
  registry; it is `!Send`, so one per thread.

### Option B: a `Sanitizer` value that owns the configuration

Sketch, names not final:

```rust
pub struct Sanitizer {
    registry: DetectorRegistry,          // detection
    policy: Box<dyn Policy>,             // policy, separate field
    formatter: Box<dyn PlaceholderFormatter>,
    limits: WholeInputLimits,
}
impl Sanitizer {
    pub fn new(profile: Profile) -> Result<Self, SecretScanError>;
    pub fn from_registry(registry: DetectorRegistry) -> Self; // PII, custom, ruleset built by the caller
    pub fn with_policy(self, p: Box<dyn Policy>) -> Self;
    pub fn with_formatter(self, f: Box<dyn PlaceholderFormatter>) -> Self;
    pub fn with_limits(self, l: WholeInputLimits) -> Self;
    pub fn sanitize(&self, input: &str) -> Result<ScanResult, SecretScanError>;
}
```

Ownership: `Sanitizer` owns one registry and two boxed callbacks; `sanitize(&self)`
borrows all three for the duration of one `scan_and_redact_with_limits` call.
It holds no input.

- **Public surface cost:** one new type and about six methods, in the 0.1.x
  freeze: `core-public-api`, `tests/public_api.rs`,
  `scripts/check-rust-workspace.py`, docs and conformance naming.
  The noun collides with `IncrementalSanitizer` and with the `sanitize`
  function (#1078 chose "function, not a `Sanitizer` value" because "there is
  no state worth holding"). This measurement shows the state worth holding is
  one registry, which `DetectorRegistry` already is.
- **Detection versus policy:** kept as separate fields with separate setters.
  The risk is naming: a `with_policy` next to `from_registry` invites people to
  read the type as "a policy", which is the Flare conflation the issue warns
  against.
- **Speed:** exactly the `reused-*` rows. It adds none that option A lacks. It
  adds one thing A cannot give: one place to hold a validated configuration
  and report construction errors.
- **Incremental:** must **not** offer `Sanitizer::incremental()`. A session owns
  its registry by value (`incremental.rs:538`) and supports only built-ins;
  exposing it from a value that accepts `from_registry` would imply custom
  detectors work there. Without it, per-session construction stays.
- **Threads:** `!Send` and `!Sync` through `Box<dyn Detector>` and `Box<dyn
  Policy>`. A `Send + Sync` variant would need either bounds on the
  extension traits (a contract change that breaks every existing implementor
  and must be recorded for #1066) or a separate built-in-only type.
- **Determinism:** unchanged (same function, same registry order).
- **Memory:** 23.4 KB plus callbacks per held value, freed on drop.

### Option C: internal per-thread cache behind the one-shot functions

`sanitize` and `sanitize_with_profile` use a `thread_local!` built-in registry
per profile, built on first use.

```rust
thread_local! { static FULL: OnceCell<DetectorRegistry> = const { OnceCell::new() }; /* + COMMON */ }
// sanitize_with_profile: FULL.with(|r| scan_and_redact(input, r.get_or_try_init(..)?, ..))
```

- **Public surface cost:** none. Signatures, errors and docs surface are
  unchanged.
- **Detection versus policy:** unchanged. The cache holds only the built-in
  detectors that `sanitize*` already hard-wires; the policy and formatter stay
  the crate's own unit values. There is nothing to configure, so nothing to
  conflate.
- **Reentrancy:** none. The default policy and formatter are crate-owned and
  cannot call back into user code, and the registry is only shared-borrowed
  (`OnceCell`, no `RefCell`), so a nested `sanitize` from the same thread is
  safe.
- **Threads:** thread-local because the registry is `!Sync`, the same choice as
  Python, Node and WASM. No process-wide cache and no `Sync` requirement on
  custom detectors (there are none in this path).
- **Memory:** about 23.4 KB per thread per profile actually used, held until
  thread exit. A thread that calls `sanitize` once keeps it.
- **Determinism:** unchanged: the built-in registry is a pure function of the
  binary and is never mutated.
- **Cost of the change:** it reverses the #1078 doc sentence "nothing is cached
  and no hidden global exists" and puts a one-time initialization into a
  function that was stateless by design; the incremental and custom-detector
  paths gain nothing. Output must be byte-identical to today, verified by the
  existing `sanitize` doctests plus a test that compares `sanitize*` against
  `scan_and_redact` over a fresh registry on the canonical corpus.

### Comparison

| | A: document | B: `Sanitizer` | C: hidden cache |
| --- | --- | --- | --- |
| Speed for a one-shot `sanitize` loop on short strings | none (caller must change code) | none for existing callers; `reused` for callers who migrate | `reused` for all existing callers, no change needed |
| Public surface added to the 0.1.x freeze | 0 | 1 type, about 6 methods | 0 |
| Covers PII, rulesets, custom detectors, incremental | as today, by the caller | PII/custom/ruleset via `from_registry`; not incremental | no |
| Keeps detection and policy separate | yes | yes, but name invites confusion | yes (nothing configurable) |
| Hidden state | none | none | one per-thread registry per profile |
| `Send` / `Sync` | caller's | `!Send`, `!Sync` | n/a, thread-local |
| Reverses a recorded decision | no | partly (#1078 "function, not a value") | yes (#1078 "nothing is cached") |
| Reversible after 0.1.0 | n/a | no, a public type is permanent | yes, internal |

## Recommendation

**Choose A now.** Record that no API is added. The follow-up is a docs-only
change to the `sanitize` and `sanitize_with_profile` rustdoc and the core
README: state that `sanitize*` constructs a registry per call, give the
figures above (about 18 us; dominant below roughly 1 KiB, under 2x at 1 KiB,
1.5% at 64 KiB), show the `scan_and_redact` recipe, and say that
`IncrementalSanitizer::new*` also builds one registry per session.

Why not B: its speed is the speed the existing API already gives, and its
only added value, holding a validated configuration, is what a registry
already is. It would freeze a type name that collides with
`IncrementalSanitizer`, at the moment #1066 is deciding what 0.1.x promises.

Why not C yet: it is the only option that speeds up existing one-shot callers
without a migration and it costs no surface, so it is the right thing to build
**if** the pattern is shown to exist. It is not shown: no in-repo caller of
`sanitize*` exists (the CLI and all three bindings reuse a registry), and no
reported caller does. Building it would contradict the #1078 design note to fix
a pattern nobody has reported.

Deferring costs nothing in compatibility: adding a function, a type or an
internal cache later is an additive change, while shipping the wrong wrapper
now is permanent.

### Criteria to build

Build **C** (smallest, internal) when all hold:

1. There is evidence of repeated short-input use of the one-shot function:
   an issue or report from a caller, a first-party caller (example, service,
   or benchmark workload) that calls `sanitize*` per line or per message, or a
   `redact-secret-benchmarks` workload on inputs under 1 KiB where fresh
   `sanitize` is at least 3x the reused registry.
2. The change keeps output byte-identical on the canonical conformance corpus
   and on Unicode, invisible-character and adversarial near-miss inputs, with
   the registry-build bench unchanged.
3. The #1078 rustdoc sentence is rewritten in the same change and the
   per-thread memory is stated.

Build **B** only when, in addition, at least one of these is demonstrated:

- callers need to hold a non-default validated configuration (a ruleset, PII
  selection, policy or limits) in one value and are getting the
  `scan_and_redact` recipe wrong or missing it, shown by more than one report;
- a `Send + Sync` shareable handle is required by a multi-threaded server use
  case. That needs a contract decision on the extension traits (or a separate
  built-in-only type), recorded for #1066 **before** the freeze ships;
- a session pool or many short-lived `IncrementalSanitizer` sessions need a
  shared registry. That needs an ownership change to `IncrementalSanitizer`
  (borrowed or `Arc` registry) and, because sessions support only built-ins,
  its own decision.

Whatever is built also needs: construction, first-call and steady-state
reported separately (the third table above), native and WASM full/common
raw and gzip size and init (not measured here), PII on and off, a ruleset row,
partition and lifecycle qualification if incremental is touched, and no new
dependency, `unsafe`, public diagnostics, plaintext caching or detection
change.

## Reproduction

Base `cfa87360d439` with a clean tree. The probe is not committed. It is a
`crates/secret-scan-core/examples/*.rs` file importing `sanitize`,
`sanitize_with_profile`, `scan_and_redact`, `DetectorRegistry`, `PiiSelection`,
`DefaultPolicy` and `default_placeholder_formatter`, with a
`#[global_allocator]` counter. Run it as
`RUSTFLAGS=--cap-lints warn cargo build --release -p redact-secret --example <name>`,
then `<binary>` for the tables and `/usr/bin/time -l <binary> loop <variant>
<input> <n>` for instructions. For the maintained harness use
`cargo bench -p redact-secret --bench scan_cost -- registry-build`.
