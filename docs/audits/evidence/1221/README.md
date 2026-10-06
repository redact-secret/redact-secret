# Evidence: #1221, per-instance PII isolation and the #1222 recommendation

Research record for
[#1221](https://github.com/redact-secret/redact-secret/issues/1221) (epic
[#1216](https://github.com/redact-secret/redact-secret/issues/1216)). It
executes the same-process isolation experiments the issue specifies, on every
surface that could be built locally, and gives a decision recommendation for
[#1222](https://github.com/redact-secret/redact-secret/issues/1222). The
capability matrix is the living reference
[`docs/reference/detector-capability-matrix.md`](../../../reference/detector-capability-matrix.md);
this record is frozen.

All inputs are synthetic and the credential-shaped value is assembled at run
time. Nothing here claims installed-runtime parity or performance.

## Identity of what was run

| Item | Value |
| --- | --- |
| Source | `db0e5c8ddf706988967e971593f509daf460c222` (`main`, clean tree), `0.1.0-beta.13` |
| Host | macOS 26 (Darwin 25.5.0), arm64 |
| Toolchain | `rustc`/`cargo` from `rust-toolchain.toml`; Node v22.16.0; Python 3.14.7; maturin 1.15.0; wasm-bindgen 0.2.128 |
| Not built | `@redact-secret/core` JS facade (no `node_modules`; `npm ci` not run). Facade behavior is source-inspected, not executed. `wasm-pack` and `wasm-opt` are not installed and not used |

## Experiment design

Three configuration owners in one process:

- **A**: PII off.
- **B**: `pii:global` (email, IBAN, network address, payment card, phone).
- **C**: `pii:family:global:network-address`, a different, narrower family set.

Fixtures: `email: owner.synthetic@mail-synthetic.org` (a B finding, not C or
A), `client_ip = 192.168.1.7` (a B and C finding, not A) and a synthetic
GitHub-token-shaped line (a finding for all three). Expected per owner, as
`(email, network-address)` counts: A `(0,0)`, B `(1,1)`, C `(0,1)`. The matrix
of experiments, each run per owner:

1. all three alive together, then queried (construction order);
2. all six construction orders;
3. interleaved incremental sessions, one per owner, with the email split across
   a chunk boundary;
4. a custom ruleset, two different rulesets alternated per owner, and a PII
   selection that must survive a ruleset scan;
5. the legacy contract: an equivalent selection is idempotent, a differing one
   conflicts, and the conflict disturbs no other owner;
6. teardown: drop or terminate one owner, then check the others and a
   re-created owner.

## Results

| Surface | How an owner is made | A, B, C coexist | Orders | Streams | Rulesets | Teardown | Legacy contract | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Rust `BuiltInRegistry` and `IncrementalSanitizer` | one value per owner | yes, both profiles | 6/6 identical, both profiles | yes (`IncrementalSanitizer`) | yes, via `DetectorRegistry` (a `BuiltInRegistry` takes none) | yes; a rebuilt owner matches the first | untouched (no global state in the core) | **pass**, 7 tests |
| Node addon (raw) | one `worker_threads` Worker per owner | yes, plus an unconfigured main thread unaffected | 6/6 identical | yes, interleaved across Workers | yes; two rulesets alternate with no cross-talk | yes; a terminated owner leaves the others, a new Worker starts clean | equivalent `ok`; differing, off-after-on and on-after-off all `PII_ACTIVATION_CONFLICT` | **pass**, per thread only |
| WASM artifact (generated glue) | one module instance per owner (`?instance=` URL) | yes | 3 orders identical | yes, interleaved | yes; PII survives a ruleset scan | yes; a re-created instance has no inherited selection | equivalent `ok`; differing and off-after-on conflict; the default artifact rejects PII with `PII_SELECTOR_UNAVAILABLE` | **pass**, per module instance only |
| Python wheel | none in one process | **no**: only the first selection holds | n/a | n/a | n/a | no teardown API | after B, A and C raise `PiiActivationConflictError` on the main thread and from a second thread; `pii` equivalent is `ok` | **expected failure to isolate in-process**; three processes, three orders: identical |
| CLI | one process per run | n/a | n/a | standard input | `--ruleset` (refused with standard input) | n/a | n/a | not run; per-invocation by construction (`--pii`), source-inspected |

Precise observations:

- Node: `configure.B` activation is
  `credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2`;
  streams give A `[]`, B `[pii_global_email, pii_global_network_address]`, C
  `[pii_global_network_address]`.
- Node: calling `piiActivation()` on a thread that was never initialized
  returns the PII-off identity **and** locks that thread to off; a following
  `initializePii` with another selection is `PII_ACTIVATION_CONFLICT`. The JS
  facade guards this by requiring `initialize()` first; the raw addon is not a
  `status()` and is not side-effect-free.
- WASM: an uninitialized instance reports `NOT_INITIALIZED` for both `scan` and
  `piiActivation`.
- WASM: a bare synthetic GitHub-token-shaped value is `github_token` under
  `full` and no finding under `common`; the same value after `API_KEY=` is
  `github_token` under `full` and `contextual_secret` under `common`.
- WASM memory: about 1.7 MiB RSS per initialized `pii` instance over 10
  instances in one indicative run (no performance claim).
- Python: `import redact_secret` fails inside a Python 3.14 sub-interpreter
  (`ExecutionFailed`); not investigated further. `status()` reports
  `activation=None` before and the identity after `initialize`; its `repr` prints
  `activation=Some("...")` because it formats the Rust `Option` with `{:?}`. That
  is a cosmetic defect in `bindings/python/src/lib.rs` (`PyCoreStatus::__repr__`),
  not fixed here.

## Commands

From the repository root at `db0e5c8d`; `$S` is a scratch directory.

```bash
# Rust: new regression guard, then the neighbouring registry tests
cargo test -p redact-secret --locked --test pii_instance_isolation_1221   # 7 passed
cargo test -p redact-secret --locked --test built_in_registry_1178
cargo clippy -p redact-secret --locked --test pii_instance_isolation_1221 -- -D warnings

# Node addon, raw (no npm install)
cargo build -p redact-secret-node --release --locked
cp target/release/libredact_secret_node.dylib $S/redact-secret.node
node docs/audits/evidence/1221/probe-node.mjs $S/redact-secret.node       # PASS node probe

# WASM, four artifacts (full, full+pii, common, common+pii)
node scripts/build-browser-artifact.mjs --out-dir $S/wasm-full
node scripts/build-browser-artifact.mjs --detector-profile common --out-dir $S/wasm-common
node docs/audits/evidence/1221/probe-wasm.mjs $S                          # PASS wasm probe

# Python wheel
python3 -m venv $S/venv
(cd bindings/python && maturin build --release --locked -o $S/wheels)
$S/venv/bin/pip install $S/wheels/redact_secret-0.1.0b13-cp310-abi3-macosx_11_0_arm64.whl
$S/venv/bin/python -I docs/audits/evidence/1221/probe-python.py           # PASS python probe
```

The probes are `probe-node.mjs`, `probe-wasm.mjs` and `probe-python.py` in this
directory. They are manual evidence, not CI gates: they need a built addon,
glue or wheel. The Rust test is the deterministic regression guard and runs in
`cargo test`. No legacy test, fixture or contract was changed.

## Findings that bear on the decision

1. **Rust needs no work.** `BuiltInRegistry` (#1178) and the per-session
   `IncrementalSanitizer` already give per-instance PII, both profiles and
   thread sharing. The one thing a `BuiltInRegistry` cannot do is take a
   ruleset; that is `DetectorRegistry`, `!Send`, and stays so.
2. **The core is stateless; every binding re-introduces the global.** All
   isolation failures are in the binding ownership layer, none in the engine.
3. **Isolation without new API already exists, with a cost.** Node: one Worker
   per owner; WASM: one module instance per owner (not reachable through the
   facade); Python: one process per owner. These are workable recipes for
   hosts that already have a worker or process boundary, and are what a
   documentation-only outcome would state.
4. **Handles are cheap in the core, expensive in the facade.** A binding-owned
   scanner needs only a profile, a `PiiSelection` and an optional ruleset
   (all `Send + Sync` except the ruleset-bearing `DetectorRegistry`). The cost
   is in the JavaScript facade and the WASM artifact choice (section below).

## Recommendation for #1222

**Decision: go, narrowly, for Node and Python; defer WASM; Rust is docs-only.
If the adapters' multi-tenant requirement
([adapters#213](https://github.com/redact-secret/redact-secret-adapters/issues/213))
is not confirmed in-process, the fallback is the documentation-only outcome in
the last row.**

| Surface | Recommendation | Why |
| --- | --- | --- |
| Rust | **docs only** | `BuiltInRegistry` is the handle; #1222 should state that a configuration-bound scanner in Rust is `BuiltInRegistry` (plus `DetectorRegistry` when a ruleset is needed), not a second ownership model |
| Node | **go**: an additive handle class on the native addon and the facade | it is the surface where an adapter lives; Workers work but force an async, message-passing boundary that logging and tracing adapters cannot take |
| Python | **go**, smaller | a process-wide static is the only blocker; a frozen `BuiltInRegistry`-backed object removes it and also gives the first thread-shareable Python handle |
| WASM | **defer**; document the module-instance recipe | the artifact (default or `pii`, `full` or `common`) is chosen at load, so a facade handle must manage several downloads and instances; needs a stated demand before the design is worth its size |

### Shape, scope and size

Common shape (one design, three bindings): a handle is built once from a fixed
`{ profile, pii, ruleset? }`, immutable afterwards, and exposes `scan`,
`scanAndRedact`, `redact` and an incremental-session factory with the
legacy functions' argument and error contract. It does not replace the
one-shot `initialize()`; the legacy singleton keeps its idempotent-equivalent
and differing-selection-conflict behavior unchanged and is tested as before.

- **Core**: no change. A handle holds a `BuiltInRegistry` (no ruleset) or a
  `DetectorRegistry` (with a ruleset); a session is
  `IncrementalSanitizer::with_*_and_pii_*`, which already captures its selection.
  No new public Rust name, so no `core-public-api` or contract-class change.
- **Node** (about 300 to 450 lines of Rust in `bindings/node/src/lib.rs` and
  `incremental.rs`, an `.d.ts` and facade class in `packages/javascript`,
  conformance rows and a smoke test): a `#[napi]` class holding the registry;
  the facade builds on the loaded binding. For a WASM-fallback Node the facade
  must route to the WASM implementation, so Node cannot ship before the WASM
  decision is at least recorded; scope Node's handle to the native addon and
  make the fallback explicit (an error, not silent shared state) if WASM is
  deferred.
- **Python** (about 200 to 300 lines in `bindings/python/src/lib.rs` and
  `incremental.rs`, type stubs, tests): a `#[pyclass(frozen)]` object holding a
  `BuiltInRegistry`; no GIL-held global.
- **WASM** (if later chosen; about the Node size plus artifact management): a
  `wasm-bindgen` class on one module instance; a handle that needs PII requires
  the `pii` artifact, so the facade needs a per-handle artifact choice and a
  download-cost statement. Sizes are in the matrix.
- **Tests**: a binding conformance row per surface for A/B/C isolation, the
  legacy conflict test unchanged, and the Rust test of this record.

### Thread and reentrancy implications

- Rust handles are `Send + Sync`; `Policy` and formatter are per-call. A
  ruleset-bearing registry is `!Send`; keep it on its creating thread.
- A Node or WASM handle is single-threaded and thread-affine: it must not be
  moved to another Worker, exactly like an existing incremental session. Document
  this, and make a wrong-thread call fail with a fixed error rather than race.
- Policy and formatter callbacks run synchronously inside a scan. A callback
  may call another handle's scan, or the same handle's scan, because the
  registry is only read; it may not mutate configuration, which a handle does
  not allow. The ruleset cache must hold no borrow across a callback (the
  existing Node cache clones an `Rc` out for this reason; a handle must keep
  that property).
- Python handles are `Sync`, so they can be shared across threads and, under
  free threading, used concurrently.

### What must be rejected as unsupported

- Reconfiguring a handle (selection, profile, ruleset) after construction, or
  turning the singleton into a mutable one.
- Runtime detector selection by id, and a numeric sensitivity or confidence
  slider; neither has a supported detector contract.
- A handle shared between Workers or processes, and a `Sanitizer` builder that
  bundles policy and formatter (deferred by #1097).
- Accepting a shared `BuiltInRegistry` in `IncrementalSanitizer` (decided
  against in #1178 until session start cost is shown to matter).
- A `common` or `full` choice made implicitly from the selection.
- Any claim that handles are faster than the singleton; #1097's result stands.

### Documentation-only outcome (the exit)

If in-process multi-tenancy is not required by the adapters, #1222 closes with
documentation: a section stating that Rust uses `BuiltInRegistry`, Node uses one
Worker per configuration, WASM uses one module instance per configuration (glue
level), Python uses one process per configuration, plus the matrix and the
`piiActivation()` caution above. This needs no code and is the cheapest honest
position.

## Blockers and open items

- The facade (`@redact-secret/core`) was not executed here; the Worker claim for
  it is by source (a runtime per module evaluation), not by test. Run the probe
  shape through the built package before relying on it.
- The CLI was not executed; its isolation is by process.
- Adapter demand for in-process tenancy is stated only as a dependency in the
  linked issues; it is the input that selects between the go and the
  documentation-only outcome.
