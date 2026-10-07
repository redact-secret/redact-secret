---
decision_id: decision-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python
status: accepted
scope: workspace
title: Keep the configuration-bound scanner handle out of 0.1.x for Node, WebAssembly and Python
decided_at: 2026-10-06
spec: engine
---

# Keep the configuration-bound scanner handle out of 0.1.x for Node, WebAssembly and Python

## Context

Issue [#1222](https://github.com/redact-secret/redact-secret/issues/1222), a
child of epic [#1216](https://github.com/redact-secret/redact-secret/issues/1216),
asks whether to add a configuration-bound scanner: an object built once from a
fixed detection configuration (profile, PII selection, optional ruleset) that
owns its scans. The issue allows a documentation-only outcome when "docs plus
existing injection solve the need", and says to implement a handle only after
the ownership decision. This record is that decision.

What exists, with its evidence:

- **The action policy is already user-owned and stateless.**
  [`decision-define-the-versioned-declarative-action-policy-and-default-overlay`](2026-10-06-define-the-versioned-declarative-action-policy-and-default-overlay.md)
  (#1219) makes it a per-call argument on the Rust core, the CLI, JavaScript and
  Python; nothing is cached in a module, so two live policies never affect each
  other.
  [`decision-explain-and-compare-action-policies-over-one-detection-pass`](2026-10-06-explain-and-compare-action-policies-over-one-detection-pass.md)
  (#1220) previews a change over one detection pass. A handle would add nothing
  to either.
- **Rust already has the handle.**
  [`decision-add-a-send-sync-built-in-only-registry-as-a-distinct-type`](2026-10-05-add-a-send-sync-built-in-only-registry-as-a-distinct-type.md)
  (#1178) is an immutable `Send + Sync` value with its own PII selection, and
  that record is the Rust-side answer #1097 named as a reopen trigger. The
  executed A/B/C tests of [#1221](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1221/README.md)
  (`crates/secret-scan-core/tests/pii_instance_isolation_1221.rs`, 7 tests) show
  three PII configurations coexisting in every construction order, across
  threads, in interleaved sessions and across teardown. A second ownership model
  in Rust is not needed.
- **The core is stateless; the binding layer re-introduces the global.** The
  gap is in three bindings only: the Node addon keeps per-thread, per-profile
  registry and PII cells (`bindings/node/src/lib.rs`), the WebAssembly module
  keeps thread-local cells per module instance (`bindings/wasm/src/lifecycle.rs`,
  with one ruleset slot), and the Python wheel keeps one process-wide
  `PII_SELECTION` with an epoch. The `@redact-secret/core` facade binds one
  runtime per entry profile, so configuring another wrapper object shares it.
- **Isolation without new API works, and this change ran it.** #1221 executed
  Node (one `worker_threads` Worker per owner), WebAssembly (one module instance
  per owner) and Python (one process per owner) on the raw bindings; the
  [#1222 evidence](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1222/README.md) re-ran the Node recipe
  through the built `@redact-secret/core` facade, which #1221 had left as source
  inspection only. A Worker that imports the package gets its own runtime and
  three Workers produce `[]`, email plus network address, and network address
  only. The legacy contract (equivalent selection idempotent, differing one
  `PII_ACTIVATION_CONFLICT`, conflict changes nothing) held on every surface and
  must stay.
- **No performance rationale exists.**
  [#1097](https://github.com/redact-secret/redact-secret/issues/1097) and #1100
  decided "document only, no API change" and measured reuse at 14.2x on 11 bytes
  and 1.015x on 64 KiB; #1178's probe puts building one registry at about 15
  microseconds. #1222 states its rationale as configuration ownership and PII
  isolation, and nothing in this epic measures a gain from a handle.

## Decision

### 1. No new public configuration-bound scanner handle in 0.1.x for Node, WebAssembly or Python

No class, factory or function that is built from a fixed detection configuration
and then scans is added to `@redact-secret/core`, `@redact-secret/wasm` or the
Python package. The one-shot `initialize()` singleton and its idempotent and
conflict behavior are unchanged. Rust and the CLI need none: `BuiltInRegistry`
(with `DetectorRegistry` when a ruleset is needed) is the Rust handle, and a CLI
run is one configuration.

### 2. The supported answer is documented ownership and recipes

[`docs/guides/configuration-ownership.md`](../guides/configuration-ownership.md)
states, per surface, who owns detection configuration, action policy and host
limits, and gives recipes that were run: Rust `BuiltInRegistry` shared across
threads with different PII selections; Node one `initialize` per Worker; WebAssembly
one module instance per configuration (glue level); Python one process per
configuration; and the per-call `actionPolicy` and `compareActionPolicies` for
policy changes. It lists what is unsupported and why configuring a second
JavaScript wrapper does not isolate the singleton. The capability matrix and the
action-policy, JavaScript, Python and Rust guides link to it.

### 3. The remaining gap, stated precisely

Only this is not served: **independent PII selections, profiles or rulesets in
one thread (Node), one module instance (WebAssembly) or one process (Python)**.
Node and WebAssembly are served by a thread or instance boundary; Python is
served only by a process boundary and has no thread-shareable handle.

### 4. Why not, in order of weight

1. **Policy ownership is already solved without a handle.** The action policy
   is the configuration a deployment changes most often, and it is a per-call
   argument with a comparison primitive. A handle would hold only detection
   configuration, which changes rarely.
2. **Rust is done and the executed tests exist.** The shareable handle is
   shipped and tested (#1178, #1221).
3. **The residual gap has working recipes and no stated demand.** The adapters'
   multi-tenant requirement
   ([adapters#213](https://github.com/redact-secret/redact-secret-adapters/issues/213))
   is a dependency in the linked issues, not a confirmed in-process requirement
   with evidence that injection fails.
4. **No measured gain.** #1097 and #1100 stand: no reuse API for performance.
5. **A handle is public API and cost.** It would add names to the 0.1.x contract
   frozen by #1066 (additive, but permanent), and #1221 estimates about 300 to
   450 lines of Rust plus a declaration file, facade class, conformance rows and
   a smoke test for Node, and about 200 to 300 lines for Python: 500 to 750
   lines of binding ownership work, plus a WebAssembly design that has to manage
   a per-handle artifact choice (default or `pii`, `full` or `common`) and
   several downloads. This epic has already raised the `full` WebAssembly
   artifact by about 7% against `db0e5c8d` (the action policy parser, the digest
   and the comparison together add 11,493 bytes, 7.0%, as recorded by #1220), so
   another surface that must ship in every artifact is not free.
6. **A mutable closure could never be called immutable.** A handle that accepted
   callbacks (a policy or a formatter) would carry caller state that the
   library cannot freeze, so the claim "immutable once built" holds only for a
   handle that takes data and no callback. That narrows what a handle could
   honestly be.

### 5. The cost of this decision

- A user who needs in-process multi-tenant PII isolation in Node or WebAssembly
  must use a Worker or a module instance. A Worker boundary is asynchronous
  message passing, so a synchronous logging or tracing adapter cannot use it
  without restructuring, and each Worker holds its own runtime. The
  WebAssembly instance recipe is not reachable through the facade and depends on
  distinct module URLs surviving the bundler.
- Python has no in-process answer and no thread-shareable handle; a process per
  configuration costs interpreter and memory startup.
- A component that calls `initialize` with its own PII selection can make
  another component's call a conflict. Documentation states it; the library does
  not prevent it.
- The decision gives up the chance to land the handle before a consumer builds on
  the workaround, and the later change must keep the recipes working.

### 6. Reopen triggers

Any one of these reopens the decision, with the evidence named:

1. **An in-process multi-tenant PII isolation requirement** stated by an adapter
   or a user, naming the deployment shape and showing that Workers, module
   instances or processes cannot serve it (a synchronous boundary, a measured
   startup or memory cost, a platform without Workers).
2. **adapters#213 showing injection cannot work without a handle**, with a
   reproduction against the recipes in the guide.
3. **A measured construction cost that matters**: registry or session
   construction per call, or Worker or process startup, shown against #1097's
   build criteria (for example short-input repeated calls at least 3x slower than
   reuse), with the numbers in an evidence record.
4. **A free-threaded or multi-threaded Python consumer** that needs one
   registry shared across threads, with the consumer named.
5. **A defect in the legacy conflict contract** that harms a real integration
   and cannot be fixed by documentation.

Absent one of these, a request for a handle is answered with the guide.

### 7. The exact minimal future design

A later session starts from #1221's recommendation, narrowed as follows:

- **Core**: no change. A handle holds a `BuiltInRegistry` (no ruleset) or a
  `DetectorRegistry` (with a ruleset); a session is
  `IncrementalSanitizer::with_*_and_pii_*`.
- **Shape**: built once from a fixed `{ profile, pii, ruleset? }`; immutable
  afterwards; exposes `scan`, `scanAndRedact`, `redact` and an incremental
  session factory with the legacy functions' argument and error contract; takes
  the action policy and limits per call. It does not replace `initialize()`.
- **Node**: a `#[napi]` class holding the registry plus a facade class on the
  loaded binding, scoped to the native addon. On the WebAssembly fallback it
  fails with a fixed error and never silently shares state.
- **Python**: a `#[pyclass(frozen)]` object holding a `BuiltInRegistry`, with no
  global and no GIL-held state; the first thread-shareable Python handle.
- **WebAssembly**: deferred until a stated browser demand; it would be a
  `wasm-bindgen` class on one module instance with a per-handle artifact choice
  and a download-cost statement.
- **Thread rules**: a Node or WebAssembly handle is thread-affine, like an
  incremental session, and a wrong-thread call fails with a fixed error. A
  callback may call another handle, or the same handle, because the registry is
  only read, and holds no borrow across a callback.
- **Rejected for that design**: any mutation after construction (selection,
  profile or ruleset); per-detector selection by id (amended by [`decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`](2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md): one validated `detection` value is allowed in the immutable shape); a numeric sensitivity or
  confidence slider; sharing a handle across Workers or processes; a
  `Sanitizer` builder that bundles policy and formatter (deferred by #1097);
  accepting a shared registry in `IncrementalSanitizer` (decided against in
  #1178); choosing `common` or `full` implicitly from the selection; and any
  claim that a handle is faster than the singleton.
- **Tests**: an A/B/C isolation conformance row per surface, the legacy conflict
  tests unchanged, and the Rust tests of #1221.

## Trade-offs

This is a decision about ownership, not detection, so it changes no finding and
has no false-positive or false-negative cost. The risk is organizational: a
consumer may build on a Worker or process workaround that a handle would make
simpler. The cost is accepted because the workaround is verified, no consumer
has stated the requirement, and the alternative adds permanent public surface
and artifact size on three bindings.

## Alternatives considered

- **Ship a Node and Python handle now** (the #1221 recommendation, conditional on
  the adapters' requirement). Rejected: the condition is unmet, and the cost and
  contract growth in section 4 buy nothing measured.
- **Ship all three, including WebAssembly.** Rejected for the artifact-management
  design and size, with no demand.
- **A mutable configuration object or a `reconfigure` method.** Rejected: it
  reintroduces the shared-state conflict the legacy contract exists to prevent,
  and cannot be described as immutable.
- **Relax the legacy conflict so a second `initialize` replaces the first.**
  Rejected: a silent replacement changes what an adapter that verified the
  selection believes is active.
- **Wrap the singleton in a per-call facade object.** Rejected: it would share
  the runtime, so it would look isolated and not be.

## Consequences

No product code, public name, error code, finding field or artifact changes. The
engine spec gains one row; the guide is new; the capability matrix, the action
policy, JavaScript, Python and Rust guides, `docs/README.md` and the changelog
link to or record it. The recipes are checked by
`crates/secret-scan-core/tests/configuration_ownership_1222.rs` (Rust, run in
`cargo test`) and by `examples/configuration-ownership/guide-sync.test.mjs`
(the Node, WebAssembly and Python files are the guide's blocks verbatim), and
were run against built artifacts as the evidence records. #1222 closes with a
documentation-only outcome; the reopen triggers above are the only route to a
handle.
