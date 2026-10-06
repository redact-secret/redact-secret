# Detector capability and configuration ownership matrix

[Documentation home](../README.md)

Which configuration each surface can express (profile, PII selector, ruleset,
detector selection, incremental sessions, status), who owns that configuration
in a process, and where each kind of control acts in the pipeline. It answers
the research of [#1221](https://github.com/redact-secret/redact-secret/issues/1221);
the executed same-process experiments behind the isolation rows are in
[`docs/audits/evidence/1221`](../audits/evidence/1221/README.md). It records
current behavior and decides no policy: the rules it summarizes are in the
[engine spec](../specs/engine.md) and the records linked below.

Source: `main` at `db0e5c8d` (`0.1.0-beta.13`), 2026-10-06.

Status words:

- **supported**: present in the shipped surface and covered by a test or
  conformance fixture.
- **extension**: not present, but fits the existing ownership model, needs no
  core contract change, and can be maintained as an additive change.
- **unsupported**: not present and either excluded by an accepted decision or
  would need a new contract; do not promise it.

## 1. Detection selection

Detection selection decides which detectors can produce a candidate. It is the
only layer that changes what can be found at all.

| Capability | Rust core | Node (native, WASM fallback) | WASM (browser, workerd) | Python | CLI |
| --- | --- | --- | --- | --- | --- |
| `full` profile | supported (`with_built_in*`) | supported (root export) | supported (default artifact) | supported (the only profile) | supported (the only profile) |
| `common` profile | supported (`with_common_built_in*`) | supported (`@redact-secret/core/common`; the addon links both and exposes `*Common` functions) | supported (separate `common` artifact, chosen at build time by the `full` Cargo feature) | **extension** (`profile()` is the constant `full`; adding `*_common` functions follows the Node pattern) | **extension** (no profile flag; `Profile::Full` only) |
| Both profiles in one process | supported | supported (independent registries and PII cells per profile) | supported (two module instances) | unsupported | unsupported (one profile per invocation) |
| Disable or select one detector by id at run time | unsupported | unsupported | unsupported | unsupported | unsupported |
| Register a custom Rust `Detector` | supported (`DetectorRegistry::register`, `!Send`) | unsupported | unsupported | unsupported | unsupported |
| Declarative ruleset (adds detectors) | supported (`load_ruleset` into `DetectorRegistry`; not `BuiltInRegistry`) | supported (argument of `scan`, `scanAndRedact`; not incremental) | supported (same, per module instance) | supported (`ruleset=` of `scan`, `scan_and_redact`; not incremental) | supported (`--ruleset <path>`; refused with standard input) |
| PII selector | per registry or session (`PiiSelection`) | one-shot per thread and profile (`initialize({ pii })`) | one-shot per module instance; only the `pii` artifact variant accepts a selection | one-shot per process (`initialize(pii=...)`) | per invocation (`--pii`, repeatable) |

Per-detector runtime selection is excluded by the
[profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)
("Runtime detector selection by detector id is not offered on any surface"). A
profile is the unit of selection; a ruleset only adds.

### Detector disabling and overlap

Removing a detector never removes its text from consideration: the candidates
that remain compete, and a weaker detector can claim the same span.

- Overlap is resolved after detection by resolved-action severity, then total
  evidence weight ([severity](../decisions/2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md),
  [weight](../decisions/2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md)).
  A provider candidate that is not generated cannot be recovered by any later
  policy change.
- Measured on the built artifacts (probe in the evidence record): a bare
  synthetic GitHub-token-shaped value is `github_token` under `full` and no
  finding under `common`; the same value after `API_KEY=` is `github_token`
  under `full` and `contextual_secret` under `common`. So disabling a
  provider detector can change the finding type, the detector id and the
  default action of a span, not only drop it, whenever a contextual or
  structural detector also matches.
- PII detectors enter the same overlap arbitration as credentials
  ([PII contract](../decisions/2026-09-26-define-the-pii-domain-scope-arbitration-and-activation-contract.md)).
  A PII selection never changes a credential finding for the same input
  (pinned by `crates/secret-scan-core/tests/pii_instance_isolation_1221.rs`).

## 2. Identity and sensitivity gates, confidence, action policy

These are three separate layers after detection. They are not a sensitivity
dial, and none can recover what an earlier layer removed.

| Layer | Acts on | Public control today | Cannot do |
| --- | --- | --- | --- |
| Identity and sensitivity gate (PII families) | whether a candidate is established as the identity and as sensitive in context; `not-established` and `non-sensitive` produce no finding | the PII selector chooses which families run; the gate itself is internal, per family (`contextRequirement`) and is a non-public evaluation seam (#910) | be tuned, thresholded or exposed; a gated-out value is a non-finding, not a low-confidence finding |
| Emitted confidence | categorical `high`, `medium`, `low` on an emitted finding | read-only metadata on findings | be a calibrated probability or a percentage; a shadow evidence score is a separate frozen artifact, not confidence |
| Action policy | `allow`, `warn`, `redact`, `block` for an emitted, overlap-resolved finding | a callback per call or session; the default policy; a declarative policy document is designed in [#1217](https://github.com/redact-secret/redact-secret/issues/1217) | resurrect a candidate that detection, the gate or overlap dropped |

Consequence: a request for "more sensitive" or "less sensitive" is one of
three different things (select more detectors or families, change a gate, change
an action). Only the first is a supported public control. **A numeric
sensitivity slider has no supported detector contract and no qualification, and
is not offered.**

## 3. Incremental sessions, status and activation

| Capability | Rust core | Node | WASM | Python | CLI |
| --- | --- | --- | --- | --- | --- |
| Incremental session | supported; captures its `PiiSelection` at construction and owns its registry | supported; reads the thread's PII selection at creation; no ruleset | supported; no ruleset | supported; reads the process PII selection at creation; no ruleset | supported for standard input; `--ruleset` refused |
| Accept a shared `BuiltInRegistry` | unsupported by decision (a session owns its registry; the per-session build is the one #1097 cost) | n/a | n/a | n/a | n/a |
| Read activation identity | supported (`activation_identity()` on `DetectorRegistry`, `BuiltInRegistry`, `IncrementalSanitizer`) | supported (`piiActivation()`, after `initialize`) | supported (`piiActivation()`, after `initialize`) | supported (`pii_activation()`) | supported (`--print-pii-activation`, reads no input) |
| Side-effect-free `status()` ([#1172](https://github.com/redact-secret/redact-secret/issues/1172)) | n/a (no lifecycle) | supported (root and `./common`) | supported | supported (`redact_secret.status()`) | n/a |
| Readiness claim from an empty scan | unsupported | unsupported | unsupported | unsupported | unsupported |

An empty scan proves neither that PII is off nor that it is on; use `status()`
or the activation identity
([status record](../decisions/2026-10-05-add-a-side-effect-free-status-query-and-defer-a-published-readiness-probe.md)).
A native read that is not a `status()` can have a side effect: the Node
addon's `piiActivation()` builds the thread's registry with PII off when the
thread has not been initialized, which then makes a later
`initializePii` with another selection a conflict. The `@redact-secret/core`
facade guards this by requiring `initialize()` first; the raw addon does not.

## 4. Configuration ownership and per-instance PII isolation

Who owns the PII selection, the registry and the ruleset cache decides whether
two tenants can have different selections in one process.

| Surface | PII selection owner | Registry owner | Ruleset cache | Independent configurations in one process |
| --- | --- | --- | --- | --- |
| Rust core | each `DetectorRegistry`, `BuiltInRegistry` and `IncrementalSanitizer` | the value itself; `BuiltInRegistry` is `Send + Sync` ([#1178](../decisions/2026-10-05-add-a-send-sync-built-in-only-registry-as-a-distinct-type.md)) | none (a ruleset is built into a `DetectorRegistry`) | **supported**: any number, no global state |
| Node addon | thread-local cell per profile | thread-local registry per profile | one slot per thread | **supported per thread**: each `worker_threads` Worker is an independent owner; the main thread is one more. Not supported inside one thread |
| `@redact-secret/core` JS facade | the addon or WASM binding behind one runtime per entry profile | same | same | **unsupported inside one thread** (one runtime per entry profile; another wrapper object shares it). A Worker that imports the package gets its own runtime |
| WASM artifact | thread-local cell of the module instance | thread-local registry of the module instance | one slot per module instance | **supported per module instance**: instantiating the generated glue twice gives independent state (about 1.7 MiB RSS per `pii` instance, one indicative run). The facade binds one instance per entry profile and does not expose this |
| Python wheel | one process-wide static plus an epoch | a thread-local cache keyed by that epoch | one slot per thread, invalidated by the epoch | **unsupported in one process**: a second selection is `PiiActivationConflictError`, from any thread; `import redact_secret` failed in a Python 3.14 sub-interpreter. Separate processes are independent |
| CLI | one invocation | one invocation | one invocation | per process; each run is independent |

Preserved legacy contract, on every surface that has a one-shot
`initialize`: an equivalent selection (including the alias spelling `pii` for
`pii:global`) is idempotent; a differing selection, including PII on after
off, off after on, and PII on after a lazy PII-off registry exists, is
`PII_ACTIVATION_CONFLICT`
([runtime bindings](../decisions/2026-09-09-define-runtime-bindings.md)). A
conflict does not change the active selection.

## 5. WebAssembly artifact footprint

Four artifacts per release, from `node scripts/build-browser-artifact.mjs`
at `db0e5c8d` (release profile; gzip level 9; brotli quality 11; sizes of the
`.wasm` file; JavaScript glue not included). Size is deterministic for one
toolchain; it is a footprint fact, not a performance claim.

| Artifact | Raw | gzip | brotli |
| --- | ---: | ---: | ---: |
| `full` | 618,395 | 212,202 | 164,789 |
| `full` + `pii` | 917,156 | 335,579 | 262,175 |
| `common` | 418,579 | 146,036 | 116,647 |
| `common` + `pii` | 717,495 | 268,647 | 214,169 |

Effects:

- `common` is 32.3% smaller raw (29.2% brotli) than `full`; the PII runtime
  adds 298,761 B raw (97,386 B brotli) to `full` and 298,916 B raw (97,522 B brotli) to `common`.
- The PII runtime is a separate artifact. The facade loads it only when
  `initialize()` receives a PII selection, so a runtime that never enables PII
  never fetches it.
- A handle that must differ by PII selection and profile therefore needs the
  matching artifact: PII-off and PII-on tenants in one browser page need two
  downloads (the default and the `pii` artifact), and a `common` tenant a
  third, unless every tenant uses the `pii` artifact. Disabling detectors
  inside an artifact is not possible at run time (section 1), so footprint
  changes only by choosing a different artifact.
- Link-time reachability, not a flag, removes provider code from `common`
  ([profile contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)).
  Node and Python ship native code, so a profile or PII choice does not change
  their download size.

## 6. What this does not authorize

- No per-detector selection, no numeric sensitivity or confidence threshold,
  and no change to the identity and sensitivity gate is offered.
- No second, reconfigurable global; a handle, when one is added, is built
  once with a fixed selection and never mutated.
- Installed-runtime parity and performance are not claimed here. Performance
  results stay in `redact-secret-benchmarks`
  ([decision](../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)),
  and [#1097](https://github.com/redact-secret/redact-secret/issues/1097)'s
  result (document reuse; no new reuse API for speed) stands.
