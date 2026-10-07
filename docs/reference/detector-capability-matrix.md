# Detector capability and configuration ownership matrix

[Documentation home](../README.md)

Which configuration each surface can express (profile, PII selector, ruleset,
detector selection, incremental sessions, status), who owns that configuration
in a process, and where each kind of control acts in the pipeline. It answers
the research of [#1221](https://github.com/redact-secret/redact-secret/issues/1221);
the executed same-process experiments behind the isolation rows are in
[`docs/audits/evidence/1221`](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1221/README.md). It records
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
| Disable or select one detector by id at run time | **proposed** (accepted by the [#1249 records](#6-configuration-epic-1246-surface-matrix), not built) | **proposed** (`initialize`) | **proposed** (`initialize`) | unsupported | unsupported |
| Register a custom Rust `Detector` | supported (`DetectorRegistry::register`, `!Send`) | unsupported | unsupported | unsupported | unsupported |
| Declarative ruleset (adds detectors) | supported (`load_ruleset` into `DetectorRegistry`; not `BuiltInRegistry`) | supported (argument of `scan`, `scanAndRedact`; not incremental) | supported (same, per module instance) | supported (`ruleset=` of `scan`, `scan_and_redact`; not incremental) | supported (`--ruleset <path>`; refused with standard input) |
| PII selector | per registry or session (`PiiSelection`) | one-shot per thread and profile (`initialize({ pii })`) | one-shot per module instance; only the `pii` artifact variant accepts a selection | one-shot per process (`initialize(pii=...)`) | per invocation (`--pii`, repeatable) |

The [profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md)
excluded per-detector runtime selection; the [#1249 records](../decisions/2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md)
amended that for Rust, Node and WebAssembly, and section 6 has what shipped
with #1251: a selection by detector id, fixed once by the initialization owner,
within the artifact's compiled detectors. A profile is still the named unit; a
ruleset only adds; Python and the CLI stay profile-only.

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
| Action policy | `allow`, `warn`, `redact`, `block` for an emitted, overlap-resolved finding | a callback per call or session; the default policy; a declarative policy document ([#1217](https://github.com/redact-secret/redact-secret/issues/1217), implemented in Rust, the CLI and JavaScript by [#1219](https://github.com/redact-secret/redact-secret/issues/1219)); a whole-input preview of what up to four policies choose and why, over one detection pass ([#1220](https://github.com/redact-secret/redact-secret/issues/1220): Rust `compare_action_policies`, CLI `--compare-action-policy`, JavaScript `compareActionPolicies`; not incremental or stream) | resurrect a candidate that detection, the gate or overlap dropped |

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
two tenants can have different selections in one process. The
[configuration ownership guide](../guides/configuration-ownership.md) turns this
table into recipes that were run, and
[`decision-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python`](../decisions/2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md)
records that no configuration-bound handle is added to Node, WebAssembly or
Python in 0.1.x.

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

## 6. Configuration epic #1246 surface matrix

Decided by the [#1249 records](../decisions/2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md) ([data contracts](../decisions/2026-10-07-define-the-artifact-manifest-and-configuration-data-contracts.md), [selection and precedence](../decisions/2026-10-07-define-detector-id-selection-and-configuration-replacement-precedence.md)).
**existing** is shipped; **proposed** is accepted but not built, so do not
promise it before its issue lands; **unsupported** is excluded until a consumer
requirement with evidence reopens it. The rows above are unchanged unless named.

| Capability (issue) | Rust | Node | WASM, browser | Python | CLI |
| --- | --- | --- | --- | --- | --- |
| `full`, `common` profiles | existing | existing | existing | existing (`full`) | existing (`full`) |
| Artifact manifest, generated from the real composition (#1250) | existing (`ArtifactManifest`) | existing (`artifactManifest()`; addon `artifactManifest`, `artifactManifestCommon`) | existing (`artifactManifest()`; one manifest per built artifact) | existing (`artifact_manifest()`) | existing (`--print-artifact-manifest`) |
| `resolveConfig`, `describeConfig`, `status().configuration` (#1251) | existing (`resolve_config`, `describe_config`) | existing (`resolveConfig()`, `describeConfig()`, `status().configuration`; addon `resolveConfig`, `resolveConfigCommon`) | existing (`resolveConfig()`, `describeConfig()`; module export `resolveConfig`) | unsupported | unsupported |
| Safe diagnostics (#1252) | proposed | proposed | proposed | unsupported | unsupported |
| Runtime detector-id selection, owned by `initialize` or the registry (#1251) | existing (`DetectorRegistry::with_detection`) | existing (`initialize({ detection })`; addon `initializeDetection`, `initializeCommonDetection`) | existing (`initialize({ detection })`; module `initialize(pii, detection)`) | unsupported | unsupported |
| Static custom composition (#1253) | proposed (leaf crate) | unsupported | proposed, first | unsupported | unsupported |
| `compareConfigurations`, per call, preview only (#1254) | proposed | proposed | proposed | unsupported | unsupported |
| Action policy and `compareActionPolicies` | existing | existing | existing | policy only | existing |
| Configuration-bound handle for Node, WASM, Python | n/a | unsupported (#1222) | unsupported (#1222) | unsupported (#1222) | n/a |
| NER, sensitivity percentage, identity-gate control | unsupported | unsupported | unsupported | unsupported | unsupported |

Included, enabled, emitted and action are four levels, and a later level never
exceeds the earlier one; an unsupported request is rejected, never ignored or
fetched.

### The artifact manifest (#1250)

`artifact-manifest/v1` is the **included** level, read without a scan and
without initialization. The Rust core generates it from the registration rows
the artifact links, so a binding forwards one value and keeps no detector,
pack or type table of its own. What it says and does not say:

- **Native linking is described as it is.** The Node addon and the Python wheel
  link the `full` registry (the addon also links `common`, exposing a second
  manifest through `artifactManifestCommon`); the manifest reports what each
  profile contains. Importing `@redact-secret/core/common` selects the `common`
  registry and a `common` manifest, but the addon file is the same one: it makes
  no claim of a smaller native download. Only the WebAssembly `common` build is
  smaller, and its manifest names the `full` ids it lacks as ids only.
- **Types are declared, not closed.** `detectors[].types` is each built-in's
  reviewed declaration (`docs/coverage/detector-inventory.json`, reconciled in
  the Rust drift tests). A ruleset, a custom Rust detector and the PII adapter
  emit types the list does not name, so `typeVocabulary.complete` is `false`
  and `dynamicSources` says which.
- **No side effect.** Reading it builds no registry and reads no PII
  selection, so it cannot start or lock the legacy PII activation: a later
  `initialize({ pii })` still applies. The JavaScript `artifactManifest()`
  reports the artifact `initialize()` loaded, so it follows a successful
  `initialize()` there; the Python function, the CLI flag and the Rust API need
  none.
- **Bound to the artifact, not to a second pipeline.** The manifest is part of the
  binary, so the artifact digests the release process already records cover it;
  its own `digest` is the SHA-256 of its canonical JSON, and the facade checks it
  at `initialize()`. Its `sourceRevision` is `null` unless the build set
  `REDACT_SECRET_SOURCE_REVISION`. It is not the release manifest and carries no
  provenance record.
- **Fixed diagnostics.** A manifest that is missing, of another schema or
  version, of another variant, or whose digest is not its own fails
  `initialize()` with `INITIALIZATION_FAILED` and echoes none of the document.

### Detector selection and configuration resolution (#1251)

Implemented once in the Rust core; every binding forwards to it and keeps no
precedence table, detector list or default of its own. What it does and does
not say:

- **Selection acts at composition.** A disabled detector is not prefiltered and
  has no candidate or overlap role. The prefilter is recompiled over the
  survivors, so a disabled detector costs nothing at scan time, and the PII
  activation identity is unchanged. The cost is the one this matrix measured:
  with `common`, a bare provider token disappears, and after `API_KEY=` a span
  becomes `contextual_secret` with another default action. The snapshot flags
  it (`effects.overlapOutcomesMayChange`) and `resolveConfig` reports
  `OVERLAP_OUTCOMES_MAY_CHANGE`.
- **The four levels are separate in the snapshot.** Compiled
  (`detection.compiledCount`), enabled and disabled (`detection.enabled`,
  `detection.disabled`) and unavailable (`detection.unavailable`, the `full`
  built-ins this artifact lacks) are distinct lists; an action policy never
  appears in them, and an `allow` rule changes nothing in `detection`.
- **Above the ceiling is refused, not ignored.** `common` rejects a `provider`
  id as `DETECTOR_NOT_INCLUDED` and never loads `full`; an artifact without
  the PII runtime rejects a PII selection as `PII_SELECTOR_UNAVAILABLE`; the
  Python wheel and the CLI report `detectorSelection: false` and reject a
  selection as `DETECTION_SELECTION_UNSUPPORTED`.
- **One owner, fixed once.** Selection joins the one-shot contract of the PII
  selection; nothing reconfigures an owner, a session fixes the owner's
  configuration at creation and takes no ruleset, and a second JavaScript
  wrapper still shares the entry singleton. An owner that enables nothing is
  `EMPTY_DETECTION_SET`.
- **Snapshots are data.** They cannot scan, hold no input, ruleset body, rule
  pattern, value or path, withhold the ruleset's ids and digest by default, and
  carry no scalar sensitivity or percentage. A callback is a labelled dynamic
  reference, not reproducible behavior.

## 7. What this does not authorize

- No per-detector selection beyond the rows of section 6 (Rust, Node and WebAssembly only), no numeric sensitivity or confidence threshold,
  and no change to the identity and sensitivity gate is offered.
- No second, reconfigurable global; a handle, when one is added, is built
  once with a fixed selection and never mutated.
- Installed-runtime parity and performance are not claimed here. Performance
  results stay in `redact-secret-benchmarks`
  ([decision](../decisions/2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)),
  and [#1097](https://github.com/redact-secret/redact-secret/issues/1097)'s
  result (document reuse; no new reuse API for speed) stands.
