---
decision_id: decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support
status: accepted
scope: workspace
title: Define the configuration capability ceiling, runtime ownership and surface support
decided_at: 2026-10-07
spec: engine
---

# Define the configuration capability ceiling, runtime ownership and surface support

Issue [#1249](https://github.com/redact-secret/redact-secret/issues/1249), child
of epic [#1246](https://github.com/redact-secret/redact-secret/issues/1246). This
is the umbrella record; its companions are the
[data contracts](2026-10-07-define-the-artifact-manifest-and-configuration-data-contracts.md)
and [selection and precedence](2026-10-07-define-detector-id-selection-and-configuration-replacement-precedence.md).
It changes no code, finding, default or artifact and grants no release authority.

## Context

[`decision-define-detector-profile-and-pack-contract`](2026-09-18-define-detector-profile-and-pack-contract.md)
allows only `full` and `common`, no consumer composition and no runtime id
selection. The action policy
([#1219](https://github.com/redact-secret/redact-secret/issues/1219),
[#1220](https://github.com/redact-secret/redact-secret/issues/1220)) is per call
and cannot change which detectors generate candidates.
[`decision-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python`](2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md)
(#1222) added no handle. A consumer needs an application-specific artifact, a
runtime detection setting inside it, and a way to see the effect before
enforcement, without any of that becoming a silent global.

## Decision

### 1. Capability ceiling: four separate levels

| Level | Meaning | Fixed by | Visible as |
| --- | --- | --- | --- |
| **included** | linked into the artifact | the build | manifest `detectors`, `pii.families`, `capabilities` |
| **enabled** | in the effective detection set of one owner | runtime input, within included | snapshot `detection.enabled`, `pii`, `ruleset` |
| **emitted** | a finding in one result | the input text and overlap | `Finding` (unchanged) |
| **action** | what happens to an emitted finding | action policy or callback | `actionPolicy`, the action field |

Each level is a subset or function of the one above: enabled never exceeds
included, emitted never exceeds the types of enabled detectors, and an action
never adds or removes an emitted finding. A request for something above the
ceiling is **rejected with a coded diagnostic, never ignored, never satisfied by
loading another artifact**: that covers a detector not included, a PII family the
artifact lacks, a ruleset or policy revision it does not support, and detector
selection on an artifact without the capability. Nothing in core fetches,
reads a file or reads the environment; a host passes bytes.

### 2. Static custom composition

A consumer may build a **custom artifact** from `composition/v1`: a chosen
subset of built-in detector ids (and PII all or none), recorded in the manifest
with `composition.kind: "custom"`.

- **A composition is not a profile.** The named profiles stay exactly `full`
  and `common`; a custom artifact reports `PROFILE === "custom"` and its
  composition id. The standard entries (`@redact-secret/core`, `./common`) never
  load a custom artifact and still reject a profile mismatch with
  `INITIALIZATION_FAILED`. The published packages never contain a custom artifact.
- **Core stays Cargo-feature-free.** The mechanism is a generated leaf crate whose
  registry constructor references only the selected per-detector constructors, in
  canonical order, so link-time reachability removes the rest (the reachability
  rule of the profile record). #1253 fixes the names of the per-detector public
  constructors and the composition entry point through the reviewed
  `core-public-api` manifest, and the core validates canonical order and reserved
  ids (`InvalidDetector`). Rejected: Cargo features, a core `build.rs`,
  `RUSTFLAGS --cfg`, and filtering at runtime (which cannot shrink the binary).
- **WebAssembly first.** The generated glue gets a generated wrapper with the
  same function set as `./common`, which changes no `@redact-secret/core` export.
  Rust composes natively through the same constructors. A custom Node addon,
  Python wheel or CLI is unsupported.
- **Qualification is per exact generated artifact, with an oracle.** A custom
  artifact must give findings equal to the `full` runtime artifact with the same
  `include`, equal per-detector candidates, partition-equivalent incremental output,
  a manifest digest equal to its self-report, and a size below `full`. The
  profile record's qualification list applies to the composition, not to `2^n`
  untested combinations.

### 3. Runtime ownership

| Setting | Owner | When it changes |
| --- | --- | --- |
| entry profile or artifact | the import | a different import |
| `detection` (selection), `pii` | the **initialization owner**: `initialize()` on Node and WebAssembly (one per thread and profile, or per module instance); the registry value in Rust | a new owner: a Worker, a module instance, a process; in Rust a new registry |
| `ruleset`, `actionPolicy` or callback, `limits` | the **call** (existing) | the next call |
| an incremental session's configuration | **fixed at session creation** from the owner and the call options | a new session |
| `resolveConfig`, `compareConfigurations` | nothing: pure and per call | each call is independent |

Rules:

1. `initialize({ detection })` joins the legacy one-shot contract of `pii`: an
   equivalent resolved selection is idempotent, a differing one is
   `DETECTION_CONFIG_CONFLICT`, a conflict changes nothing, and a lazy default
   registry that already exists counts as the default configuration.
2. **Detection never changes silently.** No call changes an owner's `detection`
   or `pii`; there is no `reconfigure`, setter, hot swap or per-call detection
   argument on the scan path. A scan on an inert configuration fails with
   `EMPTY_DETECTION_SET`.
3. `compareConfigurations` builds temporary registries per call to preview, never
   scans for enforcement and never touches an owner. It is not a handle.
4. A facade wrapper is not isolation: a second wrapper object shares the entry
   singleton, as the ownership guide states.
5. Removing retention-feeding detectors (`private-key`, `bearer-token`,
   `generic-token`) is allowed; retention only shrinks. Retaining more never changes
   output.

New fixed codes (open set, additive): `INVALID_DETECTION_CONFIG` (class from the
diagnostics list), `DETECTION_CONFIG_CONFLICT`, `EMPTY_DETECTION_SET`. No error
repeats an input string.

### 4. Handle deferral stays explicit

#1222's decision is **not reopened**. Nothing here creates a configuration-bound
scanner: a snapshot is data and cannot scan. The deferral's section 7 rejected
"per-detector selection by id" for a future handle; this record **amends** it: a
future handle's immutable `{ profile, pii, ruleset? }` may also take one validated
`detection` value. Its reopen triggers and its other rejections stand. Independent detection
configurations in one thread keep the Worker, module-instance or process recipes.

### 5. Surface matrix

Existing, proposed (accepted here, not built) and unsupported. The matrix of
record, with the per-surface rows, is
[`docs/reference/detector-capability-matrix.md`](../reference/detector-capability-matrix.md).

| Capability | Rust | Node (addon, WASM fallback) | WASM, browser | Python | CLI |
| --- | --- | --- | --- | --- | --- |
| `full`, `common` profiles | existing | existing | existing | `full` only | `full` only |
| Artifact manifest (read) | proposed | proposed | proposed | proposed (`artifact_manifest()`) | proposed (`--print-artifact-manifest`) |
| Runtime detector selection | proposed | proposed (`initialize`) | proposed (`initialize`) | unsupported | unsupported |
| `resolveConfig`, `describeConfig`, diagnostics | proposed | proposed | proposed | unsupported | unsupported |
| `compareConfigurations` | proposed | proposed | proposed | unsupported | unsupported |
| Static custom composition | proposed (leaf crate) | unsupported | proposed (first) | unsupported | unsupported |
| Detection handle | existing (`BuiltInRegistry`) | unsupported (#1222) | unsupported (#1222) | unsupported (#1222) | n/a |
| Action policy, `compareActionPolicies` | existing | existing | existing | policy existing | existing |

Python and the CLI are server and enforcement surfaces: a reduced detection set
would only weaken them, and Python's process-wide singleton cannot own it. A
consumer requirement with evidence reopens a row.

### 6. What stays out

NER stays off by default and is not part of core; no manifest field or selector
names it. Customer, case and profile-interpretation logic and blanket person-name
masking stay in the application. No scalar sensitivity, probability or
percentage appears in any contract. Identity and sensitivity gates are unchanged
and not selectable. No network validation. No change to `full` or `common`
membership, order or findings.

## Amendments

| Record | Change |
| --- | --- |
| profile and pack contract | **Amended, not superseded.** "Runtime detector selection by detector id is not offered", "Consumers never compose profiles at build time", "no user-composed profiles" and the rejected "runtime allow or deny lists" are replaced as above. Profiles stay two, packs stay internal, Python and CLI stay `full` only, reachability and reserved ids stay |
| #1222 handle deferral | Reaffirmed; section 7 amended as in section 4 |
| action-policy records | Unchanged; the policy remains per call and detection-blind |
| engine spec and capability matrix | Rows updated in this change |

## Trade-offs and reopen

Cost: a selection can lose coverage or retype a span; the standard artifacts carry the resolver and diagnostics (bounded by the size
rule in the data-contract record); documentation and qualification grow with each
surface. Reopen with evidence: a consumer needing selection on Python or the CLI;
a custom Node, Python or CLI artifact; an in-process multi-tenant requirement
(the #1222 triggers); build-time defaults beyond constants; a `v2` of any schema.

## Work breakdown

| Issue | Delivers from this record |
| --- | --- |
| [#1250](https://github.com/redact-secret/redact-secret/issues/1250) | manifest generation and self-report, `build-defaults/v1`, canonical-JSON fixture, self-digest check at `initialize`, `artifactManifest()` on all surfaces |
| [#1251](https://github.com/redact-secret/redact-secret/issues/1251) | `runtime-config/v1`, grammar and precedence table, `initialize({ detection })`, the new codes, `resolveConfig`, `describeConfig`, snapshot, `status().configuration` |
| [#1252](https://github.com/redact-secret/redact-secret/issues/1252) | `config-diagnostics/v1` and every listed code, provable-shadow rule, no echo of input |
| [#1253](https://github.com/redact-secret/redact-secret/issues/1253) | `composition/v1`, generated leaf crate, per-detector public constructors, WebAssembly wrapper, `PROFILE "custom"`, capability report |
| [#1254](https://github.com/redact-secret/redact-secret/issues/1254) | `compareConfigurations`, `configuration-comparison/v1`, shared action policy |
| [#1255](https://github.com/redact-secret/redact-secret/issues/1255) | the agreement oracle, invariance, partition equivalence, reachability and size guards, installed-artifact and bundler runs, consumer journeys, standard-artifact byte identity |

Adapters: [adapters#217](https://github.com/redact-secret/redact-secret-adapters/issues/217)
forwards `actionPolicy` and needs nothing here;
[adapters#213](https://github.com/redact-secret/redact-secret-adapters/issues/213)
uses the custom WebAssembly wrapper and `initialize({ detection })`, and is not
evidence for a handle.

## Implementation status

- **#1253.** Static custom composition is implemented for WebAssembly and, natively, Rust.
  The reviewed seam is the root module `composition` of `core-public-api`: one public
  constructor per built-in detector (the id with `-` written `_`), `Composition::new`,
  `DetectorRegistry::with_composition`, the matching `IncrementalSanitizer` constructors,
  `ArtifactManifest::custom` and `Profile::Custom` (not selectable by name). A generated leaf
  crate in an isolated build workspace (`scripts/build-custom-artifact.mjs`) calls the selected
  constructors only, and the binding's third Cargo feature `custom` installs it. The generated
  wrapper has the function set of `./common`. See the
  [guide](../guides/custom-composition.md) and the engine spec row.
