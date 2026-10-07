---
decision_id: decision-define-the-artifact-manifest-and-configuration-data-contracts
status: accepted
scope: workspace
title: Define the artifact manifest and configuration data contracts
decided_at: 2026-10-07
spec: engine
---

# Define the artifact manifest and configuration data contracts

Issue [#1249](https://github.com/redact-secret/redact-secret/issues/1249), child
of epic [#1246](https://github.com/redact-secret/redact-secret/issues/1246).
Companion records:
[ceiling, ownership and surfaces](2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md)
and [selection and precedence](2026-10-07-define-detector-id-selection-and-configuration-replacement-precedence.md).
This record fixes the shapes #1250 to #1254 implement. It changes no code,
finding, default, artifact or version.

## Decision

### 1. Seven separate contracts

Each is UTF-8 JSON with a first member `schema`, a string `<name>/v<N>`. Inputs
fail closed; outputs are additive within a version (see Compatibility).

| Schema | Role | Direction | Owner |
| --- | --- | --- | --- |
| `artifact-manifest/v1` | what one artifact contains and supports | output, build-generated, self-reported | #1250 |
| `build-defaults/v1` | what the artifact does when runtime input is absent | output, embedded in the manifest as `defaults` | #1250 |
| `composition/v1` | the build input of a static custom artifact | input, a checked-in file | #1253 |
| `runtime-config/v1` | what a caller asks for | input | #1251 |
| `config-snapshot/v1` | the resolved, effective configuration | output | #1251 |
| `config-diagnostics/v1` | safe findings about an input or snapshot | output | #1252 |
| `configuration-comparison/v1` | detection differences on one input | output | #1254 |

`resolveConfig` returns the envelope `config-resolution/v1`:
`{ schema, ok, snapshot, diagnostics }`, where `snapshot` is null when `ok` is
false. Invalid input is data, never a thrown error, so a tool can show every
problem; a binding to an owner (`initialize`) throws the coded errors of the
ownership record.

### 2. `artifact-manifest/v1`

| Field | Type | Rule |
| --- | --- | --- |
| `schema` | string | `"artifact-manifest/v1"` |
| `product` | string | `"redact-secret"` |
| `version` | string | the lockstep SemVer |
| `sourceRevision` | string or null | 40-hex, null when the build has none |
| `artifact` | object | `{ kind, variant, pii }`: `kind` one of `wasm`, `node-addon`, `python-wheel`, `cli`, `rust-registry`; `variant` one of `full`, `common`, `custom`; `pii` a boolean (the PII runtime is linked) |
| `composition` | object | `{ kind, profile, id }`: `kind` `standard` or `custom`; `profile` `full`, `common` or `custom`; `id` null for standard, `custom:<sha256 hex of canonical composition/v1>` for custom |
| `detectors` | array | one object per **included** built-in, canonical order: `{ id, pack, types, aliases }`. `pack` is `common` or `provider`, `types` the sorted finding types it can emit, `aliases` sorted ids (empty today) |
| `notIncluded` | array | `full` built-in ids absent from this artifact, canonical order; empty for `full` |
| `pii` | object | `{ available, families }`: `families` the canonical family ids the artifact supports, sorted; empty when unavailable |
| `capabilities` | object | `{ detectorSelection: bool, ruleset: { revisions: [int] } or null, actionPolicy: { revisions: [int] }, incremental: bool }` |
| `defaults` | object | `build-defaults/v1` |
| `bounds` | object | the artifact defaults of `limits` and the document bounds (`actionPolicyBytes`, `detectorIdsMax`, `diagnosticsMax`) |
| `digest` | string | `sha256:<hex>` of the canonical JSON of this object without `digest` |

**Canonical JSON** for every digest: UTF-8, object members in bytewise order,
arrays in their stated order, no whitespace, integers in decimal, no floats, ASCII
strings only. A manifest contains no timestamp, path, host name, username,
environment value, or build machine detail. The canonical form is a shared
fixture (`conformance/fixtures/`), run by every surface.

The manifest is generated from the artifact's real composition: the registry that
the artifact links, never a hand-kept list. The packaged
`artifact-manifest.<variant>.json` is a build output; the self-reported manifest of
the loaded binary must have the same digest, or `initialize()` fails with
`INITIALIZATION_FAILED`, as a profile mismatch does. A standard artifact's
`detectors` and `composition` never change between builds of one version.

There is no NER, entity, customer, case or profile-interpretation field. A future
capability that is not listed here is a new `capabilities` key, off by default.

### 3. `build-defaults/v1`

`{ schema, detection: "all-included", pii: { selectors: [] }, actionPolicy:
"artifact-default", limits: "artifact-default" }`. In v1 these are constants for
every artifact, recorded so a change is visible. There is no included-but-off
detector and no build-time PII default: either would be silent coverage loss
whose owner is hard to see. Build-time defaults beyond these are a reopen
condition, not a field.

### 4. `composition/v1`, `runtime-config/v1`

`composition/v1` (a build input, WASM first): `{ schema, name, include, pii }`.
`name` is an identifier; `include` a non-empty array of built-in ids (aliases
resolve, repeats and unknown ids fail); `pii` is `"none"` or `"all"`. Order is
canonical, not as written. An empty or all-unknown composition fails the build
(`EMPTY_COMPOSITION`). It names no ruleset, policy or limit.

`runtime-config/v1`: `{ schema, detection?, pii?, ruleset?, actionPolicy?, limits? }`.
`detection` and `pii` are the grammar of the selection record and the existing
PII selector grammar; `ruleset` is the ruleset text the existing calls accept;
`actionPolicy` is an `actionPolicyRevision: 1` document; `limits` is `{
maxInputBytes?, maxFindings? }`. A callback is not data and cannot appear. No
other member exists. At most 262,144 bytes, checked before parsing; each embedded
document still obeys its own bound. The Rust core parses it with the strict
parser it already has, with no new dependency.

### 5. `config-snapshot/v1`

| Field | Rule |
| --- | --- |
| `schema`, `artifact` | `{ manifestDigest, version, profile, compositionId }` |
| `detection` | `{ mode, enabled, disabled, enabledCount }`: `mode` is `all-included`, `include` or `exclude`; `enabled` and `disabled` are ids in canonical order |
| `ruleset` | `{ present, revision, detectorIds, digest }` (digest of the exact bytes; null members when absent) |
| `pii` | `{ selectors, activation, families }`: canonical selectors, the existing canonical activation identity string unchanged, the closure |
| `actionPolicy` | `{ source, revision, digest, ruleCount, explainable }`: `source` `default`, `document` or `callback`; digest is the existing action-policy digest |
| `limits` | the effective `{ maxInputBytes, maxFindings }` |
| `owners` | per key, one of `initialize`, `call`, `session`, `registry`, fixed by the surface (ownership record) |
| `effects` | `{ overlapOutcomesMayChange, inert }`: both booleans |
| `detectionDigest` | `sha256:` of canonical `{ manifestDigest, enabled, ruleset.digest, pii.activation }`: equal digests mean the same detection |
| `digest` | `sha256:` of the canonical snapshot without `digest` |

It is data, not a handle: nothing scans from a snapshot in 0.1.x, so the
[#1222 deferral](2026-10-06-keep-the-configuration-bound-scanner-handle-out-of-0-1-x-for-node-webassembly-and-python.md)
stands. The snapshot contains ids, counts and digests; it never contains an input
byte, a ruleset body, a rule's pattern, a value or a path.

### 6. `config-diagnostics/v1`

`{ schema, truncated, items }`, `items` at most 256, errors first, then document
order. Item: `{ code, severity, path, id }`. `severity` is `error`, `warning` or
`info`. `path` is a fixed-syntax pointer such as `detection.include[3]` or
`actionPolicy.rules[2].match.type[0]`. `id` is **only** a canonical detector id from
the catalog, or a rule id of a validated action policy; it is null otherwise.
**An unknown or invalid input string is never echoed**: a user can paste a secret
where an id belongs, so only the index appears. Codes are an open set; a consumer
treats an unknown code by its `severity`.

| Severity | Codes (v1) |
| --- | --- |
| error | `UNKNOWN_SCHEMA`, `UNKNOWN_FIELD`, `WRONG_TYPE`, `INVALID_IDENTIFIER`, `TOO_MANY_DETECTOR_IDS`, `DUPLICATE_DETECTOR_ID`, `UNKNOWN_DETECTOR_ID`, `DETECTOR_NOT_INCLUDED`, `DETECTOR_NOT_SELECTABLE`, `DETECTION_SELECTOR_CONFLICT`, `DETECTION_SELECTION_UNSUPPORTED`, `INVALID_ACTION_POLICY` (with the existing class), `INVALID_RULESET`, `INVALID_LIMITS`, `PII_SELECTOR_INVALID`, `PII_SELECTOR_UNSUPPORTED`, `PII_SELECTOR_UNAVAILABLE`, `INVALID_OPTIONS` (callback with a policy), `EMPTY_DETECTION_SET` |
| warning | `DETECTOR_ALIAS_USED`, `NO_BUILT_IN_DETECTORS`, `ACTION_POLICY_UNKNOWN_TYPE`, `ACTION_POLICY_UNKNOWN_DETECTOR`, `ACTION_POLICY_RULE_ON_UNENABLED_DETECTOR`, `ACTION_POLICY_SHADOWED_RULE` |
| info | `OVERLAP_OUTCOMES_MAY_CHANGE` |

`ACTION_POLICY_SHADOWED_RULE` fires only when containment is **provable**: an
earlier rule whose every key is absent or a superset of this rule's set for that
key. Open-set doubt yields no warning. No diagnostic claims a missed detection or
a percentage.

### 7. `configuration-comparison/v1`

Input: one whole-input text, 1 to 4 `runtime-config/v1` values (their detection,
`pii`, `ruleset` members), one shared action policy (default or document). Output:
`{ schema, configs, results, differences }`. `configs` holds each snapshot digest
pair. `results[i]` holds safe finding metadata (`type`, `detector`, `confidence`,
`range`, `action`, as the existing explain output carries them), never a text
slice or value. `differences[i]` against config 0 holds `added`, `removed` and
`changed` (same range, different type, detector or action). It reports differences
on this input only and states so in the field `scope: "input"`. It uses the
existing whole-input limits and errors, is preview-only and per call, builds its
registries for the call, and holds nothing. Details are #1254's, inside this shape.

## Compatibility, evolution and bounds

- **Evolution.** A new input key, vocabulary entry or bound is `v2`; an unknown
  schema or field is rejected. A new output field is additive within `v1` and
  changes that output's digest; digests bind exact content and are not stable
  across versions (`version` is inside them). Revisions coexist, as for rulesets.
- **Standard compatibility.** With no `runtime-config`, standard `full` and
  `common` findings, order, ranges, output and errors are byte-identical to
  beta.14. The activation identity string is unchanged; `status()` gains one
  additive field, `configuration`: the snapshot digest of the owner-fixed
  configuration, null before initialization.
- **Security.** The core reads no file, network or environment value and
  fetches nothing; hosts read files and pass bytes. Output is bounded by the
  catalog, 256 diagnostics, four comparison configs and the existing limits.
- **Size.** The combined parser, resolver, manifest and diagnostics of #1250 to
  #1252 and #1254 are measured per real artifact. If the `full` brotli increase
  exceeds 5% of its then-current size, the implementing issue stops and reopens
  placement (for example moving comparison out of the artifact). That bound is a
  budget, not a performance claim.

## Rejected

A hand-written catalog (drifts); one merged input and output object; echoing
unknown ids; any score or percentage; a callback in `runtime-config`; a manifest
field for NER, entities or cases.

## Consequences

#1250 generates and verifies the manifest, #1251 the input, snapshot and
`describeConfig`, #1252 the diagnostics, #1253 the composition input and its
manifest, #1254 the comparison.
