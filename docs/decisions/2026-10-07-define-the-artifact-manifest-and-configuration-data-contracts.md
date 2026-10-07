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

Each is UTF-8 JSON with a member `schema`, a string `<name>/v<N>`. An **emitted**
document writes `schema` first and every other member, at every depth, in bytewise
order; the **canonical form** a digest is taken over writes every member, `schema`
included, in bytewise order (see Canonical JSON). Inputs fail closed; outputs are
additive within a version (see Compatibility).

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
| `artifact` | object | `{ kind, variant, pii }`: `kind` (the build target class; there is no separate `target`) one of `wasm`, `node-addon`, `python-wheel`, `cli`, `rust-registry`; `variant` one of `full`, `common`, `custom`; `pii` a boolean (the PII runtime is linked) |
| `composition` | object | `{ kind, profile, id }`: `kind` `standard` or `custom`; `profile` `full`, `common` or `custom`; `id` null for standard, `custom:<sha256 hex of canonical composition/v1>` for custom |
| `detectors` | array | one object per **included** built-in, canonical order: `{ id, pack, types, aliases }`. `pack` is `common` or `provider`, `types` the sorted finding types it can emit, `aliases` sorted ids (empty today) |
| `notIncluded` | array | `full` built-in ids absent from this artifact, canonical order; empty for `full` |
| `pii` | object | `{ available, families }`: `families` the canonical family ids the artifact supports, sorted; empty when unavailable |
| `capabilities` | object | `{ detectorSelection: bool, ruleset: { revisions: [int] } or null, actionPolicy: { revisions: [int] }, incremental: bool }` |
| `defaults` | object | `build-defaults/v1` |
| `bounds` | object | the artifact defaults of `limits` and the document bounds (`actionPolicyBytes`, `detectorIdsMax`, `diagnosticsMax`) |
| `typeVocabulary` | object | `{ builtInTypes: "declared", complete: false, dynamicSources: ["custom-detector", "pii", "ruleset"] }`: says that each detector's `types` is its reviewed declaration and not a closed vocabulary, because a declarative ruleset, a custom detector and the PII adapter emit types no list names (added by #1250; a new member is additive within `v1`) |
| `digest` | string | `sha256:<hex>` of the canonical JSON of this object without `digest` |

**Canonical JSON** for every digest: UTF-8, object members in bytewise order at
every depth, `schema` in its bytewise place and `digest` absent, arrays in their
stated order, no whitespace, integers in decimal, no floats, ASCII strings only.
The emitted document differs from it in two ways only: `schema` is written first,
and `digest` is present, in its bytewise place among the other members. A consumer
re-derives a digest by parsing the document, removing `digest`, sorting the keys at
every depth and hashing the compact text. A manifest contains no timestamp, path,
host name, username, environment value, or build machine detail. The canonical
form is a shared fixture (`conformance/fixtures/`), run by every surface.

The manifest is generated from the artifact's real composition: the registry that
the artifact links, never a hand-kept list. **Current state (#1250):** it is embedded
in the binary and generated at call time from the registration rows the artifact
links, so the artifact digests the release process already records cover it, and no
separate `artifact-manifest.<variant>.json` file is packaged. `initialize()` verifies
what the loaded artifact reports: the `artifact-manifest/v1` schema, the lockstep
version, the variant of the entry point and the document's own digest (the SHA-256
of its canonical form); any mismatch fails with `INITIALIZATION_FAILED`, as a profile
mismatch does, and echoes nothing of the document. `ArtifactManifest::verify_packaged`
exists for comparing a packaged document with the generated one and is not used by any
surface yet. **Follow-up, not built:** a packaged file per variant compared with
the self-reported manifest at `initialize()`; #1253 (custom artifacts) and #1255
(qualification) may pick it up. A standard artifact's `detectors` and `composition` never
change between builds of one version. There is no `target` field: the build target
class is `artifact.kind`.

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
- **Size.** The combined manifest, parser, resolver, diagnostics and comparison
  of #1250 to #1252 and #1254 are measured per real artifact against the
  pre-epic `full` brotli WebAssembly (181,882 B). The first bound of 5% was a
  trigger to revisit, not a measured limit. Measured: #1250 added 2.3% and #1251
  a further 6.9% (`full`; common 2.8% and 9.4%), about 9.3% in total, and the
  feature is the epic's outcome, so the bound is revised to 15% cumulative for
  `full`. Each remaining issue reports its own delta; if the total would pass
  15%, that issue stops and reopens placement (for example moving comparison
  out of the artifact). Size-sensitive consumers use a custom composition
  (#1253) rather than a smaller standard artifact. The bound is a budget, not a
  performance claim.

## Implementation status

Where the shipped code differs from or settles something above, the code and its
tests are authoritative; the decision of each section is unchanged.

- **#1250.** The manifest is embedded and self-verified, not a packaged file
  (section 2); `typeVocabulary` is added; `artifact.kind` is the target class;
  `capabilities.detectorSelection` is `true` for the Rust, Node addon and
  WebAssembly kinds and `false` for the Python wheel and the CLI, so a manifest
  digest differs by kind.
- **#1251.** `resolveConfig` and `describeConfig` are implemented once, in the
  Rust core. `ruleset` and `actionPolicy` are given beside the JSON text of the
  other `runtime-config/v1` members as their exact bytes (so the policy identity
  is the digest of the bytes a call would load), and a callback as the fact that
  one is in force. A ruleset's detector ids and digest are withheld from the
  snapshot by default (`ruleset.disclosed`), while `detectionDigest` still binds
  them. Added additively to the snapshot: `detection.compiledCount`,
  `detection.unavailable`, `detection.customDetectors`, `pii.available`,
  `artifact.kind`, `owners.incremental` and `origins`. In JavaScript
  `describeConfig()` takes no argument and describes what the runtime is fixed
  to; a preview is `resolveConfig`. [API contract](../reference/api-contract.md#detector-selection-and-effective-configuration)
  has the rest.

## Rejected

A hand-written catalog (drifts); one merged input and output object; echoing
unknown ids; any score or percentage; a callback in `runtime-config`; a manifest
field for NER, entities or cases.

## Consequences

#1250 generates and verifies the manifest, #1251 the input, snapshot and
`describeConfig`, #1252 the diagnostics, #1253 the composition input and its
manifest, #1254 the comparison.
