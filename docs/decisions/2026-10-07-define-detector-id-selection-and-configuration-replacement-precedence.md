---
decision_id: decision-define-detector-id-selection-and-configuration-replacement-precedence
status: accepted
scope: workspace
title: Define detector-id selection and configuration replacement precedence
decided_at: 2026-10-07
spec: engine
---

# Define detector-id selection and configuration replacement precedence

Issue [#1249](https://github.com/redact-secret/redact-secret/issues/1249), child
of epic [#1246](https://github.com/redact-secret/redact-secret/issues/1246). It
is the semantics record of three: the capability ceiling, ownership and surface
support are in
[`decision-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support`](2026-10-07-define-the-configuration-capability-ceiling-runtime-ownership-and-surface-support.md);
the data shapes are in
[`decision-define-the-artifact-manifest-and-configuration-data-contracts`](2026-10-07-define-the-artifact-manifest-and-configuration-data-contracts.md).
It changes no code, finding, default, artifact or version.

## Context

[`decision-define-detector-profile-and-pack-contract`](2026-09-18-define-detector-profile-and-pack-contract.md)
rejected runtime allow and deny lists by detector id because they "create
unqualifiable combinations and change overlap outcomes without review". The
[capability matrix](../reference/detector-capability-matrix.md) measured the
second half: with `common`, a bare provider token disappears, and after
`API_KEY=` it becomes `contextual_secret` with another default action. Both
costs are real. They are bounded here, not ignored: selection is strict,
inspectable before use, and qualified against the standard profiles.

## Decision

### 1. What a selection is

A **detector-id selection** chooses which of an artifact's **included** built-in
detectors are **enabled**. It names `Finding.detector` ids (`github-token`, not
the type `github_token`). It acts when the registry is composed, before
detection:

- a disabled detector is not constructed, not prefiltered, produces no
  candidate, is no overlap competitor, and adds no retention behavior;
- overlap, evidence weighting and policy then run over the enabled detectors
  exactly as they run over a profile's detectors;
- **canonical subsequence:** the enabled set is the artifact's canonical order
  filtered to the enabled ids. Request order never matters, so the fourth overlap
  tie breaker ranks two detectors the same way in every configuration holding both;
- **per-detector invariance extends:** an enabled detector's candidates equal its
  candidates in `full`. Findings still differ from `full` through overlap, as the
  profile contract already states for `common`.

A selection names built-in detectors only. A ruleset's detectors exist exactly
when that ruleset is supplied. A PII family is chosen by the PII selector, whose
ids contain `:` and are not identifiers. A custom Rust detector is chosen by
the code that registers it. None is selectable by id (`DETECTOR_NOT_SELECTABLE`
when a known one is named; `INVALID_IDENTIFIER` for a PII family).

### 2. Grammar

`detection` is an object with at most one of two members, `include` or `exclude`.
Each is an array of 0 to 256 ids. Every id is an identifier (`is_identifier`:
lowercase, at most 64 bytes). Selection ids are not case-folded or trimmed.

| Input | Meaning |
| --- | --- |
| `detection` absent, or `{}` | all included detectors enabled (the build default) |
| `include: [ids]` | exactly these enabled: an allowlist. A detector added in a later release is **not** enabled |
| `exclude: [ids]` | every included detector except these: a denylist. A detector added later **is** enabled |
| `include` and `exclude` together | `DETECTION_SELECTOR_CONFLICT` |

Mutual exclusion removes the "named in both" and "excluded but not included"
cases. Allowlist versus denylist is a deliberate choice the author makes and the
snapshot records (`mode`).

### 3. Validation, in this order, first violation reported

1. unknown member or wrong type (`UNKNOWN_FIELD`, `WRONG_TYPE`);
2. more than 256 ids (`TOO_MANY_DETECTOR_IDS`);
3. a non-identifier (`INVALID_IDENTIFIER`);
4. the artifact has no selection capability (`DETECTION_SELECTION_UNSUPPORTED`);
5. per id, in array order: resolve aliases (section 4); a repeated detector,
   including an alias plus its canonical id, is `DUPLICATE_DETECTOR_ID`; an id that
   is a ruleset or custom id is `DETECTOR_NOT_SELECTABLE`; an id that is a
   `full` built-in absent from this artifact is `DETECTOR_NOT_INCLUDED`; any other
   id is `UNKNOWN_DETECTOR_ID`.

Unknown and not-included ids are **rejected**, never ignored, never fetched. A
typo in an `include` list would otherwise silently lose coverage. This differs
from the action policy, where an unknown `type` is accepted because a rule can
only tighten or loosen an existing action and the base protects the miss. No
artifact is chosen or downloaded to satisfy a selection: selecting `github-token`
in the `common` entry is `DETECTOR_NOT_INCLUDED`, not a switch to `full`.

### 4. Aliases

An **alias** is an alternate spelling of exactly one detector id, declared in the
artifact manifest (`detectors[].aliases`). It exists only to keep a selection
written for a renamed built-in id working: a rename is a breaking change class
decided on its own, and aliases are never user-supplied. In `0.1.0-beta.14` the
set is empty. An alias is an identifier, unique across all ids and aliases, and
resolves before duplicate checks; the snapshot and every output use the canonical
id; `DETECTOR_ALIAS_USED` (warning) is reported. Group or vendor selectors
(`cloud`, `ai`, `*`, a prefix or a regex) are not aliases and are not offered: a
profile remains the only named group, and groups would make a newly added
detector's membership ambiguous.

### 5. Reserved ids

A custom or ruleset detector id may not equal any `full` built-in id (existing
rule, including ids absent from the artifact) and, new, any alias. Selection ids
are never reinterpreted: a custom id can never shadow a built-in selector. The
reservation is unchanged for the declarative ruleset
([`decision-define-declarative-detector-ruleset-contract`](2026-09-19-define-declarative-detector-ruleset-contract.md)).

### 6. Empty selections

`include: []` is valid data and enables no built-in detector. `exclude: []` is
valid and identical to absent. The empty built-in set is useful with a ruleset or
a PII selection, so it is not rejected at resolution. Because a scan that cannot
detect anything reads as a clean pass, the rule is:

- `resolveConfig`/`describeConfig` succeed and report `detection.enabledCount: 0`
  with the warning `NO_BUILT_IN_DETECTORS`;
- a configuration whose **total** enabled set (built-in, ruleset and PII) is empty
  is **inert**. Binding it to a scan owner (`initialize`, a session) fails with
  `EMPTY_DETECTION_SET`; preview functions still describe it.

A ruleset cannot be empty (existing rule), so the explicit-empty case for rulesets
is not expressible.

### 7. Replacement precedence

Layers, lowest to highest: the artifact's **build defaults**, then the **runtime
input**. There is no third layer, no environment, no file lookup and no merge of
two runtime inputs. For each key:

| Key | Absent | Explicit empty | Explicit value |
| --- | --- | --- | --- |
| `detection.include` | all included enabled | no built-in enabled | **replaces**: exactly the list |
| `detection.exclude` | none excluded | none excluded (same as absent) | **replaces**: exactly the list |
| `pii.selectors` | PII off | PII off (existing) | **replaces**: the canonical set; never unioned with a prior selection |
| `ruleset` | no ruleset | not expressible (empty ruleset rejected) | adds the ruleset's detectors |
| `actionPolicy` | the artifact's default evaluation | `rules: []` equals the base; not a distinct state | **replaces the whole document**: rules are never concatenated or merged across layers |
| `limits.maxInputBytes`, `limits.maxFindings` | artifact default | not expressible (zero is rejected, existing) | replaces that field only; the two scalars inherit independently |
| callback `policy` | none | n/a | replaces the default; together with `actionPolicy` is `INVALID_OPTIONS` (existing) |

Consequences of the table:

- **Replace, never union.** Two layers never combine arrays. A second `initialize`
  whose resolved detection or PII differs is a conflict, not a merge.
- **Explicit empty disables; absent inherits.** The two are never the same
  except where the table says so.
- **Callback versus `actionPolicy`.** A callback is code, not data: it cannot appear
  in `runtime-config/v1`. Where both are supplied the existing
  `INVALID_OPTIONS` stands. A snapshot reports `actionPolicy.source: "callback"`
  without content and states `explainable: false`.
- `null` is not an absent value in `runtime-config/v1`; it is `WRONG_TYPE`.

### 8. Detection never reads policy, and policy never reads detection

An action policy cannot enable or disable a detector, and a selection cannot change
an action. `resolveConfig` may warn that a policy rule names a type or detector the
snapshot cannot emit (`ACTION_POLICY_UNKNOWN_TYPE`, `..._DETECTOR`,
`..._RULE_ON_UNENABLED_DETECTOR`) but never rejects it, preserving the open-set
rule of the action-policy record.

## Trade-offs

- **False negatives.** A selection can remove coverage and can move a span to a
  weaker detector's type and action. Mitigations: strict rejection of unknown and
  not-included ids, `OVERLAP_OUTCOMES_MAY_CHANGE` on any disabled built-in, the
  inert refusal, and the comparison of #1254 on a representative input. Server
  enforcement should run an unselected `full`. Nothing here claims missed-detection
  coverage.
- **False positives.** Unchanged or lower: a selection only drops candidates, so
  the rate cannot rise from detection. A span can reappear under another type.
- **Qualification.** `2^n` selections cannot each be tested. The obligation is the
  agreement oracle in the ownership record: `full` with `include` equal to
  `common`'s ids must equal the `common` artifact on the corpus, and any custom
  artifact must equal `full` with the same `include`, plus invariance and
  incremental partition equivalence for every case a test runs.
- **Include versus exclude.** An allowlist is safer against surprise and weaker
  against growth: a new detector stays off. The record does not choose one for the
  user.

## Alternatives considered

- **Union or merge layers.** Rejected: a union cannot express removal and a merge
  needs an order.
- **Both `include` and `exclude`.** Rejected for the smallest surface; reopen on a
  consumer that needs it and shows the combined list is not derivable.
- **Ignore unknown ids.** Rejected: a typo silently loses coverage.
- **Reject an empty `include`.** Rejected: ruleset-only and PII-only scans are
  legitimate, and the inert refusal covers the silent case.
- **Group, glob or regex selectors.** Rejected as above.
- **Per-call selection on the scan path.** Rejected: see the ownership record.

## Reopen conditions

Any one, with evidence: a consumer that needs both lists or a group selector; a
rename that needs the first alias; a measured wrong-coverage incident traced to a
selection that the diagnostics did not flag; an input over 256 ids that is not a
mistake.

## Consequences

#1251 implements the grammar, validation order and precedence table over the
manifest of #1250, #1252 the diagnostics named here. The engine spec gains one
row; the profile record is amended by the ownership record.

## Implementation status

- **#1251, #1252.** The grammar, validation order, truth table and diagnostics are implemented once in
  the Rust core and forwarded by the Node addon and WebAssembly; the code and its tests are
  authoritative (see the [API contract](../reference/api-contract.md#detector-selection-and-effective-configuration)).
- **#1255.** Verified on the installed artifacts, build defaults against runtime overrides: `include` of
  every id (also reversed) and `exclude: []` give the build defaults' enabled set, detection
  identity and scans; selection runs before the prefilter and overlap resolution (excluding
  `github-token` hands the span to `generic-token` with its own type and action); a reserved
  built-in id in a ruleset is `INVALID_RULESET`; a ruleset id is not selectable
  (`UNKNOWN_DETECTOR_ID`); a secret pasted where an id belongs is rejected without being echoed.
  A session captures the configuration once and takes no `detection` or `ruleset` key
  (`INVALID_OPTIONS`; a `ruleset` key used to be ignored silently). The reopen conditions above
  are unchanged.
